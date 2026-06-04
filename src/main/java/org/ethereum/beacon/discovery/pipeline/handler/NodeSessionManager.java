/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.pipeline.handler;

import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.annotations.VisibleForTesting;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.crypto.Signer;
import org.ethereum.beacon.discovery.pipeline.AbstractSkippingEnvelopeHandler;
import org.ethereum.beacon.discovery.pipeline.Envelope;
import org.ethereum.beacon.discovery.pipeline.Field;
import org.ethereum.beacon.discovery.pipeline.HandlerUtil;
import org.ethereum.beacon.discovery.pipeline.Pipeline;
import org.ethereum.beacon.discovery.scheduler.ExpirationScheduler;
import org.ethereum.beacon.discovery.scheduler.ExpirationSchedulerFactory;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeSession;
import org.ethereum.beacon.discovery.storage.KBuckets;
import org.ethereum.beacon.discovery.storage.LocalNodeRecordStore;
import org.ethereum.beacon.discovery.type.Bytes12;
import org.ethereum.beacon.discovery.util.Functions;

/**
 * Performs {@link Field#SESSION_LOOKUP} request. Looks up for Node session based on NodeId, which
 * should be in request field and stores it in {@link Field#SESSION} field.
 */
public class NodeSessionManager extends AbstractSkippingEnvelopeHandler {
  private static final int SESSION_CLEANUP_DELAY_SECONDS = 180;
  private static final int REQUEST_CLEANUP_DELAY_SECONDS = 60;
  private static final Logger LOG = LogManager.getLogger(NodeSessionManager.class);
  private final LocalNodeRecordStore localNodeRecordStore;
  private final Signer signer;
  private final KBuckets nodeBucketStorage;
  private final boolean ipv6BindAvailable;
  private final Map<SessionKey, NodeSession> recentSessions = new ConcurrentHashMap<>();
  private final Map<Bytes12, NodeSession> lastNonceToSession = new ConcurrentHashMap<>();
  private final Pipeline outgoingPipeline;
  private final ExpirationScheduler<SessionKey> sessionExpirationScheduler;
  private final ExpirationScheduler<Bytes> requestExpirationScheduler;

  public NodeSessionManager(
      final LocalNodeRecordStore localNodeRecordStore,
      final Signer signer,
      final KBuckets nodeBucketStorage,
      final Pipeline outgoingPipeline,
      final ExpirationSchedulerFactory expirationSchedulerFactory,
      final boolean ipv6BindAvailable) {
    this.localNodeRecordStore = localNodeRecordStore;
    this.signer = signer;
    this.nodeBucketStorage = nodeBucketStorage;
    this.outgoingPipeline = outgoingPipeline;
    this.ipv6BindAvailable = ipv6BindAvailable;
    this.sessionExpirationScheduler =
        expirationSchedulerFactory.create(SESSION_CLEANUP_DELAY_SECONDS, TimeUnit.SECONDS);
    this.requestExpirationScheduler =
        expirationSchedulerFactory.create(REQUEST_CLEANUP_DELAY_SECONDS, TimeUnit.SECONDS);
  }

  @Override
  protected void handlePacket(final Envelope envelope) {
    if (!HandlerUtil.requireField(Field.SESSION_LOOKUP, envelope)) {
      return;
    }
    if (envelope.contains(Field.SESSION)) {
      return;
    }
    LOG.trace(
        "Envelope {} in NodeSessionManager, requirements are satisfied!", envelope.getIdString());

    SessionLookup sessionRequest = envelope.get(Field.SESSION_LOOKUP);
    envelope.remove(Field.SESSION_LOOKUP);
    LOG.trace(
        "Envelope {}: Session lookup requested for nodeId {}",
        envelope.getIdString(),
        sessionRequest);

    getOrCreateSession(sessionRequest, envelope)
        .ifPresentOrElse(
            nodeSession -> {
              envelope.put(Field.SESSION, nodeSession);
              LOG.trace(
                  "Session resolved: {} in envelope #{}", nodeSession, envelope.getIdString());
            },
            () ->
                LOG.trace(
                    "Session could not be resolved or created for {}", sessionRequest.getNodeId()));
  }

  private Optional<NodeSession> getOrCreateSession(
      final SessionLookup sessionLookup, final Envelope envelope) {
    return getRemoteSocketAddress(envelope)
        .map(
            remoteSocketAddress -> {
              SessionKey sessionKey =
                  new SessionKey(sessionLookup.getNodeId(), remoteSocketAddress);
              NodeSession context =
                  recentSessions.computeIfAbsent(
                      sessionKey,
                      existingSessionKey ->
                          createNodeSession(existingSessionKey, sessionLookup.getNodeRecord()));

              sessionExpirationScheduler.put(sessionKey, () -> deleteSession(sessionKey));
              return context;
            });
  }

  public void dropSession(final NodeSession session) {
    final SessionKey sessionKey = new SessionKey(session.getNodeId(), session.getRemoteAddress());
    sessionExpirationScheduler.cancel(sessionKey);
    deleteSession(sessionKey);
  }

  private void deleteSession(final SessionKey sessionKey) {
    final NodeSession removedSession = recentSessions.remove(sessionKey);
    if (removedSession != null) {
      // Mark inactive to prevent registering any new nonces
      removedSession.markInactive();
      // Clean up ALL nonce mappings for this session. Multiple nonces may be registered when
      // several packets were sent before the handshake completed (see onSessionLastNonceUpdate).
      lastNonceToSession.values().removeIf(s -> s == removedSession);
    }
  }

  @VisibleForTesting
  public Optional<NodeSession> getNodeSession(final Bytes nodeId) {
    return recentSessions.entrySet().stream()
        .filter(e -> e.getKey().nodeId.equals(nodeId))
        .map(Map.Entry::getValue)
        .findFirst();
  }

  public Optional<NodeSession> getNodeSessionByLastOutboundNonce(final Bytes12 nonce) {
    return Optional.ofNullable(lastNonceToSession.get(nonce));
  }

  /**
   * Mirrors {@link NodeSession}'s bounded recent-outbound-nonce window. The session passes the
   * nonce evicted from its window (if any) so we can drop the matching {@code lastNonceToSession}
   * entry at the same time. This keeps the map bounded at {@code num_sessions *
   * MAX_RECENT_OUTBOUND_NONCES}.
   */
  public void onSessionLastNonceUpdate(
      final NodeSession session, final Optional<Bytes12> evictedNonce, final Bytes12 newNonce) {
    // Value-conditional remove so a colliding nonce (or a delete-then-evict race with another
    // session that has since reused the nonce) cannot evict the other session's fresh mapping.
    // Mirrors removeNoncesForSession.
    evictedNonce.ifPresent(n -> lastNonceToSession.remove(n, session));
    lastNonceToSession.put(newNonce, session);
  }

  /**
   * Removes the given nonces from {@code lastNonceToSession} when they still map to {@code
   * session}. Called by {@link NodeSession}'s handshake reset so the manager's view stays
   * consistent with the session's bounded recent-nonce window even when the window is cleared en
   * bloc (rather than via single-nonce eviction in {@link #onSessionLastNonceUpdate}).
   *
   * <p>Uses value-conditional removal so a race where the session was already replaced by a new one
   * for the same nonce cannot remove the new mapping.
   */
  public void removeNoncesForSession(final NodeSession session, final Collection<Bytes12> nonces) {
    for (Bytes12 nonce : nonces) {
      lastNonceToSession.remove(nonce, session);
    }
  }

  private NodeSession createNodeSession(
      final SessionKey key, final Optional<NodeRecord> suppliedNodeRecord) {
    final Optional<NodeRecord> nodeRecord =
        suppliedNodeRecord.or(() -> nodeBucketStorage.getNode(key.nodeId));
    final SecureRandom random = Functions.getRandom();
    return new NodeSession(
        key.nodeId,
        nodeRecord,
        key.remoteSocketAddress,
        this,
        localNodeRecordStore,
        signer,
        nodeBucketStorage,
        outgoingPipeline::push,
        random,
        requestExpirationScheduler);
  }

  private Optional<InetSocketAddress> getRemoteSocketAddress(final Envelope envelope) {
    return Optional.ofNullable(envelope.get(Field.REMOTE_SENDER))
        .or(
            () -> {
              final NodeRecord nodeRecord = envelope.get(Field.NODE);
              final NodeRecord homeNodeRecord = localNodeRecordStore.getLocalNodeRecord();
              final Optional<InetSocketAddress> homeUdpAddress = homeNodeRecord.getUdpAddress();
              final Optional<InetSocketAddress> homeUdp6Address = homeNodeRecord.getUdp6Address();
              // Prefer IPv6 outbound when the home record advertises IPv6 OR when an IPv6 socket
              // is bound but the home record has not (yet) advertised IPv6 — the latter case
              // matters for IPv6 external-address auto-discovery, where we must dial IPv6 in order
              // to receive PONGs reporting our IPv6 source address.
              final boolean preferIpv6Outbound = homeUdp6Address.isPresent() || ipv6BindAvailable;
              if (homeUdpAddress.isPresent() && preferIpv6Outbound) {
                return nodeRecord.getUdp6Address().or(nodeRecord::getUdpAddress);
              } else if (preferIpv6Outbound) {
                return nodeRecord.getUdp6Address();
              } else {
                return nodeRecord.getUdpAddress();
              }
            });
  }

  public Stream<NodeRecord> streamActiveSessions() {
    return recentSessions.values().stream()
        .filter(NodeSession::isAuthenticated)
        .flatMap(session -> session.getNodeRecord().stream());
  }

  private static class SessionKey {
    private final Bytes nodeId;
    private final InetSocketAddress remoteSocketAddress;

    private SessionKey(final Bytes nodeId, final InetSocketAddress remoteSocketAddress) {
      checkNotNull(remoteSocketAddress);
      this.nodeId = nodeId;
      this.remoteSocketAddress = remoteSocketAddress;
    }

    @Override
    public boolean equals(final Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      final SessionKey that = (SessionKey) o;
      return Objects.equals(nodeId, that.nodeId)
          && Objects.equals(remoteSocketAddress, that.remoteSocketAddress);
    }

    @Override
    public int hashCode() {
      return Objects.hash(nodeId, remoteSocketAddress);
    }
  }
}
