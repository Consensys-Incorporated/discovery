/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.schema;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.ethereum.beacon.discovery.task.TaskStatus.AWAIT;
import static org.ethereum.beacon.discovery.task.TaskStatus.SENT;

import com.google.common.annotations.VisibleForTesting;
import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.ethereum.beacon.discovery.crypto.Signer;
import org.ethereum.beacon.discovery.message.V5Message;
import org.ethereum.beacon.discovery.network.NetworkParcel;
import org.ethereum.beacon.discovery.network.NetworkParcelV5;
import org.ethereum.beacon.discovery.packet.HandshakeMessagePacket;
import org.ethereum.beacon.discovery.packet.HandshakeMessagePacket.HandshakeAuthData;
import org.ethereum.beacon.discovery.packet.Header;
import org.ethereum.beacon.discovery.packet.OrdinaryMessagePacket;
import org.ethereum.beacon.discovery.packet.OrdinaryMessagePacket.OrdinaryAuthData;
import org.ethereum.beacon.discovery.packet.Packet;
import org.ethereum.beacon.discovery.packet.RawPacket;
import org.ethereum.beacon.discovery.packet.WhoAreYouPacket;
import org.ethereum.beacon.discovery.pipeline.handler.NodeSessionManager;
import org.ethereum.beacon.discovery.pipeline.info.Request;
import org.ethereum.beacon.discovery.pipeline.info.RequestInfo;
import org.ethereum.beacon.discovery.scheduler.ExpirationScheduler;
import org.ethereum.beacon.discovery.storage.KBuckets;
import org.ethereum.beacon.discovery.storage.LocalNodeRecordStore;
import org.ethereum.beacon.discovery.type.Bytes12;
import org.ethereum.beacon.discovery.type.Bytes16;

/**
 * Stores session status and all keys for discovery message exchange between us, `homeNode` and the
 * other `node`
 */
public class NodeSession {
  private static final Logger LOG = LogManager.getLogger(NodeSession.class);

  public static final int REQUEST_ID_SIZE = 8;

  /**
   * Maximum number of in-flight WHOAREYOU challenges retained per session. Bounds memory when an
   * initiator sends many ordinary packets before completing the handshake.
   */
  @VisibleForTesting static final int MAX_PENDING_WHOAREYOU = 5;

  /**
   * Maximum number of recent outbound nonces retained per session. A WHOAREYOU is accepted iff its
   * nonce is one of the last {@code MAX_RECENT_OUTBOUND_NONCES} we sent — broader than just the
   * latest (so concurrent ordinary packets work, and a resent WHOAREYOU referencing an earlier
   * packet is still bindable), narrower than "any nonce we've ever sent" (no unbounded growth in
   * {@code NodeSessionManager.lastNonceToSession}; stale post-auth WHOAREYOUs evict naturally).
   */
  @VisibleForTesting static final int MAX_RECENT_OUTBOUND_NONCES = 8;

  private final Bytes32 homeNodeId;
  private final LocalNodeRecordStore localNodeRecordStore;
  private final NodeSessionManager nodeSessionManager;
  private final KBuckets nodeBucketStorage;
  private final InetSocketAddress remoteAddress;
  private final Consumer<NetworkParcel> outgoingPipeline;
  private final Random rnd;
  private final Bytes nodeId;
  private Optional<NodeRecord> nodeRecord;
  private SessionState state = SessionState.INITIAL;
  private Bytes initiatorKey;
  private Bytes recipientKey;
  private final Map<Bytes, RequestInfo> requestIdStatuses;
  private final ExpirationScheduler<Bytes> requestExpirationScheduler;
  private final Signer signer;
  private Optional<InetSocketAddress> reportedExternalAddress = Optional.empty();

  // Pending WHOAREYOU challenges keyed by the ordinary packet nonce that caused each challenge.
  // The discv5 wire spec requires the WHOAREYOU nonce to mirror the offending packet's nonce, and
  // a handshake response signed against a prior challenge may arrive after a fresh challenge has
  // been issued for a different ordinary packet. Keeping the set bounded prevents an attacker (or
  // a busy peer) from forcing unbounded growth.
  private final Map<Bytes12, PendingWhoAreYou> pendingWhoAreYou =
      Collections.synchronizedMap(
          new LinkedHashMap<>(MAX_PENDING_WHOAREYOU + 1, 1.0f, true) {
            @Override
            protected boolean removeEldestEntry(final Map.Entry<Bytes12, PendingWhoAreYou> eldest) {
              return size() > MAX_PENDING_WHOAREYOU;
            }
          });

  private Optional<Bytes12> lastOutboundNonce = Optional.empty();

  // Bounded set of recent outbound nonces in insertion order. Used by the initiator to validate
  // incoming WHOAREYOU packets and by NodeSessionManager to bind WHOAREYOU → session. Capped at
  // MAX_RECENT_OUTBOUND_NONCES so memory does not grow with session lifetime.
  private final LinkedHashSet<Bytes12> recentOutboundNonces = new LinkedHashSet<>();
  private boolean active = true;
  private final Function<Random, Bytes12> nonceGenerator;

  public NodeSession(
      final Bytes nodeId,
      final Optional<NodeRecord> nodeRecord,
      final InetSocketAddress remoteAddress,
      final NodeSessionManager nodeSessionManager,
      final LocalNodeRecordStore localNodeRecordStore,
      final Signer signer,
      final KBuckets nodeBucketStorage,
      final Consumer<NetworkParcel> outgoingPipeline,
      final Random rnd,
      final ExpirationScheduler<Bytes> requestExpirationScheduler) {
    this(
        nodeId,
        nodeRecord,
        remoteAddress,
        nodeSessionManager,
        localNodeRecordStore,
        signer,
        nodeBucketStorage,
        outgoingPipeline,
        rnd,
        requestExpirationScheduler,
        // Insertion-ordered so getFirstAwait/SentRequestInfo() returns the earliest-created
        // (≈ earliest-sent) request — the one a WHOAREYOU nonce-referenced (spec §189-201).
        // ConcurrentHashMap iterates in hash-bucket order, which would pick a non-deterministic
        // request to embed in the handshake. Synchronization is provided by NodeSession's
        // synchronized methods (all access goes through them).
        Collections.synchronizedMap(new LinkedHashMap<>()));
  }

  @VisibleForTesting
  NodeSession(
      final Bytes nodeId,
      final Optional<NodeRecord> nodeRecord,
      final InetSocketAddress remoteAddress,
      final NodeSessionManager nodeSessionManager,
      final LocalNodeRecordStore localNodeRecordStore,
      final Signer signer,
      final KBuckets nodeBucketStorage,
      final Consumer<NetworkParcel> outgoingPipeline,
      final Random rnd,
      final ExpirationScheduler<Bytes> requestExpirationScheduler,
      final Map<Bytes, RequestInfo> requestIdStatuses) {
    this.nodeId = nodeId;
    this.nodeRecord = nodeRecord;
    this.remoteAddress = remoteAddress;
    this.localNodeRecordStore = localNodeRecordStore;
    this.nodeSessionManager = nodeSessionManager;
    this.nodeBucketStorage = nodeBucketStorage;
    this.signer = signer;
    this.homeNodeId = Bytes32.wrap(localNodeRecordStore.getLocalNodeRecord().getNodeId());
    this.outgoingPipeline = outgoingPipeline;
    this.rnd = rnd;
    this.requestExpirationScheduler = requestExpirationScheduler;
    this.nonceGenerator = new NonceGenerator();
    this.requestIdStatuses = requestIdStatuses;
  }

  public Bytes getNodeId() {
    return nodeId;
  }

  public Optional<NodeRecord> getNodeRecord() {
    return nodeRecord;
  }

  public InetSocketAddress getRemoteAddress() {
    return remoteAddress;
  }

  public void sendOutgoingOrdinary(final V5Message message) {
    LOG.trace(() -> String.format("Sending outgoing message %s in session %s", message, this));
    Bytes16 maskingIV = generateMaskingIV();
    Header<OrdinaryAuthData> header =
        Header.createOrdinaryHeader(getHomeNodeId(), Bytes12.wrap(generateNonce()));
    OrdinaryMessagePacket packet =
        OrdinaryMessagePacket.create(maskingIV, header, message, getInitiatorKey());
    sendOutgoing(maskingIV, packet);
  }

  public void sendOutgoingRandom(final Bytes randomData) {
    Header<OrdinaryAuthData> header =
        Header.createOrdinaryHeader(getHomeNodeId(), Bytes12.wrap(generateNonce()));
    OrdinaryMessagePacket packet = OrdinaryMessagePacket.createRandom(header, randomData);
    LOG.trace(
        () -> String.format("Sending outgoing Random message %s in session %s", packet, this));
    sendOutgoing(generateMaskingIV(), packet);
  }

  public synchronized void sendOutgoingWhoAreYou(final WhoAreYouPacket packet) {
    LOG.trace(
        () -> String.format("Sending outgoing WhoAreYou message %s in session %s", packet, this));
    Bytes16 maskingIV = generateMaskingIV();
    Bytes challengeData = Bytes.wrap(maskingIV, packet.getHeader().getBytes());
    Bytes12 msgNonce = packet.getHeader().getStaticHeader().getNonce();
    pendingWhoAreYou.put(msgNonce, new PendingWhoAreYou(packet, maskingIV, challengeData));
    sendOutgoing(maskingIV, packet);
  }

  public boolean hasPendingWhoAreYouForNonce(final Bytes12 nonce) {
    return pendingWhoAreYou.containsKey(nonce);
  }

  public void resendOutgoingWhoAreYouFor(final Bytes12 nonce) {
    final PendingWhoAreYou pending = pendingWhoAreYou.get(nonce);
    if (pending == null) {
      return;
    }
    LOG.trace(
        () ->
            String.format(
                "Resending outgoing WhoAreYou message %s in session %s", pending.packet(), this));
    // Reuse the original maskingIV so the challenge bytes the initiator signed over remain
    // identical.
    sendOutgoing(pending.maskingIV(), pending.packet());
  }

  /**
   * Resends the first pending WHOAREYOU challenge when a second ordinary packet arrives while a
   * handshake is already in progress. Mirrors geth's handleUnknown which always resends the current
   * challenge rather than issuing a fresh one with a different nonce.
   *
   * <p>Reads the entry via the values iterator rather than {@code get(nonce)} because {@link
   * #pendingWhoAreYou} is a {@link LinkedHashMap} with {@code accessOrder=true} — using {@code get}
   * would move the accessed entry to the tail, causing a subsequent call to pick a different
   * "first" entry when multiple pending challenges exist.
   */
  public void resendFirstOutgoingWhoAreYou() {
    final PendingWhoAreYou pending;
    synchronized (pendingWhoAreYou) {
      if (pendingWhoAreYou.isEmpty()) {
        return;
      }
      pending = pendingWhoAreYou.values().iterator().next();
    }
    LOG.trace(
        () ->
            String.format(
                "Resending outgoing WhoAreYou message %s in session %s", pending.packet(), this));
    sendOutgoing(pending.maskingIV(), pending.packet());
  }

  /**
   * Returns the challenge data ({@code maskingIV || header bytes}) for every pending WHOAREYOU. The
   * handshake handler attempts to match the incoming handshake against each candidate because the
   * handshake packet does not directly identify which challenge it answers.
   */
  public Collection<Bytes> getPendingWhoAreYouChallenges() {
    synchronized (pendingWhoAreYou) {
      return pendingWhoAreYou.values().stream()
          .map(PendingWhoAreYou::challengeData)
          .collect(Collectors.toUnmodifiableList());
    }
  }

  public void clearPendingWhoAreYouChallenges() {
    pendingWhoAreYou.clear();
  }

  public void sendOutgoingHandshake(
      final Header<HandshakeAuthData> header, final V5Message message) {
    LOG.trace(
        () ->
            String.format(
                "Sending outgoing Handshake message %s, %s in session %s", header, message, this));
    Bytes16 maskingIV = generateMaskingIV();
    HandshakeMessagePacket handshakeMessagePacket =
        HandshakeMessagePacket.create(maskingIV, header, message, getInitiatorKey());
    sendOutgoing(maskingIV, handshakeMessagePacket);
  }

  private void sendOutgoing(final Bytes16 maskingIV, final Packet<?> packet) {
    Bytes16 destNodeId = Bytes16.wrap(getNodeId(), 0);
    RawPacket rawPacket = RawPacket.createAndMask(maskingIV, packet, destNodeId);
    outgoingPipeline.accept(new NetworkParcelV5(rawPacket, remoteAddress));
  }

  /**
   * Creates object with request information: requestId etc, RequestInfo, designed to maintain
   * request status and its changes. Also stores info in session repository to track related
   * messages.
   *
   * <p>The value selected as request ID must allow for concurrent conversations. Using a timestamp
   * can result in parallel conversations with the same id, so this should be avoided. Request IDs
   * also prevent replay of responses. Using a simple counter would be fine if the implementation
   * could ensure that restarts or even re-installs would increment the counter based on previously
   * saved state in all circumstances. The easiest to implement is a random number.
   */
  public synchronized RequestInfo createNextRequest(final Request<?> request) {
    byte[] requestId = new byte[REQUEST_ID_SIZE];
    rnd.nextBytes(requestId);
    Bytes wrappedId = Bytes.wrap(requestId);
    request
        .getResultPromise()
        .whenComplete(
            (aVoid, throwable) -> {
              if (throwable == null) {
                updateLiveness();
              }
            });
    RequestInfo requestInfo = RequestInfo.create(wrappedId, request);
    requestIdStatuses.put(wrappedId, requestInfo);
    requestExpirationScheduler.put(
        wrappedId,
        () -> {
          LOG.trace(
              () ->
                  String.format(
                      "Request %s expired for id %s in session %s: no reply",
                      requestInfo, wrappedId, this));
          // Route through the synchronized helper so the removal serialises with iterations
          // in getFirstAwait/SentRequestInfo() and cancelAllRequests(). The underlying
          // synchronizedMap(LinkedHashMap) throws CME on concurrent structural modification
          // during iteration.
          clearRequestInfo(wrappedId);
          resetHandshakeState();
        });
    return requestInfo;
  }

  private synchronized void resetHandshakeState() {
    if (state == SessionState.WHOAREYOU_SENT || state == SessionState.RANDOM_PACKET_SENT) {
      pendingWhoAreYou.clear();
      if (!recentOutboundNonces.isEmpty()) {
        // Snapshot before clearing so the manager iterates a stable collection. The live set is
        // cleared immediately after; passing it directly would hand the manager a reference that
        // becomes empty before it finishes iterating (in tests) or is unexpectedly mutated.
        // Route bulk eviction through the manager so lastNonceToSession stays in sync with the
        // bounded window. Without this, orphaned mappings would linger until session delete.
        nodeSessionManager.removeNoncesForSession(this, Set.copyOf(recentOutboundNonces));
        recentOutboundNonces.clear();
      }
      setState(SessionState.INITIAL);
    }
  }

  /** Updates request info. Thread-safe. */
  public synchronized void cancelAllRequests(final String message) {
    LOG.trace(() -> String.format("Cancelling all requests in session %s", this));
    final Set<Bytes> requestIdsCopy = new HashSet<>(requestIdStatuses.keySet());
    requestIdsCopy.forEach(
        requestId -> {
          final RequestInfo requestInfo = clearRequestInfo(requestId);
          if (requestInfo != null) {
            try {
              requestInfo
                  .getRequest()
                  .getResultPromise()
                  .completeExceptionally(
                      new RuntimeException(
                          String.format(
                              "Request %s cancelled due to reason: %s", requestInfo, message)));
            } catch (Exception e) {
              LOG.debug("Exception occurred clearing requests", e);
            }
          } else {
            LOG.debug("Found an empty requestInfo for requestId {}", () -> requestId);
          }
        });
  }

  /** Generates random nonce */
  public synchronized Bytes12 generateNonce() {
    final Bytes12 newNonce = nonceGenerator.apply(rnd);
    lastOutboundNonce = Optional.of(newNonce);
    recentOutboundNonces.add(newNonce);
    Optional<Bytes12> evicted = Optional.empty();
    if (recentOutboundNonces.size() > MAX_RECENT_OUTBOUND_NONCES) {
      final Bytes12 eldest = recentOutboundNonces.iterator().next();
      recentOutboundNonces.remove(eldest);
      evicted = Optional.of(eldest);
    }
    if (active) {
      // Update while synchronized so the manager's map stays consistent with the session's
      // bounded window. Skip when the session is inactive to avoid re-adding a removed session.
      nodeSessionManager.onSessionLastNonceUpdate(this, evicted, newNonce);
    }
    return newNonce;
  }

  /**
   * Generates a nonce for a <em>handshake</em> packet. Unlike {@link #generateNonce()}, this nonce
   * is not tracked in the recent-outbound window because WHOAREYOU packets never reference
   * handshake-packet nonces; tracking them would wastefully evict ordinary-packet nonces from the
   * bounded window.
   */
  public synchronized Bytes12 generateHandshakeNonce() {
    return nonceGenerator.apply(rnd);
  }

  public synchronized boolean hasRecentOutboundNonce(final Bytes12 nonce) {
    return recentOutboundNonces.contains(nonce);
  }

  public synchronized Optional<Bytes12> getLastOutboundNonce() {
    return lastOutboundNonce;
  }

  public synchronized void markInactive() {
    active = false;
  }

  /** If true indicates that handshake is complete */
  public synchronized boolean isAuthenticated() {
    return SessionState.AUTHENTICATED.equals(state);
  }

  public Bytes32 getHomeNodeId() {
    return homeNodeId;
  }

  public Bytes16 generateMaskingIV() {
    final byte[] ivBytes = new byte[16];
    rnd.nextBytes(ivBytes);
    return Bytes16.wrap(ivBytes);
  }

  /** return initiator key, also known as write key */
  public Bytes getInitiatorKey() {
    return initiatorKey;
  }

  public void setInitiatorKey(final Bytes initiatorKey) {
    this.initiatorKey = initiatorKey;
  }

  /** return recipient key, also known as read key */
  public Bytes getRecipientKey() {
    return recipientKey;
  }

  public void setRecipientKey(final Bytes recipientKey) {
    this.recipientKey = recipientKey;
  }

  public Optional<InetSocketAddress> getReportedExternalAddress() {
    return reportedExternalAddress;
  }

  public void setReportedExternalAddress(final InetSocketAddress reportedExternalAddress) {
    this.reportedExternalAddress = Optional.of(reportedExternalAddress);
  }

  @SuppressWarnings("unchecked")
  public synchronized <T> void clearRequestInfo(final Bytes requestId, T result) {
    final RequestInfo requestInfo = clearRequestInfo(requestId);
    checkNotNull(requestInfo, "Attempting to clear an unknown request");
    ((Request<T>) requestInfo.getRequest()).getResultPromise().complete(result);
  }

  /** Updates nodeRecord {@link NodeStatus} to ACTIVE of the node associated with this session */
  public synchronized void updateLiveness() {
    nodeRecord.ifPresent(nodeBucketStorage::onNodeContacted);
  }

  private synchronized RequestInfo clearRequestInfo(final Bytes requestId) {
    final RequestInfo requestInfo = requestIdStatuses.remove(requestId);
    requestExpirationScheduler.cancel(requestId);
    return requestInfo;
  }

  public synchronized Optional<RequestInfo> getRequestInfo(final Bytes requestId) {
    if (requestId == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(requestIdStatuses.get(requestId));
  }

  /**
   * Returns any queued {@link RequestInfo} which was not started because session is not
   * authenticated
   */
  public synchronized Optional<RequestInfo> getFirstAwaitRequestInfo() {
    return requestIdStatuses.values().stream()
        .filter(requestInfo -> AWAIT.equals(requestInfo.getTaskStatus()))
        .findFirst();
  }

  public synchronized Optional<RequestInfo> getFirstSentRequestInfo() {
    return requestIdStatuses.values().stream()
        .filter(requestInfo -> SENT.equals(requestInfo.getTaskStatus()))
        .findFirst();
  }

  /** Returns the first request eligible for handshake embedding (AWAIT preferred over SENT). */
  public synchronized Optional<RequestInfo> getFirstPendingRequestInfo() {
    return getFirstAwaitRequestInfo().or(this::getFirstSentRequestInfo);
  }

  public Stream<NodeRecord> getNodeRecordsInBucket(final int distance) {
    return nodeBucketStorage.getLiveNodeRecords(distance);
  }

  public NodeRecord getHomeNodeRecord() {
    return localNodeRecordStore.getLocalNodeRecord();
  }

  public synchronized void onNodeRecordReceived(final NodeRecord node) {
    if (node.getNodeId().equals(nodeId) && isUpdateRequired(node, nodeRecord)) {
      LOG.trace(
          () ->
              String.format(
                  "NodeRecord updated from %s to %s in session %s", nodeRecord, node, this));
      nodeRecord = Optional.of(node);
    }
    nodeBucketStorage.offer(node);
  }

  private boolean isUpdateRequired(
      final NodeRecord newRecord, final Optional<NodeRecord> existingRecord) {
    return existingRecord.isEmpty()
        || existingRecord.get().getSeq().compareTo(newRecord.getSeq()) < 0;
  }

  @Override
  public String toString() {
    return "NodeSession{" + nodeId + " (" + state + ")}";
  }

  public synchronized SessionState getState() {
    return state;
  }

  public synchronized void setState(final SessionState newStatus) {
    LOG.trace(
        () -> String.format("Switching status of node %s from %s to %s", nodeId, state, newStatus));
    this.state = newStatus;
  }

  public Signer getSigner() {
    return signer;
  }

  public enum SessionState {
    INITIAL, // other side is trying to connect, or we are initiating (before random packet is sent
    WHOAREYOU_SENT, // other side is initiator, we've sent whoareyou in response
    RANDOM_PACKET_SENT, // our node is initiator, we've sent random packet
    AUTHENTICATED
  }

  private record PendingWhoAreYou(WhoAreYouPacket packet, Bytes16 maskingIV, Bytes challengeData) {}
}
