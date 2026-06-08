/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.pipeline.handler;

import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.SECP256K1.KeyPair;
import org.apache.tuweni.units.bigints.UInt64;
import org.ethereum.beacon.discovery.message.V5Message;
import org.ethereum.beacon.discovery.packet.HandshakeMessagePacket.HandshakeAuthData;
import org.ethereum.beacon.discovery.packet.Header;
import org.ethereum.beacon.discovery.packet.WhoAreYouPacket;
import org.ethereum.beacon.discovery.pipeline.AbstractSkippingEnvelopeHandler;
import org.ethereum.beacon.discovery.pipeline.Envelope;
import org.ethereum.beacon.discovery.pipeline.Field;
import org.ethereum.beacon.discovery.pipeline.HandlerUtil;
import org.ethereum.beacon.discovery.pipeline.Pipeline;
import org.ethereum.beacon.discovery.pipeline.info.RequestInfo;
import org.ethereum.beacon.discovery.scheduler.Scheduler;
import org.ethereum.beacon.discovery.schema.EnrField;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeSession;
import org.ethereum.beacon.discovery.schema.NodeSession.SessionState;
import org.ethereum.beacon.discovery.task.TaskStatus;
import org.ethereum.beacon.discovery.type.Bytes12;
import org.ethereum.beacon.discovery.type.Bytes16;
import org.ethereum.beacon.discovery.util.Functions;

/** Handles {@link WhoAreYouPacket} in {@link Field#PACKET_WHOAREYOU} field */
public class WhoAreYouPacketHandler extends AbstractSkippingEnvelopeHandler {
  private static final Logger LOG = LogManager.getLogger(WhoAreYouPacketHandler.class);

  private final Pipeline outgoingPipeline;
  private final Scheduler scheduler;

  public WhoAreYouPacketHandler(final Pipeline outgoingPipeline, final Scheduler scheduler) {
    this.outgoingPipeline = outgoingPipeline;
    this.scheduler = scheduler;
  }

  @Override
  protected void handlePacket(final Envelope envelope) {
    if (!HandlerUtil.requireSessionWithNodeRecord(envelope)) {
      return;
    }
    if (!HandlerUtil.requireField(Field.PACKET_WHOAREYOU, envelope)) {
      return;
    }
    if (!HandlerUtil.requireField(Field.MASKING_IV, envelope)) {
      throw new IllegalStateException("Internal error: No MASKING_IV field for WhoAreYou packet");
    }
    LOG.trace(
        () ->
            String.format(
                "Envelope %s in WhoAreYouPacketHandler, requirements are satisfied!",
                envelope.getIdString()));

    WhoAreYouPacket whoAreYouPacket = envelope.get(Field.PACKET_WHOAREYOU);
    NodeSession session = envelope.get(Field.SESSION);
    try {
      final NodeRecord nodeRecord = session.getNodeRecord().orElseThrow();

      Bytes12 whoAreYouNonce = whoAreYouPacket.getHeader().getStaticHeader().getNonce();
      // Per spec §"WHOAREYOU is only ever valid as a response to a previously sent request":
      // accept iff the nonce is in our recent outbound window AND at least one request is still
      // pending. The first check rejects unknown / evicted nonces. The second check rejects a
      // stale or replayed WHOAREYOU whose referenced request has already been answered — without
      // this, a delayed duplicate could overwrite live session keys on an established session.
      final boolean recent = session.hasRecentOutboundNonce(whoAreYouNonce);
      final boolean hasPendingRequests = session.getFirstPendingRequestInfo().isPresent();
      if (!recent || !hasPendingRequests) {
        LOG.trace(
            "Ignoring WHOAREYOU [{}] from node {} (status {}): recent={}, hasPendingRequests={}",
            whoAreYouPacket,
            nodeRecord,
            session.getState(),
            recent,
            hasPendingRequests);
        envelope.remove(Field.PACKET_WHOAREYOU);
        return;
      }
      Bytes remotePubKey = (Bytes) nodeRecord.get(EnrField.PKEY_SECP256K1);
      byte[] ephemeralKeyBytes = new byte[32];
      Functions.getRandom().nextBytes(ephemeralKeyBytes);
      KeyPair ephemeralKeyPair =
          Functions.createKeyPairFromSecretBytes(Bytes32.wrap(ephemeralKeyBytes));

      // The handshake uses the unmasked WHOAREYOU challenge as an input:
      // challenge-data     = masking-iv || static-header || authdata
      Bytes16 whoAreYouMaskingIV = envelope.get(Field.MASKING_IV);
      Bytes challengeData =
          Bytes.wrap(
              whoAreYouMaskingIV,
              whoAreYouPacket
                  .getHeader()
                  .getBytes() // this is effectively `static-header || authdata`
              );

      Bytes32 destNodeId = Bytes32.wrap(nodeRecord.getNodeId());
      Functions.HKDFKeys hkdfKeys =
          Functions.hkdfExpand(
              session.getHomeNodeId(),
              destNodeId,
              ephemeralKeyPair.secretKey(),
              remotePubKey,
              challengeData);
      final Optional<RequestInfo> embeddedRequestOpt = session.getFirstPendingRequestInfo();
      if (embeddedRequestOpt.isEmpty()) {
        // Race: the last pending request expired between the gate above and this lookup
        // (session monitor is released between synchronized calls, and HKDF runs in between).
        // Treat the same as a gate miss — ignore the WHOAREYOU rather than throwing into
        // the catch path and calling cancelAllRequests for a benign race. Note: we have NOT
        // yet applied hkdfKeys to the session, so the previous session keys remain valid.
        LOG.trace(
            "Ignoring WHOAREYOU [{}] from node {} (status {}): no pending request after race",
            whoAreYouPacket,
            nodeRecord,
            session.getState());
        envelope.remove(Field.PACKET_WHOAREYOU);
        return;
      }
      final RequestInfo embeddedRequest = embeddedRequestOpt.get();
      final V5Message message = embeddedRequest.getMessage();

      // Past the race-check: we will emit a handshake, so it's safe to install the new keys.
      session.setInitiatorKey(hkdfKeys.getInitiatorKey());
      session.setRecipientKey(hkdfKeys.getRecipientKey());

      Bytes ephemeralPubKey =
          Functions.deriveCompressedPublicKeyFromPrivate(ephemeralKeyPair.secretKey());

      Bytes idSignature =
          HandshakeAuthData.signId(challengeData, ephemeralPubKey, destNodeId, session.getSigner());

      NodeRecord respRecord = null;
      UInt64 lastKnownOurEnrVer = whoAreYouPacket.getHeader().getAuthData().getEnrSeq();

      if (lastKnownOurEnrVer.compareTo(session.getHomeNodeRecord().getSeq()) < 0
          || lastKnownOurEnrVer.isZero()) {
        respRecord = session.getHomeNodeRecord();
      }
      Header<HandshakeAuthData> header =
          Header.createHandshakeHeader(
              session.getHomeNodeId(),
              session.generateHandshakeNonce(),
              idSignature,
              ephemeralPubKey,
              Optional.ofNullable(respRecord));
      session.setState(SessionState.AUTHENTICATED);

      session.sendOutgoingHandshake(header, message);
      embeddedRequest.setTaskStatus(TaskStatus.SENT);

      envelope.remove(Field.PACKET_WHOAREYOU);
      NextTaskHandler.tryToSendAwaitTaskIfAny(session, outgoingPipeline, scheduler);
    } catch (Throwable ex) {
      String error =
          String.format(
              "Failed to read message [%s] from node %s in status %s",
              whoAreYouPacket, session.getNodeRecord(), session.getState());
      LOG.debug(error, ex);
      envelope.remove(Field.PACKET_WHOAREYOU);
      session.cancelAllRequests("Bad WHOAREYOU received from node");
    }
  }
}
