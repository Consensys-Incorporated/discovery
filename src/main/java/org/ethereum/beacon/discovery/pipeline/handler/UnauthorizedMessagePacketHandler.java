/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.pipeline.handler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.units.bigints.UInt64;
import org.ethereum.beacon.discovery.packet.Header;
import org.ethereum.beacon.discovery.packet.OrdinaryMessagePacket;
import org.ethereum.beacon.discovery.packet.WhoAreYouPacket;
import org.ethereum.beacon.discovery.packet.WhoAreYouPacket.WhoAreYouAuthData;
import org.ethereum.beacon.discovery.pipeline.AbstractSkippingEnvelopeHandler;
import org.ethereum.beacon.discovery.pipeline.Envelope;
import org.ethereum.beacon.discovery.pipeline.Field;
import org.ethereum.beacon.discovery.pipeline.HandlerUtil;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeSession;
import org.ethereum.beacon.discovery.schema.NodeSession.SessionState;
import org.ethereum.beacon.discovery.type.Bytes12;
import org.ethereum.beacon.discovery.type.Bytes16;
import org.ethereum.beacon.discovery.util.Functions;

public class UnauthorizedMessagePacketHandler extends AbstractSkippingEnvelopeHandler {

  private static final Logger LOG = LogManager.getLogger(UnauthorizedMessagePacketHandler.class);

  @Override
  protected void handlePacket(Envelope envelope) {
    if (!HandlerUtil.requireField(Field.UNAUTHORIZED_PACKET_MESSAGE, envelope)) {
      return;
    }
    if (!HandlerUtil.requireField(Field.SESSION, envelope)) {
      return;
    }
    LOG.trace(
        () ->
            String.format(
                "Envelope %s in UnauthorizedMessagePacketHandler, requirements are satisfied!",
                envelope.getIdString()));

    NodeSession session = envelope.get(Field.SESSION);

    OrdinaryMessagePacket unknownPacket = envelope.get(Field.UNAUTHORIZED_PACKET_MESSAGE);
    Bytes12 msgNonce = unknownPacket.getHeader().getStaticHeader().getNonce();

    // If we have already issued a WHOAREYOU for this exact ordinary packet nonce, resend that
    // same challenge — the initiator may have already signed against it.
    if (session.hasPendingWhoAreYouForNonce(msgNonce)) {
      session.resendOutgoingWhoAreYouFor(msgNonce);
      return;
    }
    // If any WHOAREYOU challenge is already in flight (different nonce), resend the first one.
    // The initiator may have signed against it and is now sending concurrent requests before the
    // handshake completes. Issuing a new challenge with a different nonce would break the
    // in-progress handshake. Mirrors geth's handleUnknown behaviour.
    if (session.getState() == SessionState.WHOAREYOU_SENT) {
      session.resendFirstOutgoingWhoAreYou();
      return;
    }

    try {
      Bytes16 idNonce = Bytes16.random(Functions.getRandom());

      Header<WhoAreYouAuthData> header =
          Header.createWhoAreYouHeader(
              msgNonce,
              idNonce,
              session.getNodeRecord().map(NodeRecord::getSeq).orElse(UInt64.ZERO));
      WhoAreYouPacket whoAreYouPacket = WhoAreYouPacket.create(header);
      session.sendOutgoingWhoAreYou(whoAreYouPacket);

      session.setState(SessionState.WHOAREYOU_SENT);
    } catch (Exception ex) {
      String error =
          String.format(
              "Failed to read message [%s] from node %s in status %s",
              unknownPacket, session.getNodeRecord(), session.getState());
      LOG.trace(error, ex);
      envelope.put(Field.BAD_PACKET, unknownPacket);
      envelope.put(Field.BAD_EXCEPTION, ex);
    }
    envelope.remove(Field.PACKET_MESSAGE);
  }
}
