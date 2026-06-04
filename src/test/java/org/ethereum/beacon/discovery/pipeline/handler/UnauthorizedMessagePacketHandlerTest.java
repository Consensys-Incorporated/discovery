/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.pipeline.handler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.ethereum.beacon.discovery.packet.Header;
import org.ethereum.beacon.discovery.packet.OrdinaryMessagePacket;
import org.ethereum.beacon.discovery.packet.OrdinaryMessagePacket.OrdinaryAuthData;
import org.ethereum.beacon.discovery.packet.WhoAreYouPacket;
import org.ethereum.beacon.discovery.pipeline.Envelope;
import org.ethereum.beacon.discovery.pipeline.Field;
import org.ethereum.beacon.discovery.schema.NodeSession;
import org.ethereum.beacon.discovery.schema.NodeSession.SessionState;
import org.ethereum.beacon.discovery.type.Bytes12;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class UnauthorizedMessagePacketHandlerTest {

  private final UnauthorizedMessagePacketHandler handler = new UnauthorizedMessagePacketHandler();

  @Test
  void shouldResendExistingWhoAreYouWhenNonceMatchesPending() {
    final NodeSession session = mock(NodeSession.class);
    when(session.getState()).thenReturn(SessionState.WHOAREYOU_SENT);

    final OrdinaryMessagePacket packet = createOrdinaryPacket();
    final Bytes12 nonce = packet.getHeader().getStaticHeader().getNonce();
    when(session.hasPendingWhoAreYouForNonce(nonce)).thenReturn(true);

    handler.handle(envelopeWith(session, packet));

    verify(session).resendOutgoingWhoAreYouFor(nonce);
    verify(session, never()).sendOutgoingWhoAreYou(any());
    verify(session, never()).setState(any());
  }

  @Test
  void shouldNotChangeStateWhenResendingForKnownNonce() {
    final NodeSession session = mock(NodeSession.class);
    when(session.getState()).thenReturn(SessionState.WHOAREYOU_SENT);

    final OrdinaryMessagePacket packet = createOrdinaryPacket();
    final Bytes12 nonce = packet.getHeader().getStaticHeader().getNonce();
    when(session.hasPendingWhoAreYouForNonce(nonce)).thenReturn(true);

    handler.handle(envelopeWith(session, packet));

    verify(session, never()).setState(any());
  }

  @Test
  void shouldResendFirstExistingWhoAreYouWhenIncomingNonceIsUnknownDuringHandshake() {
    final NodeSession session = mock(NodeSession.class);
    when(session.getState()).thenReturn(SessionState.WHOAREYOU_SENT);
    when(session.getNodeRecord()).thenReturn(Optional.empty());

    final OrdinaryMessagePacket packet = createOrdinaryPacket();
    final Bytes12 incomingNonce = packet.getHeader().getStaticHeader().getNonce();
    // No pending WhoAreYou for this nonce — an earlier challenge was for a different nonce.
    // Per geth's handleUnknown: resend the existing challenge, don't issue a new one.
    when(session.hasPendingWhoAreYouForNonce(incomingNonce)).thenReturn(false);

    handler.handle(envelopeWith(session, packet));

    verify(session).resendFirstOutgoingWhoAreYou();
    verify(session, never()).sendOutgoingWhoAreYou(any());
    verify(session, never()).setState(any());
  }

  @Test
  void shouldSendNewWhoAreYouWithIncomingNonceWhenInInitialState() {
    final NodeSession session = mock(NodeSession.class);
    when(session.getState()).thenReturn(SessionState.INITIAL);
    when(session.getNodeRecord()).thenReturn(Optional.empty());

    final OrdinaryMessagePacket packet = createOrdinaryPacket();
    handler.handle(envelopeWith(session, packet));

    final ArgumentCaptor<WhoAreYouPacket> captor = ArgumentCaptor.forClass(WhoAreYouPacket.class);
    verify(session).sendOutgoingWhoAreYou(captor.capture());
    verify(session, never()).resendOutgoingWhoAreYouFor(any());
    verify(session).setState(SessionState.WHOAREYOU_SENT);

    // The WHOAREYOU nonce must echo the incoming packet's nonce so the initiator can
    // match it to their pending request.
    final Bytes12 expectedNonce = packet.getHeader().getStaticHeader().getNonce();
    assertThat(captor.getValue().getHeader().getStaticHeader().getNonce()).isEqualTo(expectedNonce);
  }

  @Test
  void shouldSkipWhenUnauthorizedPacketMessageFieldAbsent() {
    final NodeSession session = mock(NodeSession.class);
    final Envelope envelope = new Envelope();
    envelope.put(Field.SESSION, session);

    handler.handle(envelope);

    verify(session, never()).resendOutgoingWhoAreYouFor(any());
    verify(session, never()).sendOutgoingWhoAreYou(any());
  }

  @Test
  void shouldSkipWhenSessionFieldAbsent() {
    final Envelope envelope = new Envelope();
    envelope.put(Field.UNAUTHORIZED_PACKET_MESSAGE, createOrdinaryPacket());

    // Should not throw even without a session.
    handler.handle(envelope);
  }

  private static OrdinaryMessagePacket createOrdinaryPacket() {
    final Bytes12 nonce = Bytes12.wrap(Bytes.random(12));
    final Header<OrdinaryAuthData> header = Header.createOrdinaryHeader(Bytes32.ZERO, nonce);
    return OrdinaryMessagePacket.createRandom(header, Bytes.random(20));
  }

  private static Envelope envelopeWith(
      final NodeSession session, final OrdinaryMessagePacket packet) {
    final Envelope envelope = new Envelope();
    envelope.put(Field.UNAUTHORIZED_PACKET_MESSAGE, packet);
    envelope.put(Field.SESSION, session);
    return envelope;
  }
}
