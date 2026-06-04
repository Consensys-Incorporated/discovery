/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery;

import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt64;
import org.ethereum.beacon.discovery.TestManagerWrapper.TestMessage;
import org.ethereum.beacon.discovery.crypto.DefaultSigner;
import org.ethereum.beacon.discovery.message.PingMessage;
import org.ethereum.beacon.discovery.packet.HandshakeMessagePacket;
import org.ethereum.beacon.discovery.packet.HandshakeMessagePacket.HandshakeAuthData;
import org.ethereum.beacon.discovery.packet.Header;
import org.ethereum.beacon.discovery.packet.OrdinaryMessagePacket;
import org.ethereum.beacon.discovery.packet.RawPacket;
import org.ethereum.beacon.discovery.packet.WhoAreYouPacket;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;
import org.ethereum.beacon.discovery.schema.NodeSession;
import org.ethereum.beacon.discovery.type.Bytes16;
import org.junit.jupiter.api.Test;

@SuppressWarnings("JavaCase")
public class DiscoveryManagerTest {

  @Test
  public void testRegularHandshake() {
    TestNetwork network = new TestNetwork();
    TestManagerWrapper m1 = network.createDiscoveryManager(1);
    TestManagerWrapper m2 = network.createDiscoveryManager(2);

    CompletableFuture<Void> pingRes = m1.getDiscoveryManager().ping(m2.getNodeRecord());

    TestMessage out1_1 = m1.nextOutbound();
    assertThat(out1_1.getPacket()).isInstanceOf(OrdinaryMessagePacket.class);
    m2.deliver(out1_1); // Random (Ping is pending)

    TestMessage out2_1 = m2.nextOutbound();
    assertThat(out2_1.getPacket()).isInstanceOf(WhoAreYouPacket.class);
    m1.deliver(out2_1); // WhoAreYou

    TestMessage out1_2 = m1.nextOutbound();
    assertThat(out1_2.getPacket()).isInstanceOf(HandshakeMessagePacket.class);
    m2.deliver(out1_2); // Handshake + pending Ping

    TestMessage out2_2 = m2.nextOutbound();
    assertThat(out2_2.getPacket()).isInstanceOf(OrdinaryMessagePacket.class);
    m1.deliver(out2_2); // Pong

    assertThat(pingRes).isCompleted();
  }

  @Test
  public void testInvalidHandshakeShouldDropsSession() {
    TestNetwork network = new TestNetwork();
    TestManagerWrapper attackerNode = network.createDiscoveryManager(1);
    TestManagerWrapper victimNode = network.createDiscoveryManager(2);

    attackerNode.getDiscoveryManager().ping(victimNode.getNodeRecord());

    TestMessage out1_1 = attackerNode.nextOutbound();
    assertThat(out1_1.getPacket()).isInstanceOf(OrdinaryMessagePacket.class);
    victimNode.deliver(out1_1); // Random (Ping is pending)

    TestMessage out2_1 = victimNode.nextOutbound();
    assertThat(out2_1.getPacket()).isInstanceOf(WhoAreYouPacket.class);
    attackerNode.deliver(out2_1); // WhoAreYou

    TestMessage validHandshakeMessage = attackerNode.nextOutbound(); // valid Handshake
    assertThat(validHandshakeMessage.getPacket()).isInstanceOf(HandshakeMessagePacket.class);

    // preparing Handshake with invalid id signature
    NodeSession attackerToVictimSession =
        attackerNode
            .getDiscoveryManager()
            .getNodeSession(victimNode.getNodeRecord().getNodeId())
            .orElseThrow();
    HandshakeMessagePacket handshakePacket =
        (HandshakeMessagePacket) validHandshakeMessage.getPacket();
    RawPacket handshakeRawPacket = validHandshakeMessage.getRawPacket();
    Header<HandshakeAuthData> header = handshakePacket.getHeader();
    Bytes invalidSignature = new DefaultSigner(attackerNode.getSecretKey()).sign(Bytes32.ZERO);
    Header<HandshakeAuthData> malformedHeader =
        Header.createHandshakeHeader(
            header.getAuthData().getSourceNodeId(),
            header.getStaticHeader().getNonce(),
            invalidSignature,
            header.getAuthData().getEphemeralPubKey(),
            header.getAuthData().getNodeRecord(NodeRecordFactory.DEFAULT));
    HandshakeMessagePacket malformedHandshakePacket =
        HandshakeMessagePacket.create(
            handshakeRawPacket.getMaskingIV(),
            malformedHeader,
            new PingMessage(Bytes.EMPTY, UInt64.ONE),
            attackerToVictimSession.getInitiatorKey());
    Bytes16 maskingKey = Bytes16.wrap(victimNode.getNodeRecord().getNodeId(), 0);
    RawPacket malformedRawPacket =
        RawPacket.createAndMask(
            handshakeRawPacket.getMaskingIV(), malformedHandshakePacket, maskingKey);
    TestMessage malformedMessage = attackerNode.createOutbound(malformedRawPacket, victimNode);

    victimNode.deliver(malformedMessage); // Malformed Handshake
    victimNode.deliver(malformedMessage); // Malformed Handshake
    victimNode.deliver(validHandshakeMessage);

    // victim node should drop the session on the first malformed handshake message
    // and ignore any subsequent handshake messages
    assertThat(victimNode.maybeNextOutbound(ofSeconds(1))).isEmpty();
  }

  @Test
  public void testDroppedSession() {
    TestNetwork network = new TestNetwork();
    TestManagerWrapper m1 = network.createDiscoveryManager(1);
    TestManagerWrapper m2 = network.createDiscoveryManager(2);

    CompletableFuture<Void> pingRes1 = m1.getDiscoveryManager().ping(m2.getNodeRecord());

    m1.exchangeAll(m2);

    assertThat(pingRes1).isCompleted();

    // let's say M2 is restarted
    TestManagerWrapper m2_1 = network.createDiscoveryManager(2);

    // ping 1 => 2 would be unathorized on 2
    CompletableFuture<Void> pingRes2 = m1.getDiscoveryManager().ping(m2_1.getNodeRecord());

    // new handshake should be made
    m1.exchangeAll(m2_1);

    assertThat(pingRes2).isCompleted();
  }

  @Test
  public void testDoubleUnathorizedPing() {
    TestNetwork network = new TestNetwork();
    TestManagerWrapper m1 = network.createDiscoveryManager(1);
    TestManagerWrapper m2 = network.createDiscoveryManager(2);

    CompletableFuture<Void> pingRes1 = m1.getDiscoveryManager().ping(m2.getNodeRecord());

    m1.exchangeAll(m2);

    assertThat(pingRes1).isCompleted();

    // let's say M2 is restarted
    TestManagerWrapper m2_1 = network.createDiscoveryManager(2);

    // ping 1 => 2 would be unathorized on 2
    m1.getDiscoveryManager().ping(m2.getNodeRecord());

    TestMessage out1_2 = m1.nextOutbound();
    m2_1.deliver(out1_2); // sending Ping 1 => 2

    TestMessage out2_1_1 = m2_1.nextOutbound(); // should be WHoAreYou
    assertThat(out2_1_1.getPacket()).isInstanceOf(WhoAreYouPacket.class);

    m1.getDiscoveryManager().ping(m2.getNodeRecord());

    TestMessage out1_3 = m1.nextOutbound();
    m2_1.deliver(out1_3); // instead of 1 => 2 Handshake sending an unathorized Ping again

    TestMessage out2_1_2 = m2_1.nextOutbound(); // expecting that 2 responds with WhoAreYou again
    assertThat(out2_1_2.getPacket()).isInstanceOf(WhoAreYouPacket.class);
    m1.deliver(out2_1_2);

    m1.exchangeAll(m2_1);

    // should be ok now
    CompletableFuture<Void> pingRes2 = m1.getDiscoveryManager().ping(m2.getNodeRecord());
    m1.exchangeAll(m2_1);
    assertThat(pingRes2).isCompleted();
  }

  /**
   * Mirrors geth's TestUDPv5_callResend: two pings issued before any session exists should both
   * complete after the handshake exchange finishes.
   */
  @Test
  public void callResendAfterHandshake() {
    TestNetwork network = new TestNetwork();
    TestManagerWrapper m1 = network.createDiscoveryManager(1);
    TestManagerWrapper m2 = network.createDiscoveryManager(2);

    // Issue two pings before the session is established (analogous to geth's two goroutines).
    CompletableFuture<Void> ping1 = m1.getDiscoveryManager().ping(m2.getNodeRecord());
    CompletableFuture<Void> ping2 = m1.getDiscoveryManager().ping(m2.getNodeRecord());

    // m1 sends a random ordinary packet to initiate the handshake.
    m2.deliver(m1.nextOutbound());

    // m2 doesn't recognise m1 → sends WHOAREYOU.
    TestMessage whoAreYou = m2.nextOutbound();
    assertThat(whoAreYou.getPacket()).isInstanceOf(WhoAreYouPacket.class);
    m1.deliver(whoAreYou);

    // m1 responds with a handshake packet that embeds the first pending ping (the "resend").
    TestMessage handshake = m1.nextOutbound();
    assertThat(handshake.getPacket()).isInstanceOf(HandshakeMessagePacket.class);
    m2.deliver(handshake);

    // m2 processes the handshake, extracts the embedded ping, and sends a PONG.
    TestMessage pong1 = m2.nextOutbound();
    assertThat(pong1.getPacket()).isInstanceOf(OrdinaryMessagePacket.class);
    m1.deliver(pong1);

    // The second pending ping must now be sent as an ordinary packet (after the 1-second delay).
    TestMessage secondPing = m1.nextOutbound();
    assertThat(secondPing.getPacket()).isInstanceOf(OrdinaryMessagePacket.class);
    m2.deliver(secondPing);

    // m2 sends a PONG for the second ping.
    m1.deliver(m2.nextOutbound());

    // Both ping futures must have completed.
    assertThat(ping1).isCompleted();
    assertThat(ping2).isCompleted();
  }

  @Test
  public void testUniqueAesGcmNonceUsed() {
    TestNetwork network = new TestNetwork();
    TestManagerWrapper m1 = network.createDiscoveryManager(1);
    TestManagerWrapper m2 = network.createDiscoveryManager(2);

    CompletableFuture<Void> pingRes1 = m1.getDiscoveryManager().ping(m2.getNodeRecord());

    TestMessage out1_1 = m1.nextOutbound();
    m2.deliver(out1_1); // Random (Ping is pending)

    TestMessage out2_1 = m2.nextOutbound();
    m1.deliver(out2_1); // WhoAreYou

    // WhoAreYou should have the same nonce as inbound 'random' packet
    assertThat(((WhoAreYouPacket) out2_1.getPacket()).getHeader().getStaticHeader().getNonce())
        .isEqualTo(
            ((OrdinaryMessagePacket) out1_1.getPacket()).getHeader().getStaticHeader().getNonce());

    TestMessage out1_2 = m1.nextOutbound();
    m2.deliver(out1_2); // Handshake + pending Ping

    TestMessage out2_2 = m2.nextOutbound();
    m1.deliver(out2_2); // Pong

    assertThat(pingRes1).isCompleted();

    CompletableFuture<Void> pingRes2 = m1.getDiscoveryManager().ping(m2.getNodeRecord());

    TestMessage out1_3 = m1.nextOutbound();
    m2.deliver(out1_3); // Regular Ping

    TestMessage out2_3 = m2.nextOutbound();
    m1.deliver(out2_3); // Regular Pong

    assertThat(pingRes2).isCompleted();

    // all message (except WhoAreYou) nonces should be distinct
    assertThat(
            Stream.of(out1_1, out1_2, out1_3, out2_2, out2_3)
                .map(packet -> packet.getPacket().getHeader().getStaticHeader().getNonce()))
        .doesNotHaveDuplicates();
  }
}
