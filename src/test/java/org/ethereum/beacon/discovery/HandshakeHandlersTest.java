/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.ethereum.beacon.discovery.AddressAccessPolicy.ALLOW_ALL;
import static org.ethereum.beacon.discovery.TestUtil.NODE_RECORD_FACTORY_NO_VERIFICATION;
import static org.ethereum.beacon.discovery.pipeline.Field.BAD_PACKET;
import static org.ethereum.beacon.discovery.pipeline.Field.MASKING_IV;
import static org.ethereum.beacon.discovery.pipeline.Field.MESSAGE;
import static org.ethereum.beacon.discovery.pipeline.Field.PACKET_HANDSHAKE;
import static org.ethereum.beacon.discovery.pipeline.Field.PACKET_MESSAGE;
import static org.ethereum.beacon.discovery.pipeline.Field.SESSION;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.time.Clock;
import java.util.Optional;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt64;
import org.ethereum.beacon.discovery.TestUtil.NodeInfo;
import org.ethereum.beacon.discovery.crypto.DefaultSigner;
import org.ethereum.beacon.discovery.crypto.Signer;
import org.ethereum.beacon.discovery.liveness.LivenessChecker;
import org.ethereum.beacon.discovery.message.FindNodeMessage;
import org.ethereum.beacon.discovery.message.PingMessage;
import org.ethereum.beacon.discovery.message.handler.EnrUpdateTracker;
import org.ethereum.beacon.discovery.message.handler.ExternalAddressSelector;
import org.ethereum.beacon.discovery.network.NetworkParcel;
import org.ethereum.beacon.discovery.packet.HandshakeMessagePacket;
import org.ethereum.beacon.discovery.packet.Header;
import org.ethereum.beacon.discovery.packet.MessagePacket;
import org.ethereum.beacon.discovery.packet.OrdinaryMessagePacket;
import org.ethereum.beacon.discovery.packet.OrdinaryMessagePacket.OrdinaryAuthData;
import org.ethereum.beacon.discovery.packet.Packet;
import org.ethereum.beacon.discovery.packet.RawPacket;
import org.ethereum.beacon.discovery.packet.WhoAreYouPacket;
import org.ethereum.beacon.discovery.pipeline.Envelope;
import org.ethereum.beacon.discovery.pipeline.Field;
import org.ethereum.beacon.discovery.pipeline.Pipeline;
import org.ethereum.beacon.discovery.pipeline.PipelineImpl;
import org.ethereum.beacon.discovery.pipeline.handler.HandshakeMessagePacketHandler;
import org.ethereum.beacon.discovery.pipeline.handler.MessageHandler;
import org.ethereum.beacon.discovery.pipeline.handler.MessagePacketHandler;
import org.ethereum.beacon.discovery.pipeline.handler.NodeSessionManager;
import org.ethereum.beacon.discovery.pipeline.handler.WhoAreYouPacketHandler;
import org.ethereum.beacon.discovery.pipeline.info.FindNodeResponseHandler;
import org.ethereum.beacon.discovery.pipeline.info.MultiPacketResponseHandler;
import org.ethereum.beacon.discovery.pipeline.info.Request;
import org.ethereum.beacon.discovery.pipeline.info.RequestInfo;
import org.ethereum.beacon.discovery.scheduler.ExpirationScheduler;
import org.ethereum.beacon.discovery.scheduler.ExpirationSchedulerFactory;
import org.ethereum.beacon.discovery.scheduler.Scheduler;
import org.ethereum.beacon.discovery.scheduler.Schedulers;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;
import org.ethereum.beacon.discovery.schema.NodeSession;
import org.ethereum.beacon.discovery.storage.KBuckets;
import org.ethereum.beacon.discovery.storage.LocalNodeRecordStore;
import org.ethereum.beacon.discovery.storage.NewAddressHandler;
import org.ethereum.beacon.discovery.storage.NodeRecordListener;
import org.ethereum.beacon.discovery.task.TaskStatus;
import org.ethereum.beacon.discovery.type.Bytes12;
import org.ethereum.beacon.discovery.type.Bytes16;
import org.junit.jupiter.api.Test;

@SuppressWarnings({"DoubleBraceInitialization"})
public class HandshakeHandlersTest {
  private final Random rnd = new Random(1);
  private final Clock clock = Clock.systemUTC();

  @Test
  public void authHandlerWithMessageRoundTripTest() throws Exception {
    // Node1
    NodeInfo nodePair1 = TestUtil.generateUnverifiedNode(30303);
    NodeRecord nodeRecord1 = nodePair1.getNodeRecord();
    Signer signer1 = new DefaultSigner(nodePair1.getSecretKey());
    // Node2
    NodeInfo nodePair2 = TestUtil.generateUnverifiedNode(30304);
    NodeRecord nodeRecord2 = nodePair2.getNodeRecord();
    Signer signer2 = new DefaultSigner(nodePair2.getSecretKey());

    final LocalNodeRecordStore localNodeRecordStoreAt1 =
        new LocalNodeRecordStore(
            nodeRecord1, signer1, NodeRecordListener.NOOP, NewAddressHandler.NOOP);
    KBuckets nodeBucketStorage1 =
        new KBuckets(clock, localNodeRecordStoreAt1, new LivenessChecker(clock));
    KBuckets nodeBucketStorage2 =
        new KBuckets(
            clock,
            new LocalNodeRecordStore(
                nodeRecord2, signer2, NodeRecordListener.NOOP, NewAddressHandler.NOOP),
            new LivenessChecker(clock));

    // Node1 create AuthHeaderPacket
    LinkedBlockingQueue<RawPacket> outgoing1Packets = new LinkedBlockingQueue<>();
    final Consumer<NetworkParcel> outgoingMessages1to2 =
        parcel -> {
          System.out.println("Outgoing packet from 1 to 2: " + parcel.getPacket());
          outgoing1Packets.add(parcel.getPacket());
        };
    final ExpirationSchedulerFactory expirationSchedulerFactory =
        new ExpirationSchedulerFactory(Executors.newSingleThreadScheduledExecutor());
    final ExpirationScheduler<Bytes> reqeustExpirationScheduler =
        expirationSchedulerFactory.create(60, TimeUnit.SECONDS);
    NodeSession nodeSessionAt1For2 =
        new NodeSession(
            nodeRecord2.getNodeId(),
            Optional.of(nodeRecord2),
            nodePair2.getNodeRecord().getUdpAddress().orElseThrow(),
            mock(NodeSessionManager.class),
            localNodeRecordStoreAt1,
            signer1,
            nodeBucketStorage1,
            outgoingMessages1to2,
            rnd,
            reqeustExpirationScheduler);
    LinkedBlockingQueue<RawPacket> outgoing2Packets = new LinkedBlockingQueue<>();
    final Consumer<NetworkParcel> outgoingMessages2to1 =
        parcel -> {
          // do nothing, we don't need to test it here
          System.out.println("Outgoing packet from 2 to 1: " + parcel.getPacket());
          outgoing2Packets.add(parcel.getPacket());
        };
    NodeSession nodeSessionAt2For1 =
        new NodeSession(
            nodeRecord1.getNodeId(),
            Optional.of(nodeRecord1),
            nodeRecord1.getUdpAddress().orElseThrow(),
            mock(NodeSessionManager.class),
            new LocalNodeRecordStore(
                nodeRecord2, signer2, NodeRecordListener.NOOP, NewAddressHandler.NOOP),
            signer2,
            nodeBucketStorage2,
            outgoingMessages2to1,
            rnd,
            reqeustExpirationScheduler);

    Scheduler taskScheduler = Schedulers.createDefault().events();
    Pipeline outgoingPipeline = new PipelineImpl().build();
    WhoAreYouPacketHandler whoAreYouPacketHandlerNode1 =
        new WhoAreYouPacketHandler(outgoingPipeline, taskScheduler);

    nodeSessionAt1For2.sendOutgoingRandom(Bytes.random(128));
    Bytes12 randomMessageNonce = nodeSessionAt1For2.getLastOutboundNonce().orElseThrow();
    outgoing1Packets.clear();

    Envelope envelopeAt1From2 = new Envelope();
    Bytes16 idNonce = Bytes16.random(rnd);
    WhoAreYouPacket whoAreYouPacket =
        WhoAreYouPacket.create(
            Header.createWhoAreYouHeader(randomMessageNonce, idNonce, UInt64.ZERO));
    nodeSessionAt2For1.sendOutgoingWhoAreYou(whoAreYouPacket);

    envelopeAt1From2.put(Field.PACKET_WHOAREYOU, whoAreYouPacket);
    envelopeAt1From2.put(Field.SESSION, nodeSessionAt1For2);
    Request<Void> request =
        new Request<>(
            new CompletableFuture<>(),
            id -> new FindNodeMessage(id, singletonList(1)),
            new FindNodeResponseHandler(singletonList(1), ALLOW_ALL));
    nodeSessionAt1For2.createNextRequest(request);

    RawPacket whoAreYouRawPacket = outgoing2Packets.poll(1, TimeUnit.SECONDS);
    envelopeAt1From2.put(MASKING_IV, whoAreYouRawPacket.getMaskingIV());
    whoAreYouPacketHandlerNode1.handle(envelopeAt1From2);

    // Node2 handle AuthHeaderPacket and finish handshake
    HandshakeMessagePacketHandler handshakeMessagePacketHandlerNode2 =
        new HandshakeMessagePacketHandler(
            outgoingPipeline,
            taskScheduler,
            NODE_RECORD_FACTORY_NO_VERIFICATION,
            mock(NodeSessionManager.class),
            ALLOW_ALL);
    Envelope envelopeAt2From1 = new Envelope();
    RawPacket handshakeRawPacket = outgoing1Packets.poll(1, TimeUnit.SECONDS);
    envelopeAt2From1.put(
        PACKET_HANDSHAKE,
        (HandshakeMessagePacket)
            handshakeRawPacket.demaskPacket(nodePair2.getNodeRecord().getNodeId()));
    envelopeAt2From1.put(SESSION, nodeSessionAt2For1);
    assertFalse(nodeSessionAt2For1.isAuthenticated());

    envelopeAt2From1.put(MASKING_IV, handshakeRawPacket.getMaskingIV());
    handshakeMessagePacketHandlerNode2.handle(envelopeAt2From1);
    assertTrue(nodeSessionAt2For1.isAuthenticated());

    // Node 1 handles message from Node 2
    MessagePacketHandler messagePacketHandler1 =
        new MessagePacketHandler(NodeRecordFactory.DEFAULT);
    Envelope envelopeAt1From2WithMessage = new Envelope();
    Bytes12 pingAuthTag = nodeSessionAt1For2.generateNonce();
    Bytes16 maskingIV = nodeSessionAt1For2.generateMaskingIV();
    OrdinaryMessagePacket pingPacketFrom2To1 =
        createPingPacket(
            maskingIV,
            pingAuthTag,
            nodeSessionAt2For1,
            nodeSessionAt2For1
                .createNextRequest(
                    new Request<Void>(
                        new CompletableFuture<>(),
                        id -> new PingMessage(id, UInt64.ZERO),
                        MultiPacketResponseHandler.SINGLE_PACKET_RESPONSE_HANDLER))
                .getRequestId());
    envelopeAt1From2WithMessage.put(PACKET_MESSAGE, pingPacketFrom2To1);
    envelopeAt1From2WithMessage.put(SESSION, nodeSessionAt1For2);
    envelopeAt1From2WithMessage.put(MASKING_IV, maskingIV);
    messagePacketHandler1.handle(envelopeAt1From2WithMessage);
    assertNull(envelopeAt1From2WithMessage.get(BAD_PACKET));
    assertNotNull(envelopeAt1From2WithMessage.get(MESSAGE));

    MessageHandler messageHandler =
        new MessageHandler(
            localNodeRecordStoreAt1,
            TalkHandler.NOOP,
            EnrUpdateTracker.EnrUpdater.NOOP,
            ExternalAddressSelector.NOOP);
    messageHandler.handle(envelopeAt1From2WithMessage);

    // Node 2 handles message from Node 1
    MessagePacketHandler messagePacketHandler2 =
        new MessagePacketHandler(NodeRecordFactory.DEFAULT);
    Envelope envelopeAt2From1WithMessage = new Envelope();
    RawPacket rawMesssagePacket = outgoing1Packets.poll(1, TimeUnit.SECONDS);
    Packet<?> pongPacketFrom1To2 =
        rawMesssagePacket.demaskPacket(nodePair2.getNodeRecord().getNodeId());
    envelopeAt2From1WithMessage.put(PACKET_MESSAGE, (MessagePacket<?>) pongPacketFrom1To2);
    envelopeAt2From1WithMessage.put(SESSION, nodeSessionAt2For1);
    envelopeAt2From1WithMessage.put(MASKING_IV, rawMesssagePacket.getMaskingIV());
    messagePacketHandler2.handle(envelopeAt2From1WithMessage);
    assertNull(envelopeAt2From1WithMessage.get(BAD_PACKET));
    assertNotNull(envelopeAt2From1WithMessage.get(MESSAGE));
  }

  /**
   * A handshake signed against an earlier WHOAREYOU must still be accepted by the responder even
   * when a fresh WHOAREYOU has been issued for a different ordinary packet nonce in the meantime.
   */
  @Test
  public void responderAcceptsHandshakeForEarlierPendingWhoAreYou() throws Exception {
    NodeInfo nodePair1 = TestUtil.generateUnverifiedNode(30303);
    NodeRecord nodeRecord1 = nodePair1.getNodeRecord();
    Signer signer1 = new DefaultSigner(nodePair1.getSecretKey());
    NodeInfo nodePair2 = TestUtil.generateUnverifiedNode(30304);
    NodeRecord nodeRecord2 = nodePair2.getNodeRecord();
    Signer signer2 = new DefaultSigner(nodePair2.getSecretKey());

    final LocalNodeRecordStore localNodeRecordStoreAt1 =
        new LocalNodeRecordStore(
            nodeRecord1, signer1, NodeRecordListener.NOOP, NewAddressHandler.NOOP);
    KBuckets nodeBucketStorage1 =
        new KBuckets(clock, localNodeRecordStoreAt1, new LivenessChecker(clock));
    KBuckets nodeBucketStorage2 =
        new KBuckets(
            clock,
            new LocalNodeRecordStore(
                nodeRecord2, signer2, NodeRecordListener.NOOP, NewAddressHandler.NOOP),
            new LivenessChecker(clock));

    LinkedBlockingQueue<RawPacket> outgoing1Packets = new LinkedBlockingQueue<>();
    final Consumer<NetworkParcel> outgoingMessages1to2 =
        parcel -> outgoing1Packets.add(parcel.getPacket());
    final ExpirationSchedulerFactory expirationSchedulerFactory =
        new ExpirationSchedulerFactory(Executors.newSingleThreadScheduledExecutor());
    final ExpirationScheduler<Bytes> requestExpirationScheduler =
        expirationSchedulerFactory.create(60, TimeUnit.SECONDS);
    NodeSession nodeSessionAt1For2 =
        new NodeSession(
            nodeRecord2.getNodeId(),
            Optional.of(nodeRecord2),
            nodePair2.getNodeRecord().getUdpAddress().orElseThrow(),
            mock(NodeSessionManager.class),
            localNodeRecordStoreAt1,
            signer1,
            nodeBucketStorage1,
            outgoingMessages1to2,
            rnd,
            requestExpirationScheduler);
    LinkedBlockingQueue<RawPacket> outgoing2Packets = new LinkedBlockingQueue<>();
    final Consumer<NetworkParcel> outgoingMessages2to1 =
        parcel -> outgoing2Packets.add(parcel.getPacket());
    NodeSession nodeSessionAt2For1 =
        new NodeSession(
            nodeRecord1.getNodeId(),
            Optional.of(nodeRecord1),
            nodeRecord1.getUdpAddress().orElseThrow(),
            mock(NodeSessionManager.class),
            new LocalNodeRecordStore(
                nodeRecord2, signer2, NodeRecordListener.NOOP, NewAddressHandler.NOOP),
            signer2,
            nodeBucketStorage2,
            outgoingMessages2to1,
            rnd,
            requestExpirationScheduler);

    Scheduler taskScheduler = Schedulers.createDefault().events();
    Pipeline outgoingPipeline = new PipelineImpl().build();
    WhoAreYouPacketHandler whoAreYouPacketHandlerNode1 =
        new WhoAreYouPacketHandler(outgoingPipeline, taskScheduler);

    // Step 1: Node1 sends ordinary packet n1.
    nodeSessionAt1For2.sendOutgoingRandom(Bytes.random(128));
    Bytes12 firstMessageNonce = nodeSessionAt1For2.getLastOutboundNonce().orElseThrow();
    outgoing1Packets.clear();

    // Step 2: Node2 issues WHOAREYOU c1 for n1.
    Bytes16 firstIdNonce = Bytes16.random(rnd);
    WhoAreYouPacket firstWhoAreYouPacket =
        WhoAreYouPacket.create(
            Header.createWhoAreYouHeader(firstMessageNonce, firstIdNonce, UInt64.ZERO));
    nodeSessionAt2For1.sendOutgoingWhoAreYou(firstWhoAreYouPacket);

    // Step 3: Node1 receives c1 and produces a handshake signed against it. Hold the handshake.
    Envelope envelopeAt1From2 = new Envelope();
    envelopeAt1From2.put(Field.PACKET_WHOAREYOU, firstWhoAreYouPacket);
    envelopeAt1From2.put(Field.SESSION, nodeSessionAt1For2);
    Request<Void> request =
        new Request<>(
            new CompletableFuture<>(),
            id -> new FindNodeMessage(id, singletonList(1)),
            new FindNodeResponseHandler(singletonList(1), ALLOW_ALL));
    nodeSessionAt1For2.createNextRequest(request);

    RawPacket firstWhoAreYouRawPacket = outgoing2Packets.poll(1, TimeUnit.SECONDS);
    envelopeAt1From2.put(MASKING_IV, firstWhoAreYouRawPacket.getMaskingIV());
    whoAreYouPacketHandlerNode1.handle(envelopeAt1From2);

    RawPacket heldHandshakeRawPacket = outgoing1Packets.poll(1, TimeUnit.SECONDS);
    assertNotNull(heldHandshakeRawPacket);

    // Step 4: Before the handshake is delivered, Node1 sends a second ordinary packet n2, and
    // Node2 issues a fresh WHOAREYOU c2 for it. With the fix, both c1 and c2 are tracked.
    Bytes12 secondMessageNonce = Bytes12.wrap(Bytes.random(12));
    Bytes16 secondIdNonce = Bytes16.random(rnd);
    WhoAreYouPacket secondWhoAreYouPacket =
        WhoAreYouPacket.create(
            Header.createWhoAreYouHeader(secondMessageNonce, secondIdNonce, UInt64.ZERO));
    nodeSessionAt2For1.sendOutgoingWhoAreYou(secondWhoAreYouPacket);
    // Two challenges are now pending on the responder.
    assertTrue(nodeSessionAt2For1.hasPendingWhoAreYouForNonce(firstMessageNonce));
    assertTrue(nodeSessionAt2For1.hasPendingWhoAreYouForNonce(secondMessageNonce));

    // Step 5: Deliver the held handshake (signed against c1) to Node2.
    HandshakeMessagePacketHandler handshakeMessagePacketHandlerNode2 =
        new HandshakeMessagePacketHandler(
            outgoingPipeline,
            taskScheduler,
            NODE_RECORD_FACTORY_NO_VERIFICATION,
            mock(NodeSessionManager.class),
            ALLOW_ALL);
    Envelope envelopeAt2From1 = new Envelope();
    envelopeAt2From1.put(
        PACKET_HANDSHAKE,
        (HandshakeMessagePacket)
            heldHandshakeRawPacket.demaskPacket(nodePair2.getNodeRecord().getNodeId()));
    envelopeAt2From1.put(SESSION, nodeSessionAt2For1);
    envelopeAt2From1.put(MASKING_IV, heldHandshakeRawPacket.getMaskingIV());
    assertFalse(nodeSessionAt2For1.isAuthenticated());

    handshakeMessagePacketHandlerNode2.handle(envelopeAt2From1);

    // Step 6: Responder must accept the handshake and authenticate the session.
    assertTrue(nodeSessionAt2For1.isAuthenticated());
    assertNotNull(envelopeAt2From1.get(MESSAGE));
    assertNull(envelopeAt2From1.get(BAD_PACKET));
  }

  /**
   * Mirrors geth's TestUDPv5_callResend: the request whose message is embedded in the handshake
   * packet must be marked SENT so that NextTaskHandler does not re-send it as a second ordinary
   * packet after the session becomes authenticated.
   */
  @Test
  public void pendingRequestIsMarkedSentWhenEmbeddedInHandshake() throws Exception {
    NodeInfo nodePair1 = TestUtil.generateUnverifiedNode(30303);
    NodeRecord nodeRecord1 = nodePair1.getNodeRecord();
    Signer signer1 = new DefaultSigner(nodePair1.getSecretKey());
    NodeInfo nodePair2 = TestUtil.generateUnverifiedNode(30304);
    NodeRecord nodeRecord2 = nodePair2.getNodeRecord();
    Signer signer2 = new DefaultSigner(nodePair2.getSecretKey());

    final LocalNodeRecordStore localNodeRecordStoreAt1 =
        new LocalNodeRecordStore(
            nodeRecord1, signer1, NodeRecordListener.NOOP, NewAddressHandler.NOOP);
    KBuckets nodeBucketStorage1 =
        new KBuckets(clock, localNodeRecordStoreAt1, new LivenessChecker(clock));
    KBuckets nodeBucketStorage2 =
        new KBuckets(
            clock,
            new LocalNodeRecordStore(
                nodeRecord2, signer2, NodeRecordListener.NOOP, NewAddressHandler.NOOP),
            new LivenessChecker(clock));

    LinkedBlockingQueue<RawPacket> outgoing1Packets = new LinkedBlockingQueue<>();
    final ExpirationSchedulerFactory expirationSchedulerFactory =
        new ExpirationSchedulerFactory(Executors.newSingleThreadScheduledExecutor());
    final ExpirationScheduler<Bytes> requestExpirationScheduler =
        expirationSchedulerFactory.create(60, TimeUnit.SECONDS);

    NodeSession nodeSessionAt1For2 =
        new NodeSession(
            nodeRecord2.getNodeId(),
            Optional.of(nodeRecord2),
            nodePair2.getNodeRecord().getUdpAddress().orElseThrow(),
            mock(NodeSessionManager.class),
            localNodeRecordStoreAt1,
            signer1,
            nodeBucketStorage1,
            parcel -> outgoing1Packets.add(parcel.getPacket()),
            rnd,
            requestExpirationScheduler);

    LinkedBlockingQueue<RawPacket> outgoing2Packets = new LinkedBlockingQueue<>();
    NodeSession nodeSessionAt2For1 =
        new NodeSession(
            nodeRecord1.getNodeId(),
            Optional.of(nodeRecord1),
            nodeRecord1.getUdpAddress().orElseThrow(),
            mock(NodeSessionManager.class),
            new LocalNodeRecordStore(
                nodeRecord2, signer2, NodeRecordListener.NOOP, NewAddressHandler.NOOP),
            signer2,
            nodeBucketStorage2,
            parcel -> outgoing2Packets.add(parcel.getPacket()),
            rnd,
            requestExpirationScheduler);

    Scheduler taskScheduler = Schedulers.createDefault().events();
    Pipeline outgoingPipeline = new PipelineImpl().build();
    WhoAreYouPacketHandler whoAreYouPacketHandlerNode1 =
        new WhoAreYouPacketHandler(outgoingPipeline, taskScheduler);

    // Register a pending ping request (AWAIT status).
    RequestInfo requestInfo =
        nodeSessionAt1For2.createNextRequest(
            new Request<>(
                new CompletableFuture<>(),
                id -> new PingMessage(id, UInt64.ZERO),
                MultiPacketResponseHandler.SINGLE_PACKET_RESPONSE_HANDLER));

    // Advance session to RANDOM_PACKET_SENT (as NextTaskHandler would do).
    nodeSessionAt1For2.sendOutgoingRandom(Bytes.random(128));
    nodeSessionAt1For2.setState(NodeSession.SessionState.RANDOM_PACKET_SENT);
    Bytes12 randomNonce = nodeSessionAt1For2.getLastOutboundNonce().orElseThrow();
    outgoing1Packets.clear();

    // Build WHOAREYOU for the random packet's nonce and deliver it to WhoAreYouPacketHandler.
    Bytes16 idNonce = Bytes16.random(rnd);
    WhoAreYouPacket whoAreYouPacket =
        WhoAreYouPacket.create(Header.createWhoAreYouHeader(randomNonce, idNonce, UInt64.ZERO));
    nodeSessionAt2For1.sendOutgoingWhoAreYou(whoAreYouPacket);
    RawPacket whoAreYouRaw = outgoing2Packets.poll(1, TimeUnit.SECONDS);
    assertNotNull(whoAreYouRaw);

    Envelope envelope = new Envelope();
    envelope.put(Field.PACKET_WHOAREYOU, whoAreYouPacket);
    envelope.put(Field.SESSION, nodeSessionAt1For2);
    envelope.put(MASKING_IV, whoAreYouRaw.getMaskingIV());
    whoAreYouPacketHandlerNode1.handle(envelope);

    // Handshake must have been emitted with the pending request's message embedded.
    RawPacket handshakeRaw = outgoing1Packets.poll(1, TimeUnit.SECONDS);
    assertNotNull(handshakeRaw, "Expected handshake packet after WHOAREYOU");

    // Embedded request must be marked SENT after the handshake is emitted; otherwise
    // NextTaskHandler would re-send it as a duplicate ordinary packet ~1 s after
    // authentication.
    assertThat(requestInfo.getTaskStatus())
        .as("request embedded in handshake should be SENT, not AWAIT")
        .isEqualTo(TaskStatus.SENT);
  }

  private OrdinaryMessagePacket createPingPacket(
      Bytes16 maskingIV, Bytes12 authTag, NodeSession session, Bytes requestId) {

    PingMessage pingMessage = createPing(session, requestId);
    Header<OrdinaryAuthData> header = Header.createOrdinaryHeader(session.getHomeNodeId(), authTag);
    return OrdinaryMessagePacket.create(maskingIV, header, pingMessage, session.getInitiatorKey());
  }

  private static PingMessage createPing(NodeSession session, Bytes requestId) {
    return new PingMessage(requestId, session.getNodeRecord().orElseThrow().getSeq());
  }
}
