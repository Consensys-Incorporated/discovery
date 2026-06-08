/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.schema;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.units.bigints.UInt64;
import org.ethereum.beacon.discovery.SimpleIdentitySchemaInterpreter;
import org.ethereum.beacon.discovery.crypto.DefaultSigner;
import org.ethereum.beacon.discovery.crypto.Signer;
import org.ethereum.beacon.discovery.message.V5Message;
import org.ethereum.beacon.discovery.network.NetworkParcel;
import org.ethereum.beacon.discovery.network.NetworkParcelV5;
import org.ethereum.beacon.discovery.packet.Header;
import org.ethereum.beacon.discovery.packet.WhoAreYouPacket;
import org.ethereum.beacon.discovery.packet.WhoAreYouPacket.WhoAreYouAuthData;
import org.ethereum.beacon.discovery.pipeline.handler.NodeSessionManager;
import org.ethereum.beacon.discovery.pipeline.info.Request;
import org.ethereum.beacon.discovery.pipeline.info.RequestInfo;
import org.ethereum.beacon.discovery.scheduler.ExpirationScheduler;
import org.ethereum.beacon.discovery.schema.NodeSession.SessionState;
import org.ethereum.beacon.discovery.storage.KBuckets;
import org.ethereum.beacon.discovery.storage.LocalNodeRecordStore;
import org.ethereum.beacon.discovery.storage.NewAddressHandler;
import org.ethereum.beacon.discovery.storage.NodeRecordListener;
import org.ethereum.beacon.discovery.type.Bytes12;
import org.ethereum.beacon.discovery.type.Bytes16;
import org.ethereum.beacon.discovery.util.Functions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;
import org.mockito.ArgumentCaptor;

public class NodeSessionTest {
  private static final Signer SIGNER = new DefaultSigner(Functions.randomKeyPair().secretKey());
  private final NodeSessionManager nodeSessionManager = mock(NodeSessionManager.class);
  private final Bytes32 nodeId = Bytes32.ZERO;

  @SuppressWarnings("unchecked")
  private final Consumer<NetworkParcel> outgoingPipeline = mock(Consumer.class);

  @SuppressWarnings("unchecked")
  private final ExpirationScheduler<Bytes> expirationScheduler = mock(ExpirationScheduler.class);

  private final KBuckets kBuckets = mock(KBuckets.class);
  private final LocalNodeRecordStore localNodeRecordStore =
      new LocalNodeRecordStore(
          SimpleIdentitySchemaInterpreter.createNodeRecord(Bytes32.fromHexString("0x123456")),
          SIGNER,
          mock(NodeRecordListener.class),
          mock(NewAddressHandler.class));

  private final NodeSession session =
      new NodeSession(
          nodeId,
          Optional.empty(),
          InetSocketAddress.createUnresolved("127.0.0.1", 2999),
          nodeSessionManager,
          localNodeRecordStore,
          SIGNER,
          kBuckets,
          outgoingPipeline,
          new Random(1342),
          expirationScheduler);

  @Test
  void onNodeRecordReceived_shouldUpdateRecordWhenNoPreviousValue() {
    final NodeRecord nodeRecord =
        SimpleIdentitySchemaInterpreter.createNodeRecord(
            nodeId, new InetSocketAddress("127.0.0.1", 2));
    session.onNodeRecordReceived(nodeRecord);
    assertThat(session.getNodeRecord()).contains(nodeRecord);
  }

  @Test
  void onNodeRecordReceived_shouldUpdateRecordWhenSeqNumHigher() {
    final NodeRecord nodeRecord =
        SimpleIdentitySchemaInterpreter.createNodeRecord(
            nodeId, new InetSocketAddress("127.0.0.1", 2));
    session.onNodeRecordReceived(nodeRecord);
    assertThat(session.getNodeRecord()).contains(nodeRecord);

    final NodeRecord updatedRecord =
        nodeRecord.withUpdatedCustomField("eth2", Bytes.fromHexString("0x12"), SIGNER);
    session.onNodeRecordReceived(updatedRecord);
    assertThat(session.getNodeRecord()).contains(updatedRecord);
  }

  @Test
  void onNodeRecordReceived_shouldNotUpdateRecordWhenSeqNumLower() {
    final NodeRecord nodeRecord =
        SimpleIdentitySchemaInterpreter.createNodeRecord(
            nodeId, new InetSocketAddress("127.0.0.1", 2));

    final NodeRecord updatedRecord =
        nodeRecord.withUpdatedCustomField("eth2", Bytes.fromHexString("0x12"), SIGNER);
    session.onNodeRecordReceived(updatedRecord);
    assertThat(session.getNodeRecord()).contains(updatedRecord);

    session.onNodeRecordReceived(nodeRecord);
    assertThat(session.getNodeRecord()).contains(updatedRecord);
  }

  @Test
  void onNodeRecordReceived_shouldNotUpdateRecordWhenSeqNumEqual() {
    final NodeRecord nodeRecord =
        SimpleIdentitySchemaInterpreter.createNodeRecord(
            nodeId, new InetSocketAddress("127.0.0.1", 2));

    final NodeRecord updatedRecord1a =
        nodeRecord.withUpdatedCustomField("eth2", Bytes.fromHexString("0x12"), SIGNER);
    session.onNodeRecordReceived(updatedRecord1a);
    assertThat(session.getNodeRecord()).contains(updatedRecord1a);

    final NodeRecord updatedRecord1b =
        nodeRecord.withUpdatedCustomField("eth2", Bytes.fromHexString("0x9999"), SIGNER);
    session.onNodeRecordReceived(updatedRecord1b);
    assertThat(session.getNodeRecord()).contains(updatedRecord1a);
  }

  @ParameterizedTest
  @EnumSource(
      value = SessionState.class,
      names = {"WHOAREYOU_SENT", "RANDOM_PACKET_SENT"},
      mode = Mode.INCLUDE)
  void createNextRequest_shouldResetPartialHandshakeStatesWhenRequestTimesOut(
      final SessionState state) {
    final Request<?> request = createRequestMock();
    final RequestInfo requestInfo = session.createNextRequest(request);

    final ArgumentCaptor<Runnable> timeoutHandlerCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(expirationScheduler).put(eq(requestInfo.getRequestId()), timeoutHandlerCaptor.capture());

    final Runnable timeoutHandler = timeoutHandlerCaptor.getValue();
    session.setState(state);

    timeoutHandler.run();
    assertThat(session.getState()).isEqualTo(SessionState.INITIAL);
  }

  @Test
  void cancelAllRequests_shouldContinueIfNotFound() {
    final Bytes msgId = Bytes.random(2);
    final Map<Bytes, RequestInfo> requestIdStatuses = spy(new HashMap<>());
    doReturn(Set.of(msgId)).when(requestIdStatuses).keySet();

    final NodeSession mySession =
        new NodeSession(
            nodeId,
            Optional.empty(),
            InetSocketAddress.createUnresolved("127.0.0.1", 2999),
            nodeSessionManager,
            localNodeRecordStore,
            SIGNER,
            kBuckets,
            outgoingPipeline,
            new Random(1342),
            expirationScheduler,
            requestIdStatuses);
    mySession.cancelAllRequests("BAD PANDA");
  }

  @Test
  void createNextRequest_shouldNotResetAuthenticatedStatesWhenRequestTimesOut() {
    final Request<?> request = createRequestMock();
    final RequestInfo requestInfo = session.createNextRequest(request);

    final ArgumentCaptor<Runnable> timeoutHandlerCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(expirationScheduler).put(eq(requestInfo.getRequestId()), timeoutHandlerCaptor.capture());

    final Runnable timeoutHandler = timeoutHandlerCaptor.getValue();
    session.setState(SessionState.AUTHENTICATED);

    timeoutHandler.run();
    assertThat(session.getState()).isEqualTo(SessionState.AUTHENTICATED);
  }

  @Test
  void resendOutgoingWhoAreYouFor_shouldSendPacketWhenPendingPacketExists() {
    final Bytes12 nonce = Bytes12.wrap(Bytes.random(12));
    session.sendOutgoingWhoAreYou(createWhoAreYouPacket(nonce));

    final ArgumentCaptor<NetworkParcelV5> firstCaptor =
        ArgumentCaptor.forClass(NetworkParcelV5.class);
    verify(outgoingPipeline).accept(firstCaptor.capture());

    session.resendOutgoingWhoAreYouFor(nonce);

    final ArgumentCaptor<NetworkParcelV5> secondCaptor =
        ArgumentCaptor.forClass(NetworkParcelV5.class);
    verify(outgoingPipeline, times(2)).accept(secondCaptor.capture());
    // A packet must actually be sent on resend.
    assertThat(secondCaptor.getAllValues()).hasSize(2);
  }

  @Test
  void resendOutgoingWhoAreYouFor_shouldDoNothingWhenNoPendingPacket() {
    session.resendOutgoingWhoAreYouFor(Bytes12.wrap(Bytes.random(12)));

    verify(outgoingPipeline, never()).accept(any());
  }

  @Test
  void resendOutgoingWhoAreYouFor_shouldDoNothingForUnknownNonce() {
    final Bytes12 storedNonce = Bytes12.wrap(Bytes.random(12));
    session.sendOutgoingWhoAreYou(createWhoAreYouPacket(storedNonce));
    verify(outgoingPipeline, times(1)).accept(any());

    session.resendOutgoingWhoAreYouFor(Bytes12.wrap(Bytes.random(12)));

    verify(outgoingPipeline, times(1)).accept(any());
  }

  @Test
  void resendOutgoingWhoAreYouFor_shouldDoNothingAfterHandshakeStateReset() {
    final Request<?> request = createRequestMock();
    final RequestInfo requestInfo = session.createNextRequest(request);

    final ArgumentCaptor<Runnable> timeoutHandlerCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(expirationScheduler).put(eq(requestInfo.getRequestId()), timeoutHandlerCaptor.capture());

    final Bytes12 nonce = Bytes12.wrap(Bytes.random(12));
    session.sendOutgoingWhoAreYou(createWhoAreYouPacket(nonce));
    session.setState(SessionState.WHOAREYOU_SENT);

    // Simulate request timeout which resets the handshake state.
    timeoutHandlerCaptor.getValue().run();
    assertThat(session.getState()).isEqualTo(SessionState.INITIAL);

    session.resendOutgoingWhoAreYouFor(nonce);

    // sendOutgoingWhoAreYou was called once above; resend should not add another send.
    verify(outgoingPipeline, times(1)).accept(any());
  }

  @Test
  void resendOutgoingWhoAreYouFor_shouldPreserveOriginalChallenge() {
    final Bytes12 originalNonce = Bytes12.wrap(Bytes.random(12));
    session.sendOutgoingWhoAreYou(createWhoAreYouPacket(originalNonce));

    final Bytes challengeAfterSend = singleChallenge();

    session.resendOutgoingWhoAreYouFor(originalNonce);

    // Challenge must be unchanged after resend so a handshake signed against the original
    // challenge remains valid.
    assertThat(singleChallenge()).isEqualTo(challengeAfterSend);
  }

  @Test
  void sendOutgoingWhoAreYou_shouldStoreMultiplePendingChallengesWithoutOverwriting() {
    final Bytes12 nonce1 = Bytes12.wrap(Bytes.random(12));
    final Bytes12 nonce2 = Bytes12.wrap(Bytes.random(12));

    session.sendOutgoingWhoAreYou(createWhoAreYouPacket(nonce1));
    final Bytes challenge1 = singleChallenge();

    session.sendOutgoingWhoAreYou(createWhoAreYouPacket(nonce2));

    assertThat(session.hasPendingWhoAreYouForNonce(nonce1)).isTrue();
    assertThat(session.hasPendingWhoAreYouForNonce(nonce2)).isTrue();
    assertThat(session.getPendingWhoAreYouChallenges()).hasSize(2).contains(challenge1);
  }

  @Test
  void pendingWhoAreYou_shouldBeBoundedAndEvictOldestEntry() {
    final Bytes12[] nonces = new Bytes12[NodeSession.MAX_PENDING_WHOAREYOU + 1];
    for (int i = 0; i < nonces.length; i++) {
      nonces[i] = Bytes12.wrap(Bytes.random(12));
      session.sendOutgoingWhoAreYou(createWhoAreYouPacket(nonces[i]));
    }

    // The oldest entry must have been evicted to keep the map bounded.
    assertThat(session.hasPendingWhoAreYouForNonce(nonces[0])).isFalse();
    for (int i = 1; i < nonces.length; i++) {
      assertThat(session.hasPendingWhoAreYouForNonce(nonces[i])).isTrue();
    }
    assertThat(session.getPendingWhoAreYouChallenges()).hasSize(NodeSession.MAX_PENDING_WHOAREYOU);
  }

  @Test
  void pendingWhoAreYou_shouldEvictLeastRecentlyAccessedEntry() {
    // Fill the cache to capacity.
    final Bytes12[] nonces = new Bytes12[NodeSession.MAX_PENDING_WHOAREYOU];
    for (int i = 0; i < nonces.length; i++) {
      nonces[i] = Bytes12.wrap(Bytes.random(12));
      session.sendOutgoingWhoAreYou(createWhoAreYouPacket(nonces[i]));
    }

    // Touch the eldest entry via a resend so it becomes most-recently-used.
    session.resendOutgoingWhoAreYouFor(nonces[0]);

    // Inserting one more must evict the now-eldest (nonces[1]), not nonces[0].
    final Bytes12 newNonce = Bytes12.wrap(Bytes.random(12));
    session.sendOutgoingWhoAreYou(createWhoAreYouPacket(newNonce));

    assertThat(session.hasPendingWhoAreYouForNonce(nonces[0])).isTrue();
    assertThat(session.hasPendingWhoAreYouForNonce(nonces[1])).isFalse();
    for (int i = 2; i < nonces.length; i++) {
      assertThat(session.hasPendingWhoAreYouForNonce(nonces[i])).isTrue();
    }
    assertThat(session.hasPendingWhoAreYouForNonce(newNonce)).isTrue();
  }

  @Test
  void clearPendingWhoAreYouChallenges_shouldClearAllPending() {
    final Bytes12 nonce1 = Bytes12.wrap(Bytes.random(12));
    final Bytes12 nonce2 = Bytes12.wrap(Bytes.random(12));
    session.sendOutgoingWhoAreYou(createWhoAreYouPacket(nonce1));
    session.sendOutgoingWhoAreYou(createWhoAreYouPacket(nonce2));
    assertThat(session.getPendingWhoAreYouChallenges()).hasSize(2);

    session.clearPendingWhoAreYouChallenges();

    assertThat(session.getPendingWhoAreYouChallenges()).isEmpty();
    assertThat(session.hasPendingWhoAreYouForNonce(nonce1)).isFalse();
    assertThat(session.hasPendingWhoAreYouForNonce(nonce2)).isFalse();
  }

  @Test
  void resetHandshakeState_shouldClearAllPendingChallenges() {
    final Request<?> request = createRequestMock();
    final RequestInfo requestInfo = session.createNextRequest(request);
    final ArgumentCaptor<Runnable> timeoutHandlerCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(expirationScheduler).put(eq(requestInfo.getRequestId()), timeoutHandlerCaptor.capture());

    final Bytes12 nonce1 = Bytes12.wrap(Bytes.random(12));
    final Bytes12 nonce2 = Bytes12.wrap(Bytes.random(12));
    session.sendOutgoingWhoAreYou(createWhoAreYouPacket(nonce1));
    session.sendOutgoingWhoAreYou(createWhoAreYouPacket(nonce2));
    session.setState(SessionState.WHOAREYOU_SENT);

    timeoutHandlerCaptor.getValue().run();

    assertThat(session.getState()).isEqualTo(SessionState.INITIAL);
    assertThat(session.getPendingWhoAreYouChallenges()).isEmpty();
  }

  @Test
  void generateNonce_shouldAddToRecentOutboundWindow() {
    final Bytes12 nonce = session.generateNonce();
    assertThat(session.hasRecentOutboundNonce(nonce)).isTrue();
  }

  @Test
  void generateNonce_shouldEvictOldestNonceWhenWindowFull() {
    final Bytes12[] nonces = new Bytes12[NodeSession.MAX_RECENT_OUTBOUND_NONCES + 1];
    for (int i = 0; i < nonces.length; i++) {
      nonces[i] = session.generateNonce();
    }

    assertThat(session.hasRecentOutboundNonce(nonces[0])).isFalse();
    for (int i = 1; i < nonces.length; i++) {
      assertThat(session.hasRecentOutboundNonce(nonces[i])).isTrue();
    }
  }

  @Test
  void generateNonce_shouldNotifyManagerWithEvictedNonceWhenWindowOverflows() {
    final Bytes12 firstNonce = session.generateNonce();
    for (int i = 1; i < NodeSession.MAX_RECENT_OUTBOUND_NONCES; i++) {
      session.generateNonce();
    }
    // firstNonce is now the eldest in the full window; one more call evicts it.
    session.generateNonce();
    verify(nodeSessionManager)
        .onSessionLastNonceUpdate(eq(session), eq(Optional.of(firstNonce)), any());
  }

  @Test
  void generateHandshakeNonce_shouldNotAddToRecentOutboundWindow() {
    final Bytes12 nonce = session.generateHandshakeNonce();
    assertThat(session.hasRecentOutboundNonce(nonce)).isFalse();
  }

  @Test
  void resetHandshakeState_shouldClearNoncesAndNotifyManager() {
    final Request<?> request = createRequestMock();
    final RequestInfo requestInfo = session.createNextRequest(request);
    final ArgumentCaptor<Runnable> timeoutHandlerCaptor = ArgumentCaptor.forClass(Runnable.class);
    verify(expirationScheduler).put(eq(requestInfo.getRequestId()), timeoutHandlerCaptor.capture());

    final Bytes12 nonce = session.generateNonce();
    session.setState(SessionState.RANDOM_PACKET_SENT);
    assertThat(session.hasRecentOutboundNonce(nonce)).isTrue();

    timeoutHandlerCaptor.getValue().run();

    assertThat(session.getState()).isEqualTo(SessionState.INITIAL);
    assertThat(session.hasRecentOutboundNonce(nonce)).isFalse();

    verify(nodeSessionManager).removeNoncesForSession(eq(session), argThat(c -> c.contains(nonce)));
  }

  private Bytes singleChallenge() {
    return session.getPendingWhoAreYouChallenges().iterator().next();
  }

  private static WhoAreYouPacket createWhoAreYouPacket(final Bytes12 nonce) {
    final Bytes16 idNonce = Bytes16.wrap(Bytes.random(16));
    final Header<WhoAreYouAuthData> header =
        Header.createWhoAreYouHeader(nonce, idNonce, UInt64.ZERO);
    return WhoAreYouPacket.create(header);
  }

  private Request<?> createRequestMock() {
    final Request<?> request = mock(Request.class);
    when(request.getResultPromise()).thenReturn(new CompletableFuture<>());
    // avoid failing when logging is on
    when(request.getRequestMessageFactory())
        .thenReturn(
            bytes -> {
              final V5Message mock = mock(V5Message.class);
              when(mock.toString()).thenReturn("");
              return mock;
            });

    return request;
  }
}
