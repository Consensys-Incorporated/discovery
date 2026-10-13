/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import org.apache.tuweni.bytes.Bytes32;
import org.ethereum.beacon.discovery.crypto.DefaultSigner;
import org.ethereum.beacon.discovery.scheduler.ExpirationSchedulerFactory;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordBuilder;
import org.ethereum.beacon.discovery.storage.KBuckets;
import org.ethereum.beacon.discovery.task.DiscoveryTaskManager;
import org.ethereum.beacon.discovery.util.Functions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DiscoverySystemImplTest {
  private final DiscoveryManager discoveryManager = mock(DiscoveryManager.class);
  private final KBuckets buckets = mock(KBuckets.class);
  private final DefaultSigner signer = new DefaultSigner(Functions.randomKeyPair().secretKey());
  private final DiscoverySystemImpl discoverySystem =
      new DiscoverySystemImpl(
          discoveryManager,
          mock(DiscoveryTaskManager.class),
          mock(ExpirationSchedulerFactory.class),
          buckets,
          List.of());

  @Test
  void streamLiveNodesShouldReturnEmptyWhenBothSourcesAreEmpty() {
    setRecords(List.of(), List.of());

    assertThat(discoverySystem.streamLiveNodes()).isEmpty();
  }

  @Test
  void streamLiveNodesShouldKeepNewerSessionRecord() {
    final NodeRecord bucketRecord = createRecord(1, 9000);
    final NodeRecord sessionRecord = createRecord(2, 9001);
    setRecords(List.of(bucketRecord), List.of(sessionRecord));

    assertThat(discoverySystem.streamLiveNodes()).containsExactly(sessionRecord);
  }

  @Test
  void streamLiveNodesShouldKeepNewerBucketRecord() {
    final NodeRecord bucketRecord = createRecord(2, 9000);
    final NodeRecord sessionRecord = createRecord(1, 9001);
    setRecords(List.of(bucketRecord), List.of(sessionRecord));

    assertThat(discoverySystem.streamLiveNodes()).containsExactly(bucketRecord);
  }

  @Test
  void streamLiveNodesShouldPreferBucketRecordWhenSequencesAreEqual() {
    final NodeRecord bucketRecord = createRecord(2, 9000);
    final NodeRecord sessionRecord = createRecord(2, 9001);
    setRecords(List.of(bucketRecord), List.of(sessionRecord));

    assertThat(discoverySystem.streamLiveNodes()).containsExactly(bucketRecord);
  }

  @Test
  void streamLiveNodesShouldDeduplicateIdenticalRecords() {
    final NodeRecord record = createRecord(1, 9000);
    setRecords(List.of(record), List.of(record));

    assertThat(discoverySystem.streamLiveNodes()).containsExactly(record);
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void streamLiveNodesShouldKeepNewestSessionOnlyRecordRegardlessOfOrder(
      final boolean newestFirst) {
    final NodeRecord oldRecord = createRecord(1, 9000);
    final NodeRecord newRecord = createRecord(2, 9001);
    setRecords(
        List.of(), newestFirst ? List.of(newRecord, oldRecord) : List.of(oldRecord, newRecord));

    assertThat(discoverySystem.streamLiveNodes()).containsExactly(newRecord);
  }

  @Test
  void streamLiveNodesShouldRetainBucketOnlyAndSessionOnlyNodes() {
    final NodeRecord bucketRecord = createRecord(1, 9000);
    final NodeRecord sessionRecord = TestUtil.generateNode(9001).getNodeRecord();
    setRecords(List.of(bucketRecord), List.of(sessionRecord));

    assertThat(discoverySystem.streamLiveNodes()).containsExactly(bucketRecord, sessionRecord);
  }

  @Test
  void streamLiveNodesShouldPreserveFirstSeenIdentityOrderWhenReplacingRecord() {
    final NodeRecord oldRecord = createRecord(1, 9000);
    final NodeRecord newRecord = createRecord(2, 9001);
    final NodeRecord bucketOnly = TestUtil.generateNode(9002).getNodeRecord();
    final NodeRecord sessionOnly = TestUtil.generateNode(9003).getNodeRecord();
    setRecords(List.of(oldRecord, bucketOnly), List.of(sessionOnly, newRecord));

    assertThat(discoverySystem.streamLiveNodes())
        .containsExactly(newRecord, bucketOnly, sessionOnly);
  }

  private NodeRecord createRecord(final int sequence, final int port) {
    return new NodeRecordBuilder().seq(sequence).signer(signer).address("127.0.0.1", port).build();
  }

  private void setRecords(
      final List<NodeRecord> bucketRecords, final List<NodeRecord> sessionRecords) {
    when(buckets.streamClosestNodes(Bytes32.ZERO)).thenAnswer(__ -> bucketRecords.stream());
    when(discoveryManager.streamActiveSessions()).thenAnswer(__ -> sessionRecords.stream());
  }
}
