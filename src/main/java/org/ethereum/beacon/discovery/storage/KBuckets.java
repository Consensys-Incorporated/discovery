/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.storage;

import java.time.Clock;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.Function;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.liveness.LivenessChecker;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.util.Functions;

public class KBuckets {
  /**
   * Minimum distance we create a bucket for. 0 is our local node record and negative distances
   * aren't allowed.
   */
  public static final int MINIMUM_BUCKET = 1;

  /** Maximum distance we create a bucket for. This is enough to cover all 32 byte node IDs. */
  public static final int MAXIMUM_BUCKET = 256;

  private final LocalNodeRecordStore localNodeRecordStore;
  private final Bytes homeNodeId;
  private final LivenessChecker livenessChecker;
  private final Map<Integer, KBucket> buckets = new HashMap<>();
  private final Clock clock;

  public KBuckets(
      final Clock clock,
      final LocalNodeRecordStore localNodeRecordStore,
      final LivenessChecker livenessChecker) {
    this.clock = clock;
    this.localNodeRecordStore = localNodeRecordStore;
    this.homeNodeId = localNodeRecordStore.getLocalNodeRecord().getNodeId();
    this.livenessChecker = livenessChecker;
  }

  public synchronized Stream<NodeRecord> getLiveNodeRecords(int distance) {
    if (distance == 0) {
      return Stream.of(localNodeRecordStore.getLocalNodeRecord());
    }
    return streamFromBucket(distance, bucket -> bucket.getLiveNodes().stream());
  }

  public synchronized Stream<NodeRecord> getAllNodeRecords(int distance) {
    if (distance == 0) {
      return Stream.of(localNodeRecordStore.getLocalNodeRecord());
    }
    return streamFromBucket(distance, bucket -> bucket.getAllNodes().stream());
  }

  /**
   * Extracts a {@link Stream} from a {@link KBucket} at a given distance, ensuring that all
   * accesses to the KBucket are completed prior to the method returning.
   *
   * <p>Specifically this method avoids using {@code getBucket(distance).stream().flatMap(mapper)}
   * as the mapper is then called after the method returns. That leads to thread safety issues.
   *
   * @param distance the bucket distance
   * @param mapper the function to convert the KBucket to a Stream of objects
   * @param <T> the type of object in the returned Stream
   * @return the result of applying mapper to the bucket at the requested distance, or an empty
   *     stream if there is no bucket at that distance.
   */
  private <T> Stream<T> streamFromBucket(int distance, final Function<KBucket, Stream<T>> mapper) {
    final Optional<KBucket> bucket = getBucket(distance);
    if (bucket.isPresent()) {
      return mapper.apply(bucket.get());
    } else {
      return Stream.empty();
    }
  }

  public Stream<NodeRecord> streamClosestNodes(Bytes nodeId) {
    return StreamSupport.stream(
        Spliterators.spliteratorUnknownSize(
            new KBucketsIterator(this, homeNodeId, nodeId), Spliterator.ORDERED),
        false);
  }

  private Optional<KBucket> getBucket(final int distance) {
    return Optional.ofNullable(buckets.get(distance));
  }

  public synchronized void offer(NodeRecord node) {
    final int distance = Functions.logDistance(homeNodeId, node.getNodeId());
    if (distance > MAXIMUM_BUCKET) {
      // Distance too great, ignore.
      return;
    }
    getOrCreateBucket(distance).ifPresent(bucket -> bucket.offer(node));
  }

  public synchronized BucketStats getStats() {
    final BucketStats stats = new BucketStats();
    buckets.forEach((distance, bucket) -> bucket.updateStats(distance, stats));
    return stats;
  }

  /**
   * Called when we have confirmed the liveness of a node by sending it a request and receiving a
   * valid response back. Must only be called for requests we initiate, not incoming requests from
   * the peer.
   *
   * @param node the node for which liveness was confirmed.
   */
  public synchronized void onNodeContacted(NodeRecord node) {
    final int distance = Functions.logDistance(homeNodeId, node.getNodeId());
    getOrCreateBucket(distance).ifPresent(bucket -> bucket.onLivenessConfirmed(node));
  }

  /** Performs maintenance on the least recently touch bucket (excluding any empty buckets). */
  public synchronized void performMaintenance() {
    buckets.values().stream()
        .filter(bucket -> !bucket.isEmpty())
        .min(Comparator.comparingLong(KBucket::getLastMaintenanceTime))
        .ifPresent(KBucket::performMaintenance);
  }

  private Optional<KBucket> getOrCreateBucket(final int distance) {
    if (distance > MAXIMUM_BUCKET || distance < MINIMUM_BUCKET) {
      // Distance too great, ignore.
      return Optional.empty();
    }
    return Optional.of(
        buckets.computeIfAbsent(distance, __ -> new KBucket(livenessChecker, clock)));
  }

  public synchronized Optional<NodeRecord> getNode(final Bytes nodeId) {
    return getBucket(Functions.logDistance(homeNodeId, nodeId))
        .flatMap(bucket -> bucket.getNode(nodeId));
  }

  public synchronized boolean containsNode(final Bytes nodeId) {
    return getNode(nodeId).isPresent();
  }

  public synchronized List<List<NodeRecord>> getNodeRecordBuckets() {
    return buckets.values().stream().map(KBucket::getAllNodes).toList();
  }

  public synchronized void deleteNode(final Bytes nodeId) {
    final int distance = Functions.logDistance(homeNodeId, nodeId);
    if (distance <= MAXIMUM_BUCKET) {
      getBucket(distance).ifPresent((bucket) -> bucket.deleteNode(nodeId));
    }
  }
}
