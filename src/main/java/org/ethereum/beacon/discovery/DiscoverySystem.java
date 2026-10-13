/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;
import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.storage.BucketStats;

public interface DiscoverySystem {
  CompletableFuture<Void> start();

  void stop();

  NodeRecord getLocalNodeRecord();

  BucketStats getBucketStats();

  void updateCustomFieldValue(final String fieldName, final Bytes value);

  /**
   * Initiates FINDNODE with node `nodeRecord`
   *
   * @param nodeRecord Ethereum Node record
   * @param distances Distances to search for
   * @return Future which is fired when reply is received or fails in timeout/not successful
   *     handshake/bad message exchange. Contains the collection of nodes returned by the peer.
   */
  CompletableFuture<Collection<NodeRecord>> findNodes(
      NodeRecord nodeRecord, List<Integer> distances);

  /**
   * Initiates PING with node `nodeRecord`
   *
   * @param nodeRecord Ethereum Node record
   * @return Future which is fired when reply is received or fails in timeout/not successful
   *     handshake/bad message exchange.
   */
  CompletableFuture<Void> ping(NodeRecord nodeRecord);

  /**
   * Initiates TALK with node `nodeRecord`
   *
   * @param nodeRecord Ethereum Node record
   * @return Promise of the node TALK response.
   */
  CompletableFuture<Bytes> talk(NodeRecord nodeRecord, Bytes protocol, Bytes request);

  /**
   * Returns live routing-table and authenticated-session records, with one record per node ID. The
   * highest sequence number wins; routing-table records take precedence on equal sequences.
   *
   * <p>Both sources are fully traversed and the selected records are buffered before this method
   * returns. Short-circuiting operations on the returned stream, such as {@code findFirst()} or
   * {@code limit(n)}, do not reduce this traversal cost. Buffer storage is proportional to the
   * number of unique node IDs observed.
   *
   * <p>The traversal is not an atomic snapshot of both sources. Concurrent updates may occur, so
   * the highest sequence number is selected among the records observed during traversal.
   *
   * @return the live node records
   */
  Stream<NodeRecord> streamLiveNodes();

  CompletableFuture<Collection<NodeRecord>> searchForNewPeers();

  /**
   * Lookup node in locally stored KBuckets by its nodeId. Allows lookup of local node record.
   *
   * @param nodeId NodeId, big endian UInt256 Node ID in bytes
   * @return NodeRecord if any found
   */
  Optional<NodeRecord> lookupNode(final Bytes nodeId);
}
