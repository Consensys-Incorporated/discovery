/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery;

import static org.ethereum.beacon.discovery.util.Utils.RECOVERABLE_ERRORS_PREDICATE;

import com.google.common.annotations.VisibleForTesting;
import io.netty.channel.socket.nio.NioDatagramChannel;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.crypto.Signer;
import org.ethereum.beacon.discovery.message.FindNodeMessage;
import org.ethereum.beacon.discovery.message.PingMessage;
import org.ethereum.beacon.discovery.message.TalkReqMessage;
import org.ethereum.beacon.discovery.message.handler.ExternalAddressSelector;
import org.ethereum.beacon.discovery.network.DiscoveryClient;
import org.ethereum.beacon.discovery.network.NettyDiscoveryClientImpl;
import org.ethereum.beacon.discovery.network.NettyDiscoveryServer;
import org.ethereum.beacon.discovery.network.NetworkParcel;
import org.ethereum.beacon.discovery.pipeline.Envelope;
import org.ethereum.beacon.discovery.pipeline.Field;
import org.ethereum.beacon.discovery.pipeline.Pipeline;
import org.ethereum.beacon.discovery.pipeline.PipelineImpl;
import org.ethereum.beacon.discovery.pipeline.handler.BadPacketHandler;
import org.ethereum.beacon.discovery.pipeline.handler.HandshakeMessagePacketHandler;
import org.ethereum.beacon.discovery.pipeline.handler.IncomingDataPacker;
import org.ethereum.beacon.discovery.pipeline.handler.MessageHandler;
import org.ethereum.beacon.discovery.pipeline.handler.MessagePacketHandler;
import org.ethereum.beacon.discovery.pipeline.handler.NewTaskHandler;
import org.ethereum.beacon.discovery.pipeline.handler.NextTaskHandler;
import org.ethereum.beacon.discovery.pipeline.handler.NodeSessionManager;
import org.ethereum.beacon.discovery.pipeline.handler.NodeSessionRequestHandler;
import org.ethereum.beacon.discovery.pipeline.handler.OutgoingParcelHandler;
import org.ethereum.beacon.discovery.pipeline.handler.PacketDispatcherHandler;
import org.ethereum.beacon.discovery.pipeline.handler.PacketSourceFilter;
import org.ethereum.beacon.discovery.pipeline.handler.UnauthorizedMessagePacketHandler;
import org.ethereum.beacon.discovery.pipeline.handler.UnknownPacketTagToSender;
import org.ethereum.beacon.discovery.pipeline.handler.WhoAreYouPacketHandler;
import org.ethereum.beacon.discovery.pipeline.handler.WhoAreYouSessionResolver;
import org.ethereum.beacon.discovery.pipeline.info.FindNodeResponseHandler;
import org.ethereum.beacon.discovery.pipeline.info.MultiPacketResponseHandler;
import org.ethereum.beacon.discovery.pipeline.info.Request;
import org.ethereum.beacon.discovery.scheduler.ExpirationSchedulerFactory;
import org.ethereum.beacon.discovery.scheduler.Scheduler;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;
import org.ethereum.beacon.discovery.schema.NodeSession;
import org.ethereum.beacon.discovery.storage.KBuckets;
import org.ethereum.beacon.discovery.storage.LocalNodeRecordStore;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

public class DiscoveryManagerImpl implements DiscoveryManager {
  private static final Logger LOG = LogManager.getLogger();

  private final Sinks.Many<NetworkParcel> outgoingMessages = Sinks.many().replay().latest();
  private final List<NettyDiscoveryServer> discoveryServers;
  private final Pipeline incomingPipeline = new PipelineImpl();
  private final Pipeline outgoingPipeline = new PipelineImpl();
  private final LocalNodeRecordStore localNodeRecordStore;
  private final AddressAccessPolicy addressAccessPolicy;
  private volatile DiscoveryClient discoveryClient;
  private final NodeSessionManager nodeSessionManager;

  public DiscoveryManagerImpl(
      final List<NettyDiscoveryServer> discoveryServers,
      final KBuckets nodeBucketStorage,
      final LocalNodeRecordStore localNodeRecordStore,
      final Signer signer,
      final NodeRecordFactory nodeRecordFactory,
      final Scheduler taskScheduler,
      final ExpirationSchedulerFactory expirationSchedulerFactory,
      final TalkHandler talkHandler,
      final ExternalAddressSelector externalAddressSelector,
      final AddressAccessPolicy addressAccessPolicy) {
    this.localNodeRecordStore = localNodeRecordStore;
    this.addressAccessPolicy = addressAccessPolicy;
    final NodeRecord homeNodeRecord = localNodeRecordStore.getLocalNodeRecord();

    this.discoveryServers = discoveryServers;
    // Detect whether any of the bound discovery servers is listening on IPv6. The session manager
    // uses this to allow IPv6 outbound dialing when the home record has not (yet) advertised IPv6
    // — required for IPv6 external-address auto-discovery to bootstrap.
    final boolean ipv6BindAvailable =
        discoveryServers.stream()
            .map(NettyDiscoveryServer::getListenAddress)
            .map(InetSocketAddress::getAddress)
            .anyMatch(addr -> addr instanceof Inet6Address);
    nodeSessionManager =
        new NodeSessionManager(
            localNodeRecordStore,
            signer,
            nodeBucketStorage,
            outgoingPipeline,
            expirationSchedulerFactory,
            ipv6BindAvailable);
    incomingPipeline
        .addHandler(new PacketSourceFilter(addressAccessPolicy))
        .addHandler(new IncomingDataPacker(homeNodeRecord.getNodeId()))
        .addHandler(new WhoAreYouSessionResolver(nodeSessionManager))
        .addHandler(new UnknownPacketTagToSender())
        .addHandler(nodeSessionManager)
        .addHandler(new PacketDispatcherHandler())
        .addHandler(new WhoAreYouPacketHandler(outgoingPipeline, taskScheduler))
        .addHandler(
            new HandshakeMessagePacketHandler(
                outgoingPipeline,
                taskScheduler,
                nodeRecordFactory,
                nodeSessionManager,
                addressAccessPolicy))
        .addHandler(new MessagePacketHandler(nodeRecordFactory))
        .addHandler(new UnauthorizedMessagePacketHandler())
        .addHandler(
            new MessageHandler(
                localNodeRecordStore,
                talkHandler,
                this::requestUpdatedEnr,
                externalAddressSelector))
        .addHandler(new BadPacketHandler());
    outgoingPipeline
        .addHandler(new OutgoingParcelHandler(outgoingMessages, addressAccessPolicy))
        .addHandler(new NodeSessionRequestHandler())
        .addHandler(nodeSessionManager)
        .addHandler(new NewTaskHandler())
        .addHandler(new NextTaskHandler(outgoingPipeline, taskScheduler));
  }

  private void requestUpdatedEnr(final NodeRecord record) {
    findNodes(record, List.of(0))
        .exceptionally(
            error -> {
              LOG.debug("Failed to request updated enr from {}", record, error);
              return null;
            });
  }

  @Override
  public CompletableFuture<Void> start() {
    incomingPipeline.build();
    outgoingPipeline.build();
    discoveryServers.forEach(
        discoveryServer ->
            Flux.from(discoveryServer.getIncomingPackets())
                .doOnNext(incomingPipeline::push)
                .onErrorContinue(
                    RECOVERABLE_ERRORS_PREDICATE,
                    (err, msg) -> LOG.debug("Error while processing message", err))
                .subscribe());
    final Map<StandardProtocolFamily, NioDatagramChannel> channels = new ConcurrentHashMap<>();
    return CompletableFuture.allOf(
            discoveryServers.stream()
                .map(
                    discoveryServer ->
                        discoveryServer
                            .start()
                            .thenAccept(
                                channel -> {
                                  // getListenAddress() returns the configured IP with the actual
                                  // bound port (resolving port 0 to the OS-assigned ephemeral
                                  // port).
                                  final InetSocketAddress boundAddress =
                                      discoveryServer.getListenAddress();
                                  // If the ENR was initialised with port 0, update it with the
                                  // real OS-assigned port.  onBoundPortResolved bypasses the
                                  // NewAddressHandler so the update is always applied regardless
                                  // of how the caller configured external address changes.
                                  localNodeRecordStore.onBoundPortResolved(boundAddress);
                                  channels.put(
                                      protocolFamilyOf(boundAddress.getAddress()), channel);
                                }))
                .toArray(CompletableFuture<?>[]::new))
        .thenRun(
            () ->
                discoveryClient =
                    new NettyDiscoveryClientImpl(outgoingMessages.asFlux(), channels));
  }

  @Override
  public void stop() {
    final DiscoveryClient client = this.discoveryClient;
    if (client != null) {
      client.stop();
    }
    discoveryServers.forEach(NettyDiscoveryServer::stop);
  }

  @Override
  public NodeRecord getLocalNodeRecord() {
    return localNodeRecordStore.getLocalNodeRecord();
  }

  @Override
  public void updateCustomFieldValue(final String fieldName, final Bytes value) {
    localNodeRecordStore.onCustomFieldValueChanged(fieldName, value);
  }

  private <T> CompletableFuture<T> executeTaskImpl(
      final NodeRecord nodeRecord, final Request<T> request) {
    Envelope envelope = new Envelope();
    envelope.put(Field.NODE, nodeRecord);
    envelope.put(Field.REQUEST, request);
    outgoingPipeline.push(envelope);
    return request.getResultPromise();
  }

  @Override
  public CompletableFuture<Collection<NodeRecord>> findNodes(
      final NodeRecord nodeRecord, final List<Integer> distances) {
    Request<Collection<NodeRecord>> request =
        new Request<>(
            new CompletableFuture<>(),
            reqId -> new FindNodeMessage(reqId, distances),
            new FindNodeResponseHandler(distances, addressAccessPolicy));
    return executeTaskImpl(nodeRecord, request);
  }

  @Override
  public CompletableFuture<Void> ping(final NodeRecord nodeRecord) {
    Request<Void> request =
        new Request<>(
            new CompletableFuture<>(),
            reqId -> new PingMessage(reqId, localNodeRecordStore.getLocalNodeRecord().getSeq()),
            MultiPacketResponseHandler.SINGLE_PACKET_RESPONSE_HANDLER);
    return executeTaskImpl(nodeRecord, request);
  }

  @Override
  public CompletableFuture<Bytes> talk(
      final NodeRecord nodeRecord, final Bytes protocol, final Bytes requestBytes) {
    Request<Bytes> request =
        new Request<>(
            new CompletableFuture<>(),
            reqId -> new TalkReqMessage(reqId, protocol, requestBytes),
            MultiPacketResponseHandler.SINGLE_PACKET_RESPONSE_HANDLER);
    return executeTaskImpl(nodeRecord, request);
  }

  @VisibleForTesting
  public Publisher<NetworkParcel> getOutgoingMessages() {
    return outgoingMessages.asFlux();
  }

  @VisibleForTesting
  public Pipeline getIncomingPipeline() {
    return incomingPipeline;
  }

  @VisibleForTesting
  public Pipeline getOutgoingPipeline() {
    return outgoingPipeline;
  }

  @VisibleForTesting
  public Optional<NodeSession> getNodeSession(final Bytes remoteNodeId) {
    return nodeSessionManager.getNodeSession(remoteNodeId);
  }

  @Override
  public Stream<NodeRecord> streamActiveSessions() {
    return nodeSessionManager.streamActiveSessions();
  }

  private static StandardProtocolFamily protocolFamilyOf(final InetAddress address) {
    return address instanceof Inet6Address
        ? StandardProtocolFamily.INET6
        : StandardProtocolFamily.INET;
  }
}
