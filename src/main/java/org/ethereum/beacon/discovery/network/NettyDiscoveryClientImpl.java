/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.network;

import io.netty.buffer.Unpooled;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioDatagramChannel;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;

/** Netty discovery UDP client */
public class NettyDiscoveryClientImpl implements DiscoveryClient {
  private static final Logger LOG = LogManager.getLogger(NettyDiscoveryClientImpl.class);

  private final Map<StandardProtocolFamily, NioDatagramChannel> channels;

  /**
   * Constructs UDP client using
   *
   * @param outgoingStream Stream of outgoing packets, client will forward them to the channel
   * @param channels must have either 1 entry (IPv4/IPv6) or 2 entries (IPv4 and IPv6)
   */
  public NettyDiscoveryClientImpl(
      final Publisher<NetworkParcel> outgoingStream,
      final Map<StandardProtocolFamily, NioDatagramChannel> channels) {
    this.channels = channels;
    Flux.from(outgoingStream)
        .subscribe(
            networkPacket ->
                send(networkPacket.getPacket().getBytes(), networkPacket.getDestination()));
    LOG.info("UDP discovery client started");
  }

  @Override
  public void stop() {}

  @Override
  public void send(final Bytes data, final InetSocketAddress destination) {
    final DatagramPacket packet =
        new DatagramPacket(Unpooled.copiedBuffer(data.toArray()), destination);
    final NioDatagramChannel channel = channels.get(protocolFamilyOf(destination.getAddress()));
    if (channel == null) {
      LOG.trace(
          () -> String.format("Dropping packet %s because of IP version incompatibility", packet));
      return;
    }
    LOG.trace(() -> String.format("Sending packet %s", packet));
    channel.write(packet);
    channel.flush();
  }

  private static StandardProtocolFamily protocolFamilyOf(final InetAddress address) {
    return address instanceof Inet6Address
        ? StandardProtocolFamily.INET6
        : StandardProtocolFamily.INET;
  }
}
