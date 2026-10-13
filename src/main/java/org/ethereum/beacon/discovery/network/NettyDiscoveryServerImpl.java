/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.network;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.nio.NioDatagramChannel;
import io.netty.handler.logging.LogLevel;
import io.netty.handler.logging.LoggingHandler;
import io.netty.handler.traffic.ChannelTrafficShapingHandler;
import java.net.InetSocketAddress;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.ethereum.beacon.discovery.pipeline.Envelope;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Sinks;

public class NettyDiscoveryServerImpl implements NettyDiscoveryServer {

  private static final Logger LOG = LogManager.getLogger(NettyDiscoveryServerImpl.class);
  private static final int RECREATION_TIMEOUT = 5000;

  private final Sinks.Many<Envelope> incomingPackets = Sinks.many().replay().latest();
  private final InetSocketAddress listenAddress;
  private final int trafficReadLimit; // bytes per sec
  private AtomicBoolean listen = new AtomicBoolean(false);
  private Channel channel;
  private EventLoopGroup nioGroup;

  public NettyDiscoveryServerImpl(
      final InetSocketAddress listenAddress, final int trafficReadLimit) {
    this.listenAddress = listenAddress;
    this.trafficReadLimit = trafficReadLimit;
  }

  @Override
  public CompletableFuture<NioDatagramChannel> start() {
    LOG.info("Starting discovery server listening on {}", listenAddress);
    if (!listen.compareAndSet(false, true)) {
      return CompletableFuture.failedFuture(
          new IllegalStateException(
              "Attempted to start an already started server listening on " + listenAddress));
    }
    nioGroup = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
    return startServer(nioGroup);
  }

  private CompletableFuture<NioDatagramChannel> startServer(final EventLoopGroup group) {
    final CompletableFuture<NioDatagramChannel> future = new CompletableFuture<>();
    final Bootstrap b = new Bootstrap();
    b.group(group)
        .channel(NioDatagramChannel.class)
        .handler(
            new ChannelInitializer<NioDatagramChannel>() {
              @Override
              public void initChannel(NioDatagramChannel ch) {
                final ChannelPipeline pipeline = ch.pipeline();
                pipeline
                    .addFirst(new LoggingHandler(LogLevel.TRACE))
                    .addLast(new DatagramToEnvelope())
                    .addLast(new IncomingMessageSink(incomingPackets));

                if (trafficReadLimit != 0) {
                  pipeline.addFirst(new ChannelTrafficShapingHandler(0, trafficReadLimit));
                }
              }
            });

    final ChannelFuture bindFuture = b.bind(listenAddress);
    bindFuture.addListener(
        result -> {
          if (!result.isSuccess()) {
            future.completeExceptionally(result.cause());
            return;
          }

          this.channel = bindFuture.channel();
          channel
              .closeFuture()
              .addListener(
                  closeFuture -> {
                    if (!listen.get()) {
                      LOG.info("Shutting down discovery server listening on {}", listenAddress);
                      group.shutdownGracefully();
                      return;
                    }
                    LOG.error(
                        String.format(
                            "Discovery server listening on %s has been closed. Trying to restore after %d milliseconds delay",
                            listenAddress, RECREATION_TIMEOUT),
                        closeFuture.cause());
                    Thread.sleep(RECREATION_TIMEOUT);
                    startServer(group);
                  });
          future.complete((NioDatagramChannel) this.channel);
        });
    return future;
  }

  @Override
  public InetSocketAddress getListenAddress() {
    if (channel != null && listenAddress.getPort() == 0) {
      // Ephemeral port: keep the configured IP (preserves IP-family) but return the actual port.
      return new InetSocketAddress(
          listenAddress.getAddress(), ((InetSocketAddress) channel.localAddress()).getPort());
    }
    return listenAddress;
  }

  @Override
  public Publisher<Envelope> getIncomingPackets() {
    return incomingPackets.asFlux();
  }

  @Override
  public void stop() {
    if (listen.compareAndSet(true, false)) {
      LOG.info("Stopping discovery server listening on {}", listenAddress);
      if (channel != null) {
        try {
          channel.close().sync();
        } catch (InterruptedException ex) {
          LOG.error("Failed to stop discovery server listening on " + listenAddress, ex);
        }
        if (nioGroup != null) {
          try {
            nioGroup.shutdownGracefully().sync();
          } catch (InterruptedException ex) {
            LOG.error("Failed to stop NIO group", ex);
          }
        }
      }
    } else {
      LOG.warn("An attempt to stop already stopping/stopped discovery server");
    }
  }
}
