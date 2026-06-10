/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.pipeline.handler;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.AddressAccessPolicy;
import org.ethereum.beacon.discovery.network.NetworkParcel;
import org.ethereum.beacon.discovery.network.NetworkParcelV5;
import org.ethereum.beacon.discovery.packet.impl.RawPacketImpl;
import org.ethereum.beacon.discovery.pipeline.Envelope;
import org.ethereum.beacon.discovery.pipeline.Field;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Sinks;

class OutgoingParcelHandlerTest {

  public static final RawPacketImpl PACKET =
      new RawPacketImpl(Bytes.fromHexString("0x12341234123412341234123412341234"));
  private static final InetSocketAddress DISALLOWED_ADDRESS =
      new InetSocketAddress(InetAddress.getLoopbackAddress(), 12345);
  private static final InetSocketAddress ALLOWED_ADDRESS =
      new InetSocketAddress(InetAddress.getLoopbackAddress(), 8080);

  @SuppressWarnings("unchecked")
  private final Sinks.Many<NetworkParcel> outgoingSink =
      (Sinks.Many<NetworkParcel>) mock(Sinks.Many.class);

  private final AddressAccessPolicy addressAccessPolicy =
      address -> !address.equals(DISALLOWED_ADDRESS);

  private final OutgoingParcelHandler handler =
      new OutgoingParcelHandler(outgoingSink, addressAccessPolicy);

  @Test
  void shouldNotSendPacketsToDisallowedHosts() {
    final Envelope envelope = new Envelope();
    envelope.put(Field.INCOMING, new NetworkParcelV5(PACKET, DISALLOWED_ADDRESS));
    handler.handle(envelope);

    verifyNoInteractions(outgoingSink);
  }

  @Test
  void shouldSendPacketsToAllowedHosts() {
    final Envelope envelope = new Envelope();
    final NetworkParcelV5 parcel = new NetworkParcelV5(PACKET, ALLOWED_ADDRESS);
    envelope.put(Field.INCOMING, parcel);
    handler.handle(envelope);

    verify(outgoingSink).tryEmitNext(parcel);
  }
}
