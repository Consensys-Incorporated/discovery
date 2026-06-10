/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.pipeline.handler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.ethereum.beacon.discovery.AddressAccessPolicy;
import org.ethereum.beacon.discovery.network.NetworkParcel;
import org.ethereum.beacon.discovery.pipeline.AbstractSkippingEnvelopeHandler;
import org.ethereum.beacon.discovery.pipeline.Envelope;
import org.ethereum.beacon.discovery.pipeline.Field;
import org.ethereum.beacon.discovery.pipeline.HandlerUtil;
import reactor.core.publisher.Sinks;

/**
 * Looks up for {@link NetworkParcel} in {@link Field#INCOMING} field. If it's found, it shows that
 * we have outgoing parcel at the very first stage. Handler pushes it to `outgoingSink` stream which
 * is linked with discovery client.
 */
public class OutgoingParcelHandler extends AbstractSkippingEnvelopeHandler {
  private static final Logger LOG = LogManager.getLogger(OutgoingParcelHandler.class);

  private final Sinks.Many<NetworkParcel> outgoingSink;
  private final AddressAccessPolicy addressAccessPolicy;

  public OutgoingParcelHandler(
      Sinks.Many<NetworkParcel> outgoingSink, final AddressAccessPolicy addressAccessPolicy) {
    this.outgoingSink = outgoingSink;
    this.addressAccessPolicy = addressAccessPolicy;
  }

  @Override
  protected void handlePacket(Envelope envelope) {
    if (!HandlerUtil.requireField(Field.INCOMING, envelope)) {
      return;
    }
    LOG.trace(
        () ->
            String.format(
                "Envelope %s in OutgoingParcelHandler, requirements are satisfied!",
                envelope.getIdString()));

    if (envelope.get(Field.INCOMING) instanceof NetworkParcel) {
      NetworkParcel parcel = (NetworkParcel) envelope.get(Field.INCOMING);
      if (parcel.getPacket().getBytes().size() > IncomingDataPacker.MAX_PACKET_SIZE) {
        LOG.error("Outgoing packet is too large, dropping it: {}", parcel.getPacket());
      } else if (!addressAccessPolicy.allow(parcel.getDestination())) {
        LOG.trace(
            "Dropping outgoing packet to disallowed destination: {}", parcel.getDestination());
      } else {
        outgoingSink.tryEmitNext(parcel);
        envelope.remove(Field.INCOMING);
      }
    }
  }
}
