/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.pipeline;

import static org.ethereum.beacon.discovery.pipeline.Field.INCOMING;
import static org.ethereum.beacon.discovery.util.Utils.RECOVERABLE_ERRORS_PREDICATE;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

public class PipelineImpl implements Pipeline {
  private static final Logger LOG = LogManager.getLogger();

  private final List<EnvelopeHandler> envelopeHandlers = new ArrayList<>();
  private final AtomicBoolean started = new AtomicBoolean(false);
  private final Sinks.Many<Envelope> pipelineSinks = Sinks.many().replay().latest();
  private Flux<Envelope> pipeline = pipelineSinks.asFlux();

  @Override
  public synchronized Pipeline build() {
    started.set(true);
    for (EnvelopeHandler handler : envelopeHandlers) {
      pipeline =
          pipeline.doOnNext(
              envelope -> {
                try {
                  handler.handle(envelope);
                } catch (Throwable t) {
                  LOG.debug(
                      "Unexpected error in pipeline handler {}",
                      handler.getClass().getSimpleName(),
                      t);
                }
              });
    }
    Flux.from(pipeline)
        .onErrorContinue(
            RECOVERABLE_ERRORS_PREDICATE,
            (err, msg) -> LOG.debug("Error while processing message: " + err))
        .subscribe();
    return this;
  }

  @Override
  public void push(Object object) {
    if (!started.get()) {
      throw new RuntimeException("You should build pipeline first");
    }
    final Envelope envelope;
    if (!(object instanceof Envelope)) {
      envelope = new Envelope();
      envelope.put(INCOMING, object);
    } else {
      envelope = (Envelope) object;
    }
    // retry on FAIL_NON_SERIALIZED to handle concurrent push from multiple event-loop threads
    pipelineSinks.emitNext(
        envelope, (signalType, emitResult) -> emitResult == Sinks.EmitResult.FAIL_NON_SERIALIZED);
  }

  @Override
  public Pipeline addHandler(EnvelopeHandler envelopeHandler) {
    if (started.get()) {
      throw new RuntimeException("Pipeline already started, couldn't add any handlers");
    }
    envelopeHandlers.add(envelopeHandler);
    return this;
  }

  @Override
  public Publisher<Envelope> getOutgoingEnvelopes() {
    return pipeline;
  }
}
