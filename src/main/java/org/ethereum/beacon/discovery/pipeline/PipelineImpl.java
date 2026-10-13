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
import reactor.core.publisher.FluxSink;
import reactor.core.publisher.Sinks;

public class PipelineImpl implements Pipeline {
  private static final Logger LOG = LogManager.getLogger();

  private final List<EnvelopeHandler> envelopeHandlers = new ArrayList<>();
  private final AtomicBoolean started = new AtomicBoolean(false);
  // Handlers run synchronously on the thread that emits into the sink, and pushes can arrive
  // concurrently (IPv4/IPv6 event loops, API callers, scheduler) or re-entrantly from a handler.
  // Two Reactor pieces give the semantics the old ReplayProcessor.cacheLast().sink() had:
  //  - Flux.create hands out a serialized FluxSink that queues such emissions and drains them in
  //    order (Sinks.many() would reject them with FAIL_NON_SERIALIZED), so the replay sink below
  //    is only ever emitted into from one thread at a time;
  //  - the replay sink multicasts to every subscriber at that subscriber's own pace, so a slow
  //    getOutgoingEnvelopes() observer cannot throttle the internal processing subscription the
  //    way demand-coordinating operators such as replay(1) or publish() would.
  private final Sinks.Many<Envelope> envelopes = Sinks.many().replay().latest();
  private volatile FluxSink<Envelope> pipelineSink;
  private Flux<Envelope> pipeline = envelopes.asFlux();

  @Override
  public synchronized Pipeline build() {
    Flux.<Envelope>create(sink -> pipelineSink = sink)
        .subscribe(
            envelope -> {
              final Sinks.EmitResult result = envelopes.tryEmitNext(envelope);
              if (result.isFailure()) {
                LOG.error(
                    "Failed to push envelope {} into pipeline: {}", envelope.getIdString(), result);
              }
            });
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
    // the Flux.create subscription above captured pipelineSink synchronously, so pushes are only
    // allowed from this point on
    started.set(true);
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
    pipelineSink.next(envelope);
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
