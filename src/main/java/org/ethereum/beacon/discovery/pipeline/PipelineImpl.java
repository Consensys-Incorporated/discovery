/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.pipeline;

import static org.ethereum.beacon.discovery.pipeline.Field.INCOMING;
import static org.ethereum.beacon.discovery.util.Utils.RECOVERABLE_ERRORS_PREDICATE;

import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

public class PipelineImpl implements Pipeline {
  private static final Logger LOG = LogManager.getLogger();

  private final List<EnvelopeHandler> envelopeHandlers = new ArrayList<>();
  private final AtomicBoolean started = new AtomicBoolean(false);
  // Handlers run synchronously on the thread that emits into the sink, and pushes can arrive
  // concurrently (IPv4/IPv6 event loops, API callers, scheduler). Reactor's serialized sinks
  // would reject a push made while another thread is still inside the handler chain
  // (FAIL_NON_SERIALIZED), so we serialize ourselves: pushes are queued and drained by whichever
  // thread currently owns the work-in-progress counter, which also makes re-entrant pushes from
  // handlers safe. The sink itself is therefore only ever emitted into from one thread at a time.
  private final Sinks.Many<Envelope> pipelineSinks = Sinks.unsafe().many().replay().latest();
  private final Queue<Envelope> pending = new ConcurrentLinkedQueue<>();
  private final AtomicInteger wip = new AtomicInteger();
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
    pending.offer(envelope);
    if (wip.getAndIncrement() != 0) {
      // another thread is draining and will pick this envelope up
      return;
    }
    int missed = 1;
    do {
      Envelope next;
      while ((next = pending.poll()) != null) {
        emit(next);
      }
      missed = wip.addAndGet(-missed);
    } while (missed != 0);
  }

  private void emit(final Envelope envelope) {
    try {
      final Sinks.EmitResult result = pipelineSinks.tryEmitNext(envelope);
      if (result.isFailure()) {
        LOG.error("Failed to push envelope {} into pipeline: {}", envelope.getIdString(), result);
      }
    } catch (final Throwable t) {
      // never let an emission failure escape the drain loop, or the pipeline would stall forever
      LOG.error(
          "Unexpected error while pushing envelope {} into pipeline", envelope.getIdString(), t);
    }
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
