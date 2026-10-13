/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.pipeline;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Subscription;
import reactor.core.publisher.BaseSubscriber;
import reactor.core.publisher.Flux;

class PipelineImplTest {

  @Test
  void shouldRetainConcurrentPushWhileHandlerIsBusy() throws Exception {
    final CountDownLatch entered = new CountDownLatch(1);
    final CountDownLatch release = new CountDownLatch(1);
    final List<String> received = new CopyOnWriteArrayList<>();
    final PipelineImpl pipeline = new PipelineImpl();
    pipeline.addHandler(
        envelope -> {
          final String value = (String) envelope.get(Field.INCOMING);
          if (value.equals("first")) {
            entered.countDown();
            try {
              if (!release.await(5, TimeUnit.SECONDS)) {
                throw new AssertionError("Handler was not released");
              }
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
              throw new AssertionError(e);
            }
          }
          received.add(value);
        });
    pipeline.build();

    final Thread first = new Thread(() -> pipeline.push("first"));
    first.start();
    try {
      assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
      // handler for "first" is still busy on the other thread; this push must not be dropped
      pipeline.push("second");
    } finally {
      release.countDown();
      first.join(5000);
    }
    assertThat(received).containsExactly("first", "second");
  }

  @Test
  void shouldProcessPushFromWithinHandlerAfterCurrentEnvelope() {
    final List<String> received = new CopyOnWriteArrayList<>();
    final PipelineImpl pipeline = new PipelineImpl();
    pipeline.addHandler(
        envelope -> {
          final String value = (String) envelope.get(Field.INCOMING);
          received.add(value);
          if (value.equals("first")) {
            // re-entrant push from a handler must be queued, not dropped or processed inline
            pipeline.push("nested");
            received.add("first-done");
          }
        });
    pipeline.build();

    pipeline.push("first");

    assertThat(received).containsExactly("first", "first-done", "nested");
  }

  @Test
  void shouldKeepProcessingAfterHandlerThrows() {
    final List<String> received = new CopyOnWriteArrayList<>();
    final PipelineImpl pipeline = new PipelineImpl();
    pipeline.addHandler(
        envelope -> {
          final String value = (String) envelope.get(Field.INCOMING);
          if (value.equals("boom")) {
            throw new IllegalStateException("handler failure");
          }
          received.add(value);
        });
    pipeline.build();

    pipeline.push("boom");
    pipeline.push("after");

    assertThat(received).containsExactly("after");
  }

  @Test
  void shouldDeliverEnvelopesToAdditionalSubscribers() {
    final List<String> received = new CopyOnWriteArrayList<>();
    final List<String> observed = new CopyOnWriteArrayList<>();
    final PipelineImpl pipeline = new PipelineImpl();
    pipeline.addHandler(envelope -> received.add((String) envelope.get(Field.INCOMING)));
    pipeline.build();
    Flux.from(pipeline.getOutgoingEnvelopes())
        .subscribe(envelope -> observed.add((String) envelope.get(Field.INCOMING)));

    pipeline.push("a");
    pipeline.push("b");

    assertThat(received).contains("a", "b");
    assertThat(observed).containsExactly("a", "b");
  }

  @Test
  void shouldReplayLatestEnvelopeToLateSubscriber() {
    final List<String> observed = new CopyOnWriteArrayList<>();
    final PipelineImpl pipeline = new PipelineImpl();
    pipeline.addHandler(envelope -> {});
    pipeline.build();

    pipeline.push("a");
    pipeline.push("b");
    Flux.from(pipeline.getOutgoingEnvelopes())
        .subscribe(envelope -> observed.add((String) envelope.get(Field.INCOMING)));
    pipeline.push("c");

    assertThat(observed).containsExactly("b", "c");
  }

  @Test
  void shouldKeepProcessingWhenAnObserverStopsRequesting() {
    final List<String> received = new CopyOnWriteArrayList<>();
    final List<String> observed = new CopyOnWriteArrayList<>();
    final PipelineImpl pipeline = new PipelineImpl();
    pipeline.addHandler(envelope -> received.add((String) envelope.get(Field.INCOMING)));
    pipeline.build();
    // an observer that only ever requests a single envelope must not throttle the pipeline
    Flux.from(pipeline.getOutgoingEnvelopes())
        .subscribe(
            new BaseSubscriber<>() {
              @Override
              protected void hookOnSubscribe(final Subscription subscription) {
                subscription.request(1);
              }

              @Override
              protected void hookOnNext(final Envelope envelope) {
                observed.add((String) envelope.get(Field.INCOMING));
              }
            });

    pipeline.push("a");
    pipeline.push("b");
    pipeline.push("c");

    assertThat(received).contains("a", "b", "c");
    assertThat(observed).containsExactly("a");
  }
}
