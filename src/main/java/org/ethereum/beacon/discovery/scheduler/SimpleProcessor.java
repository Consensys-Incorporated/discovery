/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.scheduler;

// import org.ethereum.beacon.schedulers.Scheduler;
import org.reactivestreams.Processor;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

public class SimpleProcessor<T> implements Processor<T, T> {
  Sinks.Many<T> sinks;
  Flux<T> publisher;
  boolean subscribed;

  public SimpleProcessor(Scheduler scheduler, String name, T initialValue) {
    this(scheduler.toReactor(), name);
    onNext(initialValue);
  }

  public SimpleProcessor(Scheduler scheduler, String name) {
    this(scheduler.toReactor(), name);
  }

  public SimpleProcessor(reactor.core.scheduler.Scheduler scheduler, String name) {
    sinks = Sinks.many().replay().latest();
    publisher = sinks.asFlux().publishOn(scheduler).onBackpressureError().name(name);
  }

  @SuppressWarnings({"rawtypes"})
  public SimpleProcessor doOnAnySubscribed(Runnable handler) {
    publisher =
        publisher.doOnSubscribe(
            s -> {
              if (!subscribed) {
                subscribed = true;
                handler.run();
              }
            });
    return this;
  }

  @SuppressWarnings({"rawtypes"})
  public SimpleProcessor doOnNoneSubscribed(Runnable handler) {
    publisher =
        publisher.doOnCancel(
            () -> {
              if (subscribed && sinks.currentSubscriberCount() == 0) {
                subscribed = false;
                handler.run();
              }
            });
    return this;
  }

  @Override
  public void subscribe(Subscriber<? super T> subscriber) {
    publisher.subscribe(subscriber);
  }

  @Override
  public void onSubscribe(Subscription subscription) {
    subscription.request(Long.MAX_VALUE);
  }

  @Override
  public void onNext(T t) {
    sinks.tryEmitNext(t);
  }

  @Override
  public void onError(Throwable throwable) {
    sinks.tryEmitError(throwable);
  }

  @Override
  public void onComplete() {
    sinks.tryEmitComplete();
  }
}
