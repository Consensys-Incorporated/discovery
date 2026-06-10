/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.scheduler;

import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import org.jspecify.annotations.NonNull;
import reactor.core.Disposable;
import reactor.core.scheduler.Scheduler;

public class DelegatingReactorScheduler implements Scheduler {

  protected final Scheduler delegate;
  protected final Supplier<Long> timeSupplier;

  public DelegatingReactorScheduler(Scheduler delegate, Supplier<Long> timeSupplier) {
    this.delegate = delegate;
    this.timeSupplier = timeSupplier;
  }

  @NonNull
  @Override
  public Disposable schedule(@NonNull Runnable task) {
    return delegate.schedule(task);
  }

  @NonNull
  @Override
  public Disposable schedule(Runnable task, long delay, TimeUnit unit) {
    return delegate.schedule(task, delay, unit);
  }

  @NonNull
  @Override
  public Disposable schedulePeriodically(
      Runnable task, long initialDelay, long period, TimeUnit unit) {
    return delegate.schedulePeriodically(task, initialDelay, period, unit);
  }

  @Override
  public long now(TimeUnit unit) {
    return unit.convert(timeSupplier.get(), TimeUnit.MILLISECONDS);
  }

  @NonNull
  @Override
  public Worker createWorker() {
    return delegate.createWorker();
  }

  @Override
  public void dispose() {
    delegate.dispose();
  }

  @SuppressWarnings("deprecation")
  @Override
  public void start() {
    delegate.start();
  }

  @Override
  public boolean isDisposed() {
    return delegate.isDisposed();
  }

  public static class DelegateWorker implements Worker {
    protected final Worker delegate;

    public DelegateWorker(Worker delegate) {
      this.delegate = delegate;
    }

    @NonNull
    @Override
    public Disposable schedule(@NonNull Runnable task) {
      return delegate.schedule(task);
    }

    @NonNull
    @Override
    public Disposable schedule(Runnable task, long delay, TimeUnit unit) {
      return delegate.schedule(task, delay, unit);
    }

    @NonNull
    @Override
    public Disposable schedulePeriodically(
        Runnable task, long initialDelay, long period, TimeUnit unit) {
      return delegate.schedulePeriodically(task, initialDelay, period, unit);
    }

    @Override
    public void dispose() {
      delegate.dispose();
    }

    @Override
    public boolean isDisposed() {
      return delegate.isDisposed();
    }
  }
}
