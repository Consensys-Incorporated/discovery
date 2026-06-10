/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.database;

import static com.google.common.base.Preconditions.checkArgument;

import com.google.common.base.Ticker;
import com.google.common.cache.CacheBuilder;
import java.time.Clock;
import java.time.Duration;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Set-alike collection with data expiring in configured time. This structure is not thread safe,
 * please, synchronize usage
 *
 * @param <V> data type should extend {@code Comparable<V>} to avoid collisions
 */
public class ExpirationSet<V extends Comparable<V>> {

  private final Set<V> data;

  /**
   * Creates new set with records expiring in configured timeline after insertion
   *
   * @param expirationDelayMillis Expiration delay, each record will be removed after this time
   * @param clock Clock instance
   * @param maxSize Maximum size of a set, the oldest records will be removed to store new
   */
  public ExpirationSet(final long expirationDelayMillis, final Clock clock, final long maxSize) {
    checkArgument(maxSize > 0, "Minimal size is 1");
    data =
        Collections.newSetFromMap(
            CacheBuilder.newBuilder()
                .maximumSize(maxSize)
                .expireAfterWrite(Duration.ofMillis(expirationDelayMillis))
                .ticker(
                    new Ticker() {
                      @Override
                      public long read() {
                        return TimeUnit.MILLISECONDS.toNanos(clock.millis());
                      }
                    })
                .<V, Boolean>build()
                .asMap());
  }

  /**
   * Creates new set with records expiring in configured timeline after insertion
   *
   * @param expirationDelay Expiration delay, each record will be removed after this time
   * @param clock Clock instance
   * @param maxSize Maximum size of a set, the oldest records will be removed to store new
   */
  public ExpirationSet(final Duration expirationDelay, final Clock clock, final long maxSize) {
    this(expirationDelay.toMillis(), clock, maxSize);
  }

  public boolean contains(V o) {
    return data.contains(o);
  }

  public boolean add(V v) {
    if (data.contains(v)) {
      // Ensure re-adding doesn't reset expiration.
      return false;
    }
    return data.add(v);
  }
}
