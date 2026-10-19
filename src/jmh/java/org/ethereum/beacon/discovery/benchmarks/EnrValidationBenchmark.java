/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.benchmarks;

import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.apache.tuweni.bytes.Bytes;
import org.ethereum.beacon.discovery.crypto.DefaultSigner;
import org.ethereum.beacon.discovery.schema.IdentitySchemaV4Interpreter;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordBuilder;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;
import org.ethereum.beacon.discovery.util.Functions;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;

/**
 * {@link NodeRecord#isValid()} as called for every record of a NODES response ({@code
 * FindNodeResponseHandler}).
 *
 * <p>The miss case cycles through more distinct records than the interpreter's signature cache
 * holds, so every call performs the ECDSA verification. The hit case cycles through a few records
 * that stay cached.
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
public class EnrValidationBenchmark {
  // larger than IdentitySchemaV4Interpreter's 10000 entries signature cache
  private static final int MISS_RECORDS = 16384;
  private static final int HIT_RECORDS = 64;

  private final NodeRecord[] missRecords = new NodeRecord[MISS_RECORDS];
  private final NodeRecord[] hitRecords = new NodeRecord[HIT_RECORDS];
  private int missIndex;
  private int hitIndex;

  @Setup
  public void setup() {
    final Random random = new Random(42);
    final Bytes[] serialized = new Bytes[MISS_RECORDS];
    for (int i = 0; i < MISS_RECORDS; i++) {
      serialized[i] = createMainnetLikeRecord(random).serialize();
    }
    // Fresh interpreters so that records validated while building are not cached
    final NodeRecordFactory missFactory = new NodeRecordFactory(new IdentitySchemaV4Interpreter());
    for (int i = 0; i < MISS_RECORDS; i++) {
      missRecords[i] = missFactory.fromBytes(serialized[i]);
    }
    final NodeRecordFactory hitFactory = new NodeRecordFactory(new IdentitySchemaV4Interpreter());
    for (int i = 0; i < HIT_RECORDS; i++) {
      hitRecords[i] = hitFactory.fromBytes(serialized[i]);
      if (!hitRecords[i].isValid()) {
        throw new IllegalStateException("Invalid benchmark record");
      }
    }
  }

  private static NodeRecord createMainnetLikeRecord(final Random random) {
    final byte[] eth2 = new byte[16];
    final byte[] attnets = new byte[8];
    random.nextBytes(eth2);
    random.nextBytes(attnets);
    return new NodeRecordBuilder()
        .signer(new DefaultSigner(Functions.randomKeyPair(random).secretKey()))
        .seq(1 + random.nextInt(1000))
        .address(
            "10." + random.nextInt(256) + "." + random.nextInt(256) + "." + random.nextInt(256),
            9000,
            9000)
        .customField("eth2", Bytes.wrap(eth2))
        .customField("attnets", Bytes.wrap(attnets))
        .customField("syncnets", Bytes.of(0x0f))
        .customField("cgc", Bytes.of(0x80))
        .build();
  }

  @Benchmark
  public boolean isValidCacheMiss() {
    return missRecords[missIndex++ & (MISS_RECORDS - 1)].isValid();
  }

  @Benchmark
  public boolean isValidCacheHit() {
    return hitRecords[hitIndex++ & (HIT_RECORDS - 1)].isValid();
  }
}
