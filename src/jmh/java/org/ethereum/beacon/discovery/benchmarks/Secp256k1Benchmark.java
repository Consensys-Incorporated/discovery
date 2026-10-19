/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.benchmarks;

import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.SECP256K1.KeyPair;
import org.apache.tuweni.crypto.SECP256K1.SecretKey;
import org.ethereum.beacon.discovery.crypto.DefaultSigner;
import org.ethereum.beacon.discovery.crypto.Signer;
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
 * secp256k1 operations on the discv5 hot paths: ENR / id-nonce signing, signature verification,
 * ECDH key agreement and public key derivation (handshake ephemeral keys).
 */
@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
public class Secp256k1Benchmark {
  private static final int INPUTS = 256; // power of two, see next()

  private Signer signer;
  private final Bytes32[] messageHashes = new Bytes32[INPUTS];
  private final SecretKey[] secretKeys = new SecretKey[INPUTS];
  private final Bytes32[] secretKeyBytes = new Bytes32[INPUTS];
  private final Bytes[] compressedPublicKeys = new Bytes[INPUTS];
  private final Bytes[] signatures = new Bytes[INPUTS];
  private int index;

  @Setup
  public void setup() {
    final Random random = new Random(42);
    signer = new DefaultSigner(Functions.randomKeyPair(random).secretKey());
    for (int i = 0; i < INPUTS; i++) {
      final KeyPair keyPair = Functions.randomKeyPair(random);
      final byte[] hash = new byte[32];
      random.nextBytes(hash);
      messageHashes[i] = Bytes32.wrap(hash);
      secretKeys[i] = keyPair.secretKey();
      secretKeyBytes[i] = keyPair.secretKey().bytes();
      compressedPublicKeys[i] = Functions.deriveCompressedPublicKeyFromPrivate(secretKeys[i]);
      signatures[i] = Functions.sign(secretKeys[i], messageHashes[i]);
    }
  }

  private int next() {
    return index++ & (INPUTS - 1);
  }

  /** Local node signing (ENR updates, handshake id signature). */
  @Benchmark
  public Bytes sign() {
    return signer.sign(messageHashes[next()]);
  }

  /** ENR signature and handshake id signature verification. */
  @Benchmark
  public boolean verify() {
    final int i = next();
    return Functions.verifyECDSASignature(signatures[i], messageHashes[i], compressedPublicKeys[i]);
  }

  /** Handshake key agreement with the local static key. */
  @Benchmark
  public Bytes ecdh() {
    return signer.deriveECDHKeyAgreement(compressedPublicKeys[next()]);
  }

  /** Handshake ephemeral public key. */
  @Benchmark
  public Bytes deriveCompressedPublicKey() {
    return Functions.deriveCompressedPublicKeyFromPrivate(secretKeys[next()]);
  }

  /** Handshake ephemeral key pair. */
  @Benchmark
  public KeyPair createKeyPairFromSecretBytes() {
    return Functions.createKeyPairFromSecretBytes(secretKeyBytes[next()]);
  }

  /** Handshake key agreement with an ephemeral key (initiator side). */
  @Benchmark
  public Bytes ecdhFromSecretKey() {
    final int i = next();
    return Functions.deriveECDHKeyAgreement(
        secretKeys[i], compressedPublicKeys[(i + 1) & (INPUTS - 1)]);
  }
}
