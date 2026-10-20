/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.util.Random;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.SECP256K1;
import org.apache.tuweni.crypto.SECP256K1.KeyPair;
import org.apache.tuweni.crypto.SECP256K1.SecretKey;
import org.apache.tuweni.crypto.SECP256K1.Signature;
import org.apache.tuweni.units.bigints.UInt256;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/** Checks {@link Secp256k1} against tuweni's {@link SECP256K1} as reference implementation. */
class Secp256k1Test {
  private static final BigInteger CURVE_ORDER = SECP256K1.Parameters.CURVE.getN();

  static Stream<Integer> seeds() {
    return IntStream.range(0, 20).boxed();
  }

  @ParameterizedTest
  @MethodSource("seeds")
  void sign_matchesReferenceSignature(final int seed) {
    final Random random = new Random(seed);
    final KeyPair keyPair = randomKeyPair(random);
    final Bytes32 hash = randomHash(random);

    final Bytes expected = SECP256K1.signHashed(hash, keyPair).bytes().slice(0, 64);

    assertThat(Secp256k1.sign(privateKey(keyPair), hash)).isEqualTo(expected);
  }

  @ParameterizedTest
  @MethodSource("seeds")
  void sign_producesLowS(final int seed) {
    final Random random = new Random(seed);
    final Bytes signature = Secp256k1.sign(privateKey(randomKeyPair(random)), randomHash(random));

    assertThat(signature.slice(32).toUnsignedBigInteger())
        .isLessThanOrEqualTo(CURVE_ORDER.shiftRight(1));
  }

  @ParameterizedTest
  @MethodSource("seeds")
  void verify_acceptsReferenceSignature(final int seed) {
    final Random random = new Random(seed);
    final KeyPair keyPair = randomKeyPair(random);
    final Bytes32 hash = randomHash(random);
    final Bytes signature = SECP256K1.signHashed(hash, keyPair).bytes().slice(0, 64);

    assertThat(Secp256k1.verify(signature, hash, publicKeyPoint(keyPair))).isTrue();
  }

  @Test
  void verify_rejectsSignatureOfOtherMessage() {
    final Random random = new Random(1);
    final KeyPair keyPair = randomKeyPair(random);
    final Bytes signature = Secp256k1.sign(privateKey(keyPair), randomHash(random));

    assertThat(Secp256k1.verify(signature, randomHash(random), publicKeyPoint(keyPair))).isFalse();
  }

  @Test
  void verify_rejectsSignatureOfOtherKey() {
    final Random random = new Random(2);
    final Bytes32 hash = randomHash(random);
    final Bytes signature = Secp256k1.sign(privateKey(randomKeyPair(random)), hash);

    assertThat(Secp256k1.verify(signature, hash, publicKeyPoint(randomKeyPair(random)))).isFalse();
  }

  @Test
  void verify_acceptsHighSLikeReference() {
    final Random random = new Random(3);
    final KeyPair keyPair = randomKeyPair(random);
    final Bytes32 hash = randomHash(random);
    final Signature lowS = SECP256K1.signHashed(hash, keyPair);
    final BigInteger highS = CURVE_ORDER.subtract(lowS.s());

    assertThat(
            SECP256K1.verifyHashed(
                hash, Signature.create((byte) 0, lowS.r(), highS), keyPair.publicKey()))
        .isTrue();
    assertThat(Secp256k1.verify(signature(lowS.r(), highS), hash, publicKeyPoint(keyPair)))
        .isTrue();
  }

  @Test
  void verify_rejectsOutOfRangeScalars() {
    final Random random = new Random(4);
    final KeyPair keyPair = randomKeyPair(random);
    final Bytes32 hash = randomHash(random);
    final Signature valid = SECP256K1.signHashed(hash, keyPair);
    final ECPoint publicKey = publicKeyPoint(keyPair);
    final BigInteger max = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);

    for (final BigInteger invalid : new BigInteger[] {BigInteger.ZERO, CURVE_ORDER, max}) {
      assertThat(Secp256k1.verify(signature(invalid, valid.s()), hash, publicKey)).isFalse();
      assertThat(Secp256k1.verify(signature(valid.r(), invalid), hash, publicKey)).isFalse();
    }
  }

  @ParameterizedTest
  @MethodSource("seeds")
  void compressedPublicKey_matchesReference(final int seed) {
    final KeyPair keyPair = randomKeyPair(new Random(seed));

    assertThat(Secp256k1.compressedPublicKey(privateKey(keyPair)))
        .isEqualTo(Bytes.wrap(keyPair.publicKey().asEcPoint().getEncoded(true)));
  }

  @ParameterizedTest
  @MethodSource("seeds")
  void uncompressedPublicKey_matchesReference(final int seed) {
    final KeyPair keyPair = randomKeyPair(new Random(seed));

    assertThat(Secp256k1.uncompressedPublicKey(privateKey(keyPair)))
        .isEqualTo(keyPair.publicKey().bytes());
  }

  @ParameterizedTest
  @MethodSource("seeds")
  void ecdh_matchesReference(final int seed) {
    final Random random = new Random(seed);
    final KeyPair local = randomKeyPair(random);
    final KeyPair peer = randomKeyPair(random);
    final Bytes peerCompressed = Bytes.wrap(peer.publicKey().asEcPoint().getEncoded(true));

    final Bytes expected =
        Bytes.wrap(peer.publicKey().asEcPoint().multiply(privateKey(local)).getEncoded(true));

    assertThat(Secp256k1.ecdh(privateKey(local), peerCompressed)).isEqualTo(expected);
    assertThat(Secp256k1.ecdh(privateKey(local), peer.publicKey().bytes())).isEqualTo(expected);
  }

  @ParameterizedTest
  @MethodSource("seeds")
  void decodePoint_matchesReferenceForAllEncodings(final int seed) {
    final KeyPair keyPair = randomKeyPair(new Random(seed));
    final ECPoint reference = keyPair.publicKey().asEcPoint();

    for (final Bytes encoded :
        new Bytes[] {
          Bytes.wrap(reference.getEncoded(true)),
          Bytes.wrap(reference.getEncoded(false)),
          keyPair.publicKey().bytes()
        }) {
      final ECPoint decoded = Secp256k1.decodePoint(encoded);
      assertThat(decoded.getAffineXCoord().toBigInteger())
          .isEqualTo(reference.getAffineXCoord().toBigInteger());
      assertThat(decoded.getAffineYCoord().toBigInteger())
          .isEqualTo(reference.getAffineYCoord().toBigInteger());
    }
  }

  @Test
  void decodePoint_rejectsXNotOnCurve() {
    final Bytes notOnCurve = compressedPointNotOnCurve();

    assertThatThrownBy(
            () -> SECP256K1.Parameters.CURVE.getCurve().decodePoint(notOnCurve.toArray()))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> Secp256k1.decodePoint(notOnCurve))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void decodePoint_rejectsInvalidPrefix() {
    final Bytes compressed =
        Bytes.wrap(randomKeyPair(new Random(5)).publicKey().asEcPoint().getEncoded(true));
    final Bytes invalid = Bytes.concatenate(Bytes.of(0x05), compressed.slice(1));

    assertThatThrownBy(() -> Secp256k1.decodePoint(invalid))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private static Bytes compressedPointNotOnCurve() {
    final Random random = new Random(6);
    while (true) {
      final Bytes candidate = Bytes.concatenate(Bytes.of(0x02), randomHash(random));
      try {
        SECP256K1.Parameters.CURVE.getCurve().decodePoint(candidate.toArray());
      } catch (final IllegalArgumentException e) {
        return candidate;
      }
    }
  }

  private static KeyPair randomKeyPair(final Random random) {
    while (true) {
      final BigInteger d = new BigInteger(256, random);
      if (d.signum() > 0 && d.compareTo(CURVE_ORDER) < 0) {
        return KeyPair.fromSecretKey(SecretKey.fromInteger(d));
      }
    }
  }

  private static Bytes32 randomHash(final Random random) {
    final byte[] bytes = new byte[32];
    random.nextBytes(bytes);
    return Bytes32.wrap(bytes);
  }

  private static BigInteger privateKey(final KeyPair keyPair) {
    return keyPair.secretKey().bytes().toUnsignedBigInteger();
  }

  private static ECPoint publicKeyPoint(final KeyPair keyPair) {
    return Secp256k1.decodePoint(keyPair.publicKey().bytes());
  }

  private static Bytes signature(final BigInteger r, final BigInteger s) {
    return Bytes.concatenate(toBytes32(r), toBytes32(s));
  }

  private static Bytes toBytes32(final BigInteger value) {
    if (value.bitLength() > 256) {
      throw new IllegalArgumentException("Too large");
    }
    return UInt256.valueOf(value).toBytes();
  }
}
