/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.util.Random;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.SECP256K1;
import org.apache.tuweni.crypto.SECP256K1.KeyPair;
import org.apache.tuweni.crypto.SECP256K1.SecretKey;
import org.junit.jupiter.api.Test;

/**
 * Checks {@link DefaultSigner} against tuweni's {@link SECP256K1}. Key pairs are built by tuweni so
 * that the expected public keys do not come from the code under test.
 */
class DefaultSignerTest {
  private static final BigInteger CURVE_ORDER = SECP256K1.Parameters.CURVE.getN();

  private final Random random = new Random(7);
  private final KeyPair keyPair = referenceKeyPair(random);
  private final KeyPair peerKeyPair = referenceKeyPair(random);
  private final DefaultSigner signer = new DefaultSigner(keyPair.secretKey());

  @Test
  void sign_matchesReferenceSignature() {
    for (int i = 0; i < 3; i++) {
      final Bytes32 hash = Bytes32.random(random);

      assertThat(signer.sign(hash))
          .isEqualTo(SECP256K1.signHashed(hash, keyPair).bytes().slice(0, 64));
    }
  }

  @Test
  void deriveCompressedPublicKeyFromPrivate_matchesReference() {
    final Bytes expected = Bytes.wrap(keyPair.publicKey().asEcPoint().getEncoded(true));

    assertThat(signer.deriveCompressedPublicKeyFromPrivate()).isEqualTo(expected);
    assertThat(signer.deriveCompressedPublicKeyFromPrivate()).isEqualTo(expected);
  }

  @Test
  void deriveECDHKeyAgreement_isSymmetric() {
    final DefaultSigner peerSigner = new DefaultSigner(peerKeyPair.secretKey());

    final Bytes local =
        signer.deriveECDHKeyAgreement(peerSigner.deriveCompressedPublicKeyFromPrivate());
    final Bytes remote =
        peerSigner.deriveECDHKeyAgreement(signer.deriveCompressedPublicKeyFromPrivate());

    assertThat(local).isEqualTo(remote);
    assertThat(local)
        .isEqualTo(
            Bytes.wrap(
                peerKeyPair
                    .publicKey()
                    .asEcPoint()
                    .multiply(keyPair.secretKey().bytes().toUnsignedBigInteger())
                    .getEncoded(true)));
  }

  @Test
  void constructor_rejectsZeroScalar() {
    assertThatThrownBy(() -> new DefaultSigner(SecretKey.fromBytes(Bytes32.ZERO)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void constructor_rejectsScalarNotBelowCurveOrder() {
    for (final BigInteger invalid :
        new BigInteger[] {CURVE_ORDER, BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)}) {
      assertThatThrownBy(() -> new DefaultSigner(SecretKey.fromInteger(invalid)))
          .isInstanceOf(IllegalArgumentException.class);
    }
  }

  @Test
  void constructor_acceptsScalarBoundaries() {
    assertThat(new DefaultSigner(SecretKey.fromInteger(BigInteger.ONE))).isNotNull();
    assertThat(new DefaultSigner(SecretKey.fromInteger(CURVE_ORDER.subtract(BigInteger.ONE))))
        .isNotNull();
  }

  @Test
  void destroyedSecretKey_disablesPrivateKeyOperations() {
    final SecretKey secretKey =
        SecretKey.fromInteger(keyPair.secretKey().bytes().toUnsignedBigInteger());
    final DefaultSigner destroyable = new DefaultSigner(secretKey);
    final Bytes publicKey = destroyable.deriveCompressedPublicKeyFromPrivate();

    secretKey.destroy();

    assertThatThrownBy(() -> destroyable.sign(Bytes32.random(random)))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> destroyable.deriveECDHKeyAgreement(publicKey))
        .isInstanceOf(NullPointerException.class);
    assertThat(destroyable.deriveCompressedPublicKeyFromPrivate()).isEqualTo(publicKey);
  }

  private static KeyPair referenceKeyPair(final Random random) {
    while (true) {
      final BigInteger d = new BigInteger(256, random);
      if (d.signum() > 0 && d.compareTo(CURVE_ORDER) < 0) {
        return KeyPair.fromSecretKey(SecretKey.fromInteger(d));
      }
    }
  }
}
