/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.crypto;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Random;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.SECP256K1;
import org.apache.tuweni.crypto.SECP256K1.KeyPair;
import org.ethereum.beacon.discovery.util.Functions;
import org.junit.jupiter.api.Test;

class DefaultSignerTest {
  private final Random random = new Random(7);
  private final KeyPair keyPair = Functions.randomKeyPair(random);
  private final KeyPair peerKeyPair = Functions.randomKeyPair(random);
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
}
