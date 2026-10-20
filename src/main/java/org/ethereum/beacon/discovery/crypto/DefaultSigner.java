/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.crypto;

import java.math.BigInteger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.SECP256K1.SecretKey;

/**
 * In-memory {@link Signer} implementation backed by a SECP256K1 {@link SecretKey}.
 *
 * <p>The signer keeps a reference to the {@link SecretKey} and reads it on every private key
 * operation, so {@link SecretKey#destroy()} disables signing and key agreement. The compressed
 * public key is derived once at construction and remains available afterwards.
 */
public class DefaultSigner implements Signer {
  private final SecretKey secretKey;
  private final Bytes compressedPublicKey;

  /**
   * @throws IllegalArgumentException if the secret key is not a valid secp256k1 scalar, i.e. not in
   *     the interval {@code [1, n - 1]}
   */
  public DefaultSigner(final SecretKey secretKey) {
    this.secretKey = secretKey;
    this.compressedPublicKey =
        Secp256k1.compressedPublicKey(Secp256k1.validatePrivateKey(scalar()));
  }

  /** {@inheritDoc} */
  @Override
  public Bytes deriveECDHKeyAgreement(final Bytes peerPublicKey) {
    return Secp256k1.ecdh(scalar(), peerPublicKey);
  }

  /** {@inheritDoc} */
  @Override
  public Bytes sign(final Bytes32 messageHash) {
    return Secp256k1.sign(scalar(), messageHash);
  }

  /** {@inheritDoc} */
  @Override
  public Bytes deriveCompressedPublicKeyFromPrivate() {
    return compressedPublicKey;
  }

  private BigInteger scalar() {
    return secretKey.bytes().toUnsignedBigInteger();
  }
}
