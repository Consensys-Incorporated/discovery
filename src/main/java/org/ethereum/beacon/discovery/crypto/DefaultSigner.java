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
 * <p>The key material is copied at construction time: the signer keeps its own immutable copy of
 * the scalar and the derived public key, so later changes to the {@link SecretKey} (including
 * {@link SecretKey#destroy()}) do not affect it.
 */
public class DefaultSigner implements Signer {
  private final BigInteger privateKey;
  private final Bytes compressedPublicKey;

  /**
   * @throws IllegalArgumentException if the secret key is not a valid secp256k1 scalar, i.e. not in
   *     the interval {@code [1, n - 1]}
   */
  public DefaultSigner(final SecretKey secretKey) {
    this.privateKey = Secp256k1.validatePrivateKey(secretKey.bytes().toUnsignedBigInteger());
    this.compressedPublicKey = Secp256k1.compressedPublicKey(privateKey);
  }

  /** {@inheritDoc} */
  @Override
  public Bytes deriveECDHKeyAgreement(final Bytes peerPublicKey) {
    return Secp256k1.ecdh(privateKey, peerPublicKey);
  }

  /** {@inheritDoc} */
  @Override
  public Bytes sign(final Bytes32 messageHash) {
    return Secp256k1.sign(privateKey, messageHash);
  }

  /** {@inheritDoc} */
  @Override
  public Bytes deriveCompressedPublicKeyFromPrivate() {
    return compressedPublicKey;
  }
}
