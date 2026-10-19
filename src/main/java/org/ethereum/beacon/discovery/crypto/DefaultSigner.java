/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.crypto;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import java.math.BigInteger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.SECP256K1.SecretKey;

/** In-memory {@link Signer} implementation backed by a SECP256K1 {@link SecretKey}. */
public class DefaultSigner implements Signer {
  private final BigInteger privateKey;
  private final Supplier<Bytes> compressedPublicKey;

  public DefaultSigner(final SecretKey secretKey) {
    this.privateKey = secretKey.bytes().toUnsignedBigInteger();
    this.compressedPublicKey =
        Suppliers.memoize(() -> Secp256k1.compressedPublicKey(this.privateKey));
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
    return compressedPublicKey.get();
  }
}
