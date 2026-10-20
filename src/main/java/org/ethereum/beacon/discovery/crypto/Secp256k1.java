/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.crypto;

import java.math.BigInteger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.BigIntegers;

/**
 * secp256k1 primitives used by discovery.
 *
 * <p>Built on BouncyCastle's dedicated secp256k1 curve ({@link CustomNamedCurves}), which uses
 * fixed-size field arithmetic and the GLV endomorphism. Results are identical to tuweni's {@code
 * SECP256K1}, which is based on the generic {@code BigInteger} curve and is several times slower
 * and allocation heavy.
 */
public final class Secp256k1 {
  private static final X9ECParameters PARAMETERS = CustomNamedCurves.getByName("secp256k1");
  private static final ECDomainParameters DOMAIN = new ECDomainParameters(PARAMETERS);

  private static final BigInteger HALF_CURVE_ORDER = DOMAIN.getN().shiftRight(1);
  private static final int SCALAR_SIZE = 32;
  private static final int SIGNATURE_SIZE = 2 * SCALAR_SIZE;
  private static final int RAW_PUBLIC_KEY_SIZE = 2 * SCALAR_SIZE;
  private static final byte UNCOMPRESSED_PREFIX = 0x04;

  private Secp256k1() {}

  /**
   * Decodes a public key: SEC1 compressed (33 bytes), SEC1 uncompressed (65 bytes) or raw
   * uncompressed {@code x || y} without prefix (64 bytes).
   *
   * @throws IllegalArgumentException if the encoding is invalid or the point is not on the curve
   */
  public static ECPoint decodePoint(final Bytes publicKey) {
    final byte[] encoded;
    if (publicKey.size() == RAW_PUBLIC_KEY_SIZE) {
      encoded = new byte[RAW_PUBLIC_KEY_SIZE + 1];
      encoded[0] = UNCOMPRESSED_PREFIX;
      System.arraycopy(publicKey.toArrayUnsafe(), 0, encoded, 1, RAW_PUBLIC_KEY_SIZE);
    } else {
      encoded = publicKey.toArrayUnsafe();
    }
    return DOMAIN.getCurve().decodePoint(encoded);
  }

  /**
   * Checks that the scalar is a valid private key, i.e. in the interval {@code [1, n - 1]}.
   *
   * @return the scalar
   * @throws IllegalArgumentException if it is not
   */
  public static BigInteger validatePrivateKey(final BigInteger privateKey) {
    return DOMAIN.validatePrivateScalar(privateKey);
  }

  /** Public key point of the given private key. */
  public static ECPoint publicKeyPoint(final BigInteger privateKey) {
    return new FixedPointCombMultiplier().multiply(DOMAIN.getG(), privateKey).normalize();
  }

  /** SEC1 compressed public key (33 bytes) of the given private key. */
  public static Bytes compressedPublicKey(final BigInteger privateKey) {
    return Bytes.wrap(publicKeyPoint(privateKey).getEncoded(true));
  }

  /** Raw uncompressed public key {@code x || y} (64 bytes) of the given private key. */
  public static Bytes uncompressedPublicKey(final BigInteger privateKey) {
    return Bytes.wrap(publicKeyPoint(privateKey).getEncoded(false)).slice(1);
  }

  /**
   * Deterministic (RFC 6979) ECDSA signature with low S.
   *
   * @return {@code r || s}, 64 bytes
   */
  public static Bytes sign(final BigInteger privateKey, final Bytes32 messageHash) {
    final ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
    signer.init(true, new ECPrivateKeyParameters(privateKey, DOMAIN));
    final BigInteger[] components = signer.generateSignature(messageHash.toArrayUnsafe());
    final BigInteger r = components[0];
    BigInteger s = components[1];
    if (s.compareTo(HALF_CURVE_ORDER) > 0) {
      s = DOMAIN.getN().subtract(s);
    }
    final byte[] signature = new byte[SIGNATURE_SIZE];
    BigIntegers.asUnsignedByteArray(r, signature, 0, SCALAR_SIZE);
    BigIntegers.asUnsignedByteArray(s, signature, SCALAR_SIZE, SCALAR_SIZE);
    return Bytes.wrap(signature);
  }

  /**
   * Verifies an ECDSA signature. Like tuweni's {@code SECP256K1.verifyHashed}, both low and high S
   * values are accepted.
   *
   * @param signature {@code r || s}, 64 bytes
   */
  public static boolean verify(
      final Bytes signature, final Bytes32 messageHash, final ECPoint publicKey) {
    if (signature.size() != SIGNATURE_SIZE) {
      return false;
    }
    final BigInteger r = signature.slice(0, SCALAR_SIZE).toUnsignedBigInteger();
    final BigInteger s = signature.slice(SCALAR_SIZE, SCALAR_SIZE).toUnsignedBigInteger();
    final ECDSASigner signer = new ECDSASigner();
    signer.init(false, new ECPublicKeyParameters(publicKey, DOMAIN));
    return signer.verifySignature(messageHash.toArrayUnsafe(), r, s);
  }

  /**
   * ECDH key agreement: the SEC1 compressed encoding of {@code privateKey * peerPublicKey}.
   *
   * @param peerPublicKey any encoding accepted by {@link #decodePoint(Bytes)}
   */
  public static Bytes ecdh(final BigInteger privateKey, final Bytes peerPublicKey) {
    return Bytes.wrap(decodePoint(peerPublicKey).multiply(privateKey).getEncoded(true));
  }
}
