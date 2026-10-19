/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.util;

import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.base.Preconditions;
import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import java.math.BigInteger;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.Hash;
import org.apache.tuweni.crypto.SECP256K1;
import org.apache.tuweni.crypto.SECP256K1.KeyPair;
import org.apache.tuweni.crypto.SECP256K1.PublicKey;
import org.apache.tuweni.crypto.SECP256K1.SecretKey;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.ethereum.beacon.discovery.crypto.Secp256k1;
import org.ethereum.beacon.discovery.crypto.Signer;

/** Set of cryptography and utilities functions used in discovery */
public class Functions {
  private static final Logger LOG = LogManager.getLogger();
  public static final int PRIVKEY_SIZE = 32;
  public static final int PUBKEY_SIZE = 64;
  public static final int SIGNATURE_SIZE = 64;
  public static final int COMPRESSED_PUBKEY_SIZE = 33;
  private static final int RECIPIENT_KEY_LENGTH = 16;
  private static final int INITIATOR_KEY_LENGTH = 16;
  private static final int AUTH_RESP_KEY_LENGTH = 16;
  private static final int MS_IN_SECOND = 1000;

  private static final Supplier<SecureRandom> SECURE_RANDOM = Suppliers.memoize(SecureRandom::new);

  static {
    SecurityInitializer.init();
  }

  /** SHA2 (SHA256) */
  public static Bytes32 hash(final Bytes value) {
    return Hashes.sha256(value);
  }

  /** SHA3 (Keccak256) */
  public static Bytes32 hashKeccak(final Bytes value) {
    return Hash.keccak256(value);
  }

  /**
   * Creates a signature of message `x` using the given key.
   *
   * @param secretKey private key
   * @param messageHash message, hashed
   * @return ECDSA signature with properties merged together: r || s
   */
  public static Bytes sign(final SecretKey secretKey, final Bytes32 messageHash) {
    return Secp256k1.sign(secretKey.bytes().toUnsignedBigInteger(), messageHash);
  }

  /**
   * Verifies that signature is made by signer
   *
   * @param signature Signature, ECDSA (r || s parts only, without v, 64 bytes)
   * @param hashedMessage message, hashed
   * @param pubKey Public key of supposed signer, compressed, 33 bytes
   * @return whether `signature` reflects message `x` signed with `pubkey`
   */
  public static boolean verifyECDSASignature(
      final Bytes signature, final Bytes32 hashedMessage, final Bytes pubKey) {
    if (signature.size() != SIGNATURE_SIZE) {
      LOG.trace("Invalid signature size, should be {} bytes", SIGNATURE_SIZE);
      return false;
    }
    Preconditions.checkArgument(
        pubKey.size() == COMPRESSED_PUBKEY_SIZE,
        "Invalid compressed public key size, should be %s bytes",
        COMPRESSED_PUBKEY_SIZE);
    return Secp256k1.verify(signature, hashedMessage, Secp256k1.decodePoint(pubKey));
  }

  public static SECP256K1.KeyPair randomKeyPair() {
    return KeyPair.random();
  }

  public static SECP256K1.KeyPair randomKeyPair(final Random rnd) {
    final byte[] privKeyBytes = new byte[PRIVKEY_SIZE];
    rnd.nextBytes(privKeyBytes);
    return createKeyPairFromSecretBytes(Bytes32.wrap(privKeyBytes));
  }

  /**
   * Maps public key (compressed, uncompressed or uncompressed without prefix) to point on secp256k1
   */
  public static ECPoint publicKeyToPoint(final Bytes pkey) {
    return Secp256k1.decodePoint(pkey);
  }

  public static PublicKey derivePublicKeyFromCompressed(final Bytes pubKey) {
    Preconditions.checkArgument(
        pubKey.size() == COMPRESSED_PUBKEY_SIZE,
        "Invalid compressed public key size, should be %s bytes",
        COMPRESSED_PUBKEY_SIZE);
    final ECPoint ecPoint = Functions.publicKeyToPoint(pubKey);
    final Bytes pubKeyUncompressed = Bytes.wrap(ecPoint.getEncoded(false)).slice(1);
    return PublicKey.fromBytes(pubKeyUncompressed);
  }

  /** Derives public key in SECP256K1, compressed */
  public static Bytes deriveCompressedPublicKeyFromPrivate(final SecretKey secretKey) {
    return Secp256k1.compressedPublicKey(secretKey.bytes().toUnsignedBigInteger());
  }

  /** Derives key agreement ECDH by multiplying private key by public */
  public static Bytes deriveECDHKeyAgreement(final SecretKey srcSecretKey, final Bytes destPubKey) {
    return Secp256k1.ecdh(srcSecretKey.bytes().toUnsignedBigInteger(), destPubKey);
  }

  public static KeyPair createKeyPairFromSecretBytes(final Bytes32 privateKey) {
    final SecretKey secretKey = createSecretKey(privateKey);
    return KeyPair.create(
        secretKey,
        PublicKey.fromBytes(Secp256k1.uncompressedPublicKey(privateKey.toUnsignedBigInteger())));
  }

  public static SecretKey createSecretKey(final Bytes32 privateKey) {
    return SecretKey.fromBytes(privateKey);
  }

  /**
   * The ephemeral key is used to perform Diffie-Hellman key agreement with B's static public key
   * and the session keys are derived from it using the HKDF key derivation function.
   *
   * <p><code>
   * ephemeral-key = random private key
   * ephemeral-pubkey = public key corresponding to ephemeral-key
   * dest-pubkey = public key of B
   * secret = agree(ephemeral-key, dest-pubkey)
   * info = "discovery v5 key agreement" || node-id-A || node-id-B
   * prk = HKDF-Extract(secret, id-nonce)
   * initiator-key, recipient-key, auth-resp-key = HKDF-Expand(prk, info)</code>
   */
  public static HKDFKeys hkdfExpand(
      final Bytes srcNodeId,
      final Bytes destNodeId,
      final SecretKey srcSecretKey,
      final Bytes destPubKey,
      final Bytes idNonce) {
    final Bytes keyAgreement = deriveECDHKeyAgreement(srcSecretKey, destPubKey);
    return hkdfExpand(srcNodeId, destNodeId, keyAgreement, idNonce);
  }

  /**
   * The ephemeral key is used to perform Diffie-Hellman key agreement with B's static public key
   * and the session keys are derived from it using the HKDF key derivation function.
   *
   * <p><code>
   * ephemeral-key = random private key
   * ephemeral-pubkey = public key corresponding to ephemeral-key
   * dest-pubkey = public key of B
   * secret = agree(ephemeral-key, dest-pubkey)
   * info = "discovery v5 key agreement" || node-id-A || node-id-B
   * prk = HKDF-Extract(secret, id-nonce)
   * initiator-key, recipient-key, auth-resp-key = HKDF-Expand(prk, info)</code>
   */
  public static HKDFKeys hkdfExpand(
      final Bytes srcNodeId,
      final Bytes destNodeId,
      final Signer signer,
      final Bytes destPubKey,
      final Bytes idNonce) {
    final Bytes keyAgreement = signer.deriveECDHKeyAgreement(destPubKey);
    return hkdfExpand(srcNodeId, destNodeId, keyAgreement, idNonce);
  }

  /**
   * {@link #hkdfExpand(Bytes, Bytes, Signer, Bytes, Bytes)} but with keyAgreement already derived
   * by {@link #deriveECDHKeyAgreement(SecretKey, Bytes)}
   */
  @SuppressWarnings({"DefaultCharset"})
  public static HKDFKeys hkdfExpand(
      final Bytes srcNodeId,
      final Bytes destNodeId,
      final Bytes keyAgreement,
      final Bytes idNonce) {
    try {
      Bytes info =
          Bytes.concatenate(
              Bytes.wrap("discovery v5 key agreement".getBytes()), srcNodeId, destNodeId);
      HKDFParameters hkdfParameters =
          new HKDFParameters(keyAgreement.toArray(), idNonce.toArray(), info.toArray());
      Digest digest = new SHA256Digest();
      HKDFBytesGenerator hkdfBytesGenerator = new HKDFBytesGenerator(digest);
      hkdfBytesGenerator.init(hkdfParameters);
      // initiator-key || recipient-key || auth-resp-key
      byte[] hkdfOutputBytes =
          new byte[INITIATOR_KEY_LENGTH + RECIPIENT_KEY_LENGTH + AUTH_RESP_KEY_LENGTH];
      hkdfBytesGenerator.generateBytes(
          hkdfOutputBytes, 0, INITIATOR_KEY_LENGTH + RECIPIENT_KEY_LENGTH + AUTH_RESP_KEY_LENGTH);
      Bytes hkdfOutput = Bytes.wrap(hkdfOutputBytes);
      Bytes initiatorKey = hkdfOutput.slice(0, INITIATOR_KEY_LENGTH);
      Bytes recipientKey = hkdfOutput.slice(INITIATOR_KEY_LENGTH, RECIPIENT_KEY_LENGTH);
      Bytes authRespKey = hkdfOutput.slice(INITIATOR_KEY_LENGTH + RECIPIENT_KEY_LENGTH);
      return new HKDFKeys(initiatorKey, recipientKey, authRespKey);
    } catch (Exception ex) {
      throw new RuntimeException(ex);
    }
  }

  /** Current time in seconds */
  public static long getTime() {
    return System.currentTimeMillis() / MS_IN_SECOND;
  }

  /** Random provider */
  public static SecureRandom getRandom() {
    return SECURE_RANDOM.get();
  }

  /**
   * The 'distance' between two node IDs is the bitwise XOR of the IDs, taken as the number.
   *
   * <p>distance(n₁, n₂) = n₁ XOR n₂
   *
   * <p>LogDistance is reverse of length of common prefix in bits (length - number of leftmost zeros
   * in XOR)
   */
  public static int logDistance(final Bytes nodeId1, final Bytes nodeId2) {
    Bytes distance = nodeId1.xor(nodeId2);
    return 256 - distance.numberOfLeadingZeros();
  }

  public static BigInteger distance(final Bytes nodeId1, final Bytes nodeId2) {
    return nodeId1.xor(nodeId2).toUnsignedBigInteger(ByteOrder.LITTLE_ENDIAN);
  }

  /**
   * Stores set of keys derived by simple key derivation function (KDF) based on a hash-based
   * message authentication code (HMAC)
   */
  public static class HKDFKeys {
    private final Bytes initiatorKey;
    private final Bytes recipientKey;
    private final Bytes authResponseKey;

    public HKDFKeys(
        final Bytes initiatorKey, final Bytes recipientKey, final Bytes authResponseKey) {
      this.initiatorKey = initiatorKey;
      this.recipientKey = recipientKey;
      this.authResponseKey = authResponseKey;
    }

    public Bytes getInitiatorKey() {
      return initiatorKey;
    }

    public Bytes getRecipientKey() {
      return recipientKey;
    }

    public Bytes getAuthResponseKey() {
      return authResponseKey;
    }

    @Override
    public boolean equals(final Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      HKDFKeys hkdfKeys = (HKDFKeys) o;
      return Objects.equal(initiatorKey, hkdfKeys.initiatorKey)
          && Objects.equal(recipientKey, hkdfKeys.recipientKey)
          && Objects.equal(authResponseKey, hkdfKeys.authResponseKey);
    }

    @Override
    public int hashCode() {
      return Objects.hashCode(initiatorKey, recipientKey, authResponseKey);
    }

    @Override
    public String toString() {
      return MoreObjects.toStringHelper(this)
          .add("initiatorKey", initiatorKey)
          .add("recipientKey", recipientKey)
          .add("authResponseKey", authResponseKey)
          .toString();
    }
  }
}
