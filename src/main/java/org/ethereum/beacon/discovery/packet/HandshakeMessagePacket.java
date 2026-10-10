/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.packet;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.ethereum.beacon.discovery.crypto.Signer;
import org.ethereum.beacon.discovery.message.V5Message;
import org.ethereum.beacon.discovery.packet.HandshakeMessagePacket.HandshakeAuthData;
import org.ethereum.beacon.discovery.packet.impl.HandshakeMessagePacketImpl;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;
import org.ethereum.beacon.discovery.type.Bytes16;
import org.ethereum.beacon.discovery.util.CryptoUtil;
import org.ethereum.beacon.discovery.util.DecodeException;
import org.ethereum.beacon.discovery.util.Functions;

/**
 * Handshake packet
 *
 * <p>For handshake message packets, the authdata section has variable size since public key and
 * signature sizes depend on the ENR identity scheme. For the "v4" identity scheme, we assume
 * 64-byte signature size and 33 bytes of (compressed) public key size.
 *
 * <p>authdata starts with a fixed-size authdata-head component, followed by the ID signature,
 * ephemeral public key and optional node record.
 *
 * <p>The record field may be omitted if the enr-seq of WHOAREYOU is recent enough, i.e. when it
 * matches the current sequence number of the sending node. If enr-seq is zero, the record must be
 * sent. Node records are encoded and verified as specified in EIP-778.
 *
 * <p>Please refer to the handshake section for more information about the content of the handshake
 * packet.
 *
 * <p>authdata = authdata-head || id-signature || eph-pubkey || record authdata-head = src-id ||
 * sig-size || eph-key-size authdata-size = 34 + sig-size + eph-key-size + len(record) sig-size =
 * uint8 -- value: 64 for ID scheme "v4" eph-key-size = uint8 -- value: 33 for ID scheme "v4"
 */
public interface HandshakeMessagePacket extends MessagePacket<HandshakeAuthData> {

  Bytes ID_SIGNATURE_PREFIX =
      Bytes.wrap("discovery v5 identity proof".getBytes(StandardCharsets.US_ASCII));
  byte HANDSHAKE_VERSION = 1;

  static HandshakeMessagePacket create(
      Bytes16 maskingIV, Header<HandshakeAuthData> header, V5Message message, Bytes gcmKey) {
    return new HandshakeMessagePacketImpl(maskingIV, header, message, gcmKey);
  }

  interface HandshakeAuthData extends AuthData {

    /**
     * <pre>
     * id-signature-text  = "discovery v5 identity proof"
     * id-signature-input = id-signature-text || challenge-data || ephemeral-pubkey || node-id-B
     * id-signature       = id_sign(sha256(id-signature-input))
     * </pre>
     */
    static Bytes signId(
        final Bytes challengeData,
        final Bytes ephemeralPubKey,
        final Bytes32 destNodeId,
        final Signer signer) {

      Bytes32 idSignatureInput =
          CryptoUtil.sha256(
              Bytes.wrap(ID_SIGNATURE_PREFIX, challengeData, ephemeralPubKey, destNodeId));
      return signer.sign(idSignatureInput);
    }

    Bytes32 getSourceNodeId();

    Bytes getIdSignature();

    Bytes getEphemeralPubKey();

    Optional<NodeRecord> getNodeRecord(final NodeRecordFactory nodeRecordFactory);

    default boolean verify(
        final Bytes challengeData, final Bytes32 homeNodeId, final Bytes remotePublicKey) {
      final Bytes32 idSignatureInput =
          CryptoUtil.sha256(
              Bytes.wrap(ID_SIGNATURE_PREFIX, challengeData, getEphemeralPubKey(), homeNodeId));
      return Functions.verifyECDSASignature(getIdSignature(), idSignatureInput, remotePublicKey);
    }

    @Override
    default void validate() throws DecodeException {
      DecodeException.wrap(
          () -> "Couldn't decode Handshake auth data: " + getBytes(),
          () -> {
            getSourceNodeId();
            getIdSignature();
            getEphemeralPubKey();
          });
    }
  }
}
