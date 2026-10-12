/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery;

import static org.ethereum.beacon.discovery.TestUtil.SEED;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Random;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.SECP256K1.KeyPair;
import org.apache.tuweni.units.bigints.UInt64;
import org.ethereum.beacon.discovery.crypto.DefaultSigner;
import org.ethereum.beacon.discovery.schema.EnrField;
import org.ethereum.beacon.discovery.schema.IdentitySchema;
import org.ethereum.beacon.discovery.schema.IdentitySchemaInterpreter;
import org.ethereum.beacon.discovery.schema.IdentitySchemaV4Interpreter;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.schema.NodeRecordBuilder;
import org.ethereum.beacon.discovery.schema.NodeRecordFactory;
import org.ethereum.beacon.discovery.util.Functions;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * ENR serialization/deserialization test
 *
 * <p>ENR - Ethereum Node Record, according to <a
 * href="https://eips.ethereum.org/EIPS/eip-778">https://eips.ethereum.org/EIPS/eip-778</a>
 */
public class NodeRecordTest {
  private static final NodeRecordFactory NODE_RECORD_FACTORY = NodeRecordFactory.DEFAULT;

  @Test
  public void testLocalhostV4() throws Exception {
    final String expectedHost = "127.0.0.1";
    final Integer expectedUdpPort = 30303;
    final UInt64 expectedSeqNumber = UInt64.valueOf(1);
    final Bytes expectedPublicKey =
        Bytes.fromHexString("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138");
    final Bytes expectedSignature =
        Bytes.fromHexString(
            "7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c");

    final String localhostEnr =
        "-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";
    NodeRecord nodeRecord = NODE_RECORD_FACTORY.fromBase64(localhostEnr);

    assertEquals(IdentitySchema.V4, nodeRecord.getIdentityScheme());
    assertArrayEquals(
        InetAddress.getByName(expectedHost).getAddress(),
        ((Bytes) nodeRecord.get(EnrField.IP_V4)).toArray());
    assertEquals(expectedUdpPort, nodeRecord.get(EnrField.UDP));
    //    assertEquals(expectedTcpPort, nodeRecord.get(EnrField.TCP_V4));
    assertEquals(expectedSeqNumber, nodeRecord.getSeq());
    assertEquals(expectedPublicKey, nodeRecord.get(EnrField.PKEY_SECP256K1));
    assertEquals(expectedSignature, nodeRecord.getSignature());

    String localhostEnrRestored = nodeRecord.asBase64();
    // The order of fields is not strict so we don't compare strings
    NodeRecord nodeRecordRestored = NODE_RECORD_FACTORY.fromBase64(localhostEnrRestored);

    assertEquals(IdentitySchema.V4, nodeRecordRestored.getIdentityScheme());
    assertArrayEquals(
        InetAddress.getByName(expectedHost).getAddress(),
        ((Bytes) nodeRecordRestored.get(EnrField.IP_V4)).toArray());
    assertEquals(expectedUdpPort, nodeRecordRestored.get(EnrField.UDP));
    //    assertEquals(expectedTcpPort, nodeRecordRestored.get(EnrField.TCP_V4));
    assertEquals(expectedSeqNumber, nodeRecordRestored.getSeq());
    assertEquals(expectedPublicKey, nodeRecordRestored.get(EnrField.PKEY_SECP256K1));
    assertEquals(expectedSignature, nodeRecordRestored.getSignature());
  }

  @Test
  public void testEnrWithCustomFieldsDecodes() {
    final int port = 30303;
    final Bytes ip = Bytes.fromHexString("0x7F000001");
    final Bytes nodeId =
        Bytes.fromHexString("a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7");
    final KeyPair keyPair =
        Functions.createKeyPairFromSecretBytes(
            Bytes32.fromHexString(
                "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"));
    final NodeRecord record =
        NODE_RECORD_FACTORY.createFromValues(
            UInt64.ONE,
            new EnrField(EnrField.ID, IdentitySchema.V4),
            new EnrField(EnrField.PKEY_SECP256K1, nodeId),
            new EnrField(EnrField.IP_V4, ip),
            new EnrField(EnrField.TCP, port),
            new EnrField("foo", Bytes.fromHexString("0x1234")));
    record.sign(new DefaultSigner(keyPair.secretKey()));
    final String serialized = record.asBase64();
    final NodeRecord result = NODE_RECORD_FACTORY.fromBase64(serialized);
    assertEquals(record, result);
  }

  @Test
  public void testSignature() {
    Random rnd = new Random(SEED);
    KeyPair keyPair = Functions.randomKeyPair(rnd);
    NodeRecord nodeRecord0 =
        new NodeRecordBuilder()
            .seq(0)
            .address("127.0.0.1", 30303)
            .signer(new DefaultSigner(keyPair.secretKey()))
            .build();
    assertTrue(nodeRecord0.isValid());
    NodeRecord nodeRecord1 =
        new NodeRecordBuilder()
            .seq(1)
            .address("127.0.0.1", 30303)
            .signer(new DefaultSigner(keyPair.secretKey()))
            .build();
    assertTrue(nodeRecord1.isValid());
    assertNotEquals(nodeRecord0.serialize(), nodeRecord1.serialize());
    assertNotEquals(nodeRecord0.getSignature(), nodeRecord1.getSignature());
    nodeRecord1.setSignature(nodeRecord0.getSignature());
    assertFalse(nodeRecord1.isValid());
  }

  @Test
  public void shouldBuildRecordWithoutTcpPort() {
    Random rnd = new Random(SEED);
    KeyPair keyPair = Functions.randomKeyPair(rnd);
    NodeRecord nodeRecord =
        new NodeRecordBuilder()
            .seq(0)
            .address("127.0.0.1", 30303, Optional.empty(), Optional.empty())
            .signer(new DefaultSigner(keyPair.secretKey()))
            .build();
    assertTrue(nodeRecord.isValid());
    assertTrue(nodeRecord.containsKey(EnrField.IP_V4));
    assertTrue(nodeRecord.containsKey(EnrField.UDP));
    assertFalse(nodeRecord.containsKey(EnrField.TCP));
    assertFalse(nodeRecord.containsKey(EnrField.QUIC));
    assertEquals(
        Optional.of(new InetSocketAddress("127.0.0.1", 30303)), nodeRecord.getUdpAddress());
    assertEquals(Optional.empty(), nodeRecord.getTcpAddress());
    assertEquals(Optional.empty(), nodeRecord.getQuicAddress());
  }

  @Test
  public void shouldBuildIpV6RecordWithoutTcpPort() {
    Random rnd = new Random(SEED);
    KeyPair keyPair = Functions.randomKeyPair(rnd);
    NodeRecord nodeRecord =
        new NodeRecordBuilder()
            .seq(0)
            .address("::1", 30303, Optional.empty(), Optional.empty())
            .signer(new DefaultSigner(keyPair.secretKey()))
            .build();
    assertTrue(nodeRecord.isValid());
    assertTrue(nodeRecord.containsKey(EnrField.IP_V6));
    assertTrue(nodeRecord.containsKey(EnrField.UDP_V6));
    assertFalse(nodeRecord.containsKey(EnrField.TCP_V6));
    assertFalse(nodeRecord.containsKey(EnrField.QUIC_V6));
    assertEquals(Optional.of(new InetSocketAddress("::1", 30303)), nodeRecord.getUdp6Address());
    assertEquals(Optional.empty(), nodeRecord.getTcp6Address());
    assertEquals(Optional.empty(), nodeRecord.getQuic6Address());
  }

  @Test
  public void shouldBuildRecordWithOnlyQuicPort() {
    Random rnd = new Random(SEED);
    KeyPair keyPair = Functions.randomKeyPair(rnd);
    NodeRecord nodeRecord =
        new NodeRecordBuilder()
            .seq(0)
            .address("127.0.0.1", 30303, Optional.empty(), Optional.of(9001))
            .signer(new DefaultSigner(keyPair.secretKey()))
            .build();
    assertTrue(nodeRecord.isValid());
    assertFalse(nodeRecord.containsKey(EnrField.TCP));
    assertEquals(9001, nodeRecord.get(EnrField.QUIC));
    assertEquals(
        Optional.of(new InetSocketAddress("127.0.0.1", 9001)), nodeRecord.getQuicAddress());
    assertEquals(Optional.empty(), nodeRecord.getTcpAddress());

    // round-trips through serialization
    NodeRecord decoded = NODE_RECORD_FACTORY.fromBytes(nodeRecord.serialize());
    assertTrue(decoded.isValid());
    assertEquals(nodeRecord.getQuicAddress(), decoded.getQuicAddress());
    assertEquals(Optional.empty(), decoded.getTcpAddress());
  }

  @Test
  public void shouldBuildIpV6RecordWithOnlyQuicPort() {
    Random rnd = new Random(SEED);
    KeyPair keyPair = Functions.randomKeyPair(rnd);
    NodeRecord nodeRecord =
        new NodeRecordBuilder()
            .seq(0)
            .address("::1", 30303, Optional.empty(), Optional.of(9001))
            .signer(new DefaultSigner(keyPair.secretKey()))
            .build();
    assertTrue(nodeRecord.isValid());
    assertFalse(nodeRecord.containsKey(EnrField.TCP_V6));
    assertEquals(Optional.of(new InetSocketAddress("::1", 9001)), nodeRecord.getQuic6Address());
    assertEquals(Optional.empty(), nodeRecord.getTcp6Address());
  }

  @Test
  public void existingAddressOverloadsShouldMatchOptionalOverload() {
    Random rnd = new Random(SEED);
    KeyPair keyPair = Functions.randomKeyPair(rnd);
    DefaultSigner signer = new DefaultSigner(keyPair.secretKey());

    NodeRecord viaInt =
        new NodeRecordBuilder().seq(0).address("127.0.0.1", 30303, 30304).signer(signer).build();
    NodeRecord viaOptional =
        new NodeRecordBuilder()
            .seq(0)
            .address("127.0.0.1", 30303, Optional.of(30304), Optional.empty())
            .signer(signer)
            .build();
    assertEquals(viaInt.serialize(), viaOptional.serialize());

    NodeRecord viaIntWithQuic =
        new NodeRecordBuilder()
            .seq(0)
            .address("127.0.0.1", 30303, 30304, 9001)
            .signer(signer)
            .build();
    NodeRecord viaOptionalWithQuic =
        new NodeRecordBuilder()
            .seq(0)
            .address("127.0.0.1", 30303, Optional.of(30304), Optional.of(9001))
            .signer(signer)
            .build();
    assertEquals(viaIntWithQuic.serialize(), viaOptionalWithQuic.serialize());
  }

  @Test
  public void testCustomField() {
    Random rnd = new Random(SEED);
    KeyPair keyPair = Functions.randomKeyPair(rnd);
    final String customFieldName = "custom_field_name";
    final Bytes customFieldValue = Bytes.fromHexString("0xdeadbeef");
    NodeRecord nodeRecord =
        new NodeRecordBuilder()
            .seq(0)
            .address("127.0.0.1", 30303)
            .signer(new DefaultSigner(keyPair.secretKey()))
            .customField(customFieldName, customFieldValue)
            .build();
    assertTrue(nodeRecord.isValid());
    assertEquals(nodeRecord.get(customFieldName), customFieldValue);
  }

  @Test
  public void shouldNotIncludePaddingInBase64() {
    final int port = 30303;
    final Bytes ip = Bytes.fromHexString("0x7F000001");
    final Bytes nodeId =
        Bytes.fromHexString("a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7");
    final KeyPair keyPair =
        Functions.createKeyPairFromSecretBytes(
            Bytes32.fromHexString(
                "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"));
    final int seq = 1;

    NodeRecord nodeRecord =
        new NodeRecordFactory(new IdentitySchemaV4Interpreter())
            .createFromValues(
                UInt64.valueOf(seq),
                new EnrField(EnrField.ID, IdentitySchema.V4),
                new EnrField(EnrField.IP_V4, ip),
                new EnrField(EnrField.UDP, port),
                new EnrField(
                    EnrField.PKEY_SECP256K1,
                    Functions.deriveCompressedPublicKeyFromPrivate(keyPair.secretKey())));
    nodeRecord.sign(new DefaultSigner(keyPair.secretKey()));
    assertEquals(nodeId, nodeRecord.getNodeId());
    assertEquals(
        "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8",
        nodeRecord.asEnr());
  }

  @Test
  public void shouldDecodeEnr() {
    final NodeRecordFactory nodeRecordFactory =
        new NodeRecordFactory(new IdentitySchemaV4Interpreter());
    final NodeRecord nodeRecord =
        nodeRecordFactory.fromEnr(
            "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8");
    final Bytes nodeId =
        Bytes.fromHexString("a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7");
    assertEquals(nodeId, nodeRecord.getNodeId());
    assertEquals(UInt64.valueOf(1), nodeRecord.getSeq());
    assertEquals(
        Bytes.fromHexString("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138"),
        nodeRecord.get(EnrField.PKEY_SECP256K1));
    assertEquals(Bytes.fromHexString("0x7F000001"), nodeRecord.get(EnrField.IP_V4));
    assertEquals(30303, nodeRecord.get(EnrField.UDP));
  }

  @Test
  public void shouldDecodeEnr_WithOrWithoutPrefix() {
    final NodeRecordFactory nodeRecordFactory =
        new NodeRecordFactory(new IdentitySchemaV4Interpreter());
    final String base64 =
        "-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";
    final NodeRecord nodeRecordWithoutPrefix = nodeRecordFactory.fromEnr(base64);
    final NodeRecord nodeRecordWithPrefix = nodeRecordFactory.fromEnr("enr:" + base64);
    assertEquals(nodeRecordWithoutPrefix, nodeRecordWithPrefix);
  }

  @Test
  public void testEnrWithEthFieldDecodes() {
    final int port = 30303;
    final Bytes ip = Bytes.fromHexString("0x7F000001");
    final KeyPair keyPair =
        Functions.createKeyPairFromSecretBytes(
            Bytes32.fromHexString(
                "b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291"));

    final List<Bytes> forkIdList = new ArrayList<>();
    forkIdList.add(Bytes.fromHexString("0x7a739ef1"));
    forkIdList.add(Bytes.fromHexString("0x"));

    final NodeRecord record =
        NODE_RECORD_FACTORY.createFromValues(
            UInt64.ONE,
            new EnrField(EnrField.ID, IdentitySchema.V4),
            new EnrField(
                EnrField.PKEY_SECP256K1,
                Functions.deriveCompressedPublicKeyFromPrivate(keyPair.secretKey())),
            new EnrField(EnrField.IP_V4, ip),
            new EnrField(EnrField.TCP, port),
            new EnrField("eth", Collections.singletonList(forkIdList)));
    record.sign(new DefaultSigner(keyPair.secretKey()));

    final String serialized = record.asBase64();
    final NodeRecord result = NODE_RECORD_FACTORY.fromBase64(serialized);
    assertEquals(record, result);
    String expectedEnr =
        "enr:-JC4QBF-k6ezIoeB4BTMx9sLpFmcTZT4nBGUZLJ0JeYlT_rtfpVIa02sdfJwjUcXCb1h_HwGUtgPwwz2cbJiyAP4wT4Bg2V0aMfGhHpznvGAgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN0Y3CCdl8";
    assertEquals(expectedEnr, result.asEnr());
    final NodeRecord nodeRecord = NODE_RECORD_FACTORY.fromEnr(result.asEnr());
    assertTrue(nodeRecord.isValid());
    assertEquals(Collections.singletonList(forkIdList), nodeRecord.get("eth"));
    assertEquals(result, nodeRecord);
  }

  @Test
  void testEnrWithValidEthFieldDecodes() {
    final String enr =
        "enr:-KK4QH0RsNJmIG0EX9LSnVxMvg-CAOr3ZFF92hunU63uE7wcYBjG1cFbUTvEa5G_4nDJkRhUq9q2ck9xY-VX1RtBsruBtIRldGgykIL0pysBABAg__________-CaWSCdjSCaXCEEnXQ0YlzZWNwMjU2azGhA1grTzOdMgBvjNrk-vqWtTZsYQIi0QawrhoZrsn5Hd56g3RjcIIjKIN1ZHCCIyg";
    final NodeRecord nodeRecord = NODE_RECORD_FACTORY.fromEnr(enr);
    assertEquals(enr, nodeRecord.asEnr());
    assertEquals(Bytes.fromHexString("0x82f4a72b01001020ffffffffffffffff"), nodeRecord.get("eth2"));
  }

  @Test
  void shouldDecodeEnr_withQuicField() {
    final String enr =
        "enr:-MS4QEyTlybz9KMHKN7pXHOvlD8Q1muUXN7mbeUCPjSyKOEYScKDpmkaxxuE8DOC-YlCIqweCQpEw8uLG4s4z0huDAEUh2F0dG5ldHOIAAAAAAAGAACEZXRoMpBprg6ZBQFwAP__________gmlkgnY0gmlwhIjzqrKEcXVpY4IjKYlzZWNwMjU2azGhA-tFvPZaDfibme3y3o9xderqssFhY1Pnjw6AwqwreQz7iHN5bmNuZXRzAIN0Y3CCIyiDdWRwgiMo";

    final NodeRecord nodeRecord = NODE_RECORD_FACTORY.fromEnr(enr);
    assertEquals(enr, nodeRecord.asEnr());
    assertEquals(9001, nodeRecord.get(EnrField.QUIC));
  }

  @Test
  public void testNodeRecordConstructorFailsToConstructOver300Bytes() {
    Assertions.assertThrows(
        IllegalArgumentException.class,
        () ->
            NodeRecord.fromValues(
                IdentitySchemaInterpreter.V4,
                UInt64.ONE,
                List.of(new EnrField("test", Bytes.repeat((byte) 0xFF, 300)))));
  }
}
