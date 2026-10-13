/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery;

import static org.assertj.core.api.Assertions.assertThat;
import static org.ethereum.beacon.discovery.util.Functions.PUBKEY_SIZE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.StandardProtocolFamily;
import java.time.Duration;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.crypto.SECP256K1.KeyPair;
import org.ethereum.beacon.discovery.util.Functions;
import org.ethereum.beacon.discovery.util.Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Sinks;

public class UtilsTests {
  /**
   * Tests BigInteger to byte[]. Take a look at {@link
   * Utils#extractBytesFromUnsignedBigInt(BigInteger, int)} for understanding the issue.
   */
  @Test
  public void testPubKeyBadPrefix() {
    Bytes32 privKey =
        Bytes32.fromHexString("0xade78b68f25611ea57532f86bf01da909cc463465ed9efce9395403ff7fc99b5");
    KeyPair badKey = Functions.createKeyPairFromSecretBytes(privKey);
    // Straightforward way to notice the issue
    byte[] badPubKey = badKey.publicKey().bytes().toUnsignedBigInteger().toByteArray();
    byte[] goodPubKey =
        Utils.extractBytesFromUnsignedBigInt(
            badKey.publicKey().bytes().toUnsignedBigInteger(), PUBKEY_SIZE);
    Assertions.assertEquals(65, badPubKey.length);
    Assertions.assertEquals(64, goodPubKey.length);
  }

  @Test
  public void emitNextWithRetry_shouldReturnOkWithoutRetryingWhenEmitSucceeds() {
    final Sinks.Many<String> sink = mockSink();
    when(sink.tryEmitNext(any())).thenReturn(Sinks.EmitResult.OK);

    final Sinks.EmitResult result = Utils.emitNextWithRetry(sink, "a", Duration.ofMillis(20));

    assertThat(result).isEqualTo(Sinks.EmitResult.OK);
    verify(sink, times(1)).tryEmitNext("a");
  }

  @Test
  public void emitNextWithRetry_shouldRetryOnFailNonSerialized() {
    final Sinks.Many<String> sink = mockSink();
    when(sink.tryEmitNext(any()))
        .thenReturn(Sinks.EmitResult.FAIL_NON_SERIALIZED)
        .thenReturn(Sinks.EmitResult.FAIL_NON_SERIALIZED)
        .thenReturn(Sinks.EmitResult.OK);

    final Sinks.EmitResult result = Utils.emitNextWithRetry(sink, "a", Duration.ofSeconds(1));

    assertThat(result).isEqualTo(Sinks.EmitResult.OK);
    verify(sink, times(3)).tryEmitNext("a");
  }

  @Test
  public void emitNextWithRetry_shouldNotRetryOnOtherFailures() {
    final Sinks.Many<String> sink = mockSink();
    when(sink.tryEmitNext(any())).thenReturn(Sinks.EmitResult.FAIL_TERMINATED);

    final Sinks.EmitResult result = Utils.emitNextWithRetry(sink, "a", Duration.ofSeconds(1));

    assertThat(result).isEqualTo(Sinks.EmitResult.FAIL_TERMINATED);
    verify(sink, times(1)).tryEmitNext("a");
  }

  @Test
  public void emitNextWithRetry_shouldGiveUpAfterTimeout() {
    final Sinks.Many<String> sink = mockSink();
    when(sink.tryEmitNext(any())).thenReturn(Sinks.EmitResult.FAIL_NON_SERIALIZED);

    final Sinks.EmitResult result = Utils.emitNextWithRetry(sink, "a", Duration.ofMillis(20));

    assertThat(result).isEqualTo(Sinks.EmitResult.FAIL_NON_SERIALIZED);
    verify(sink, atLeast(2)).tryEmitNext("a");
  }

  @Test
  public void protocolFamilyOf_shouldDistinguishIpv4AndIpv6() throws Exception {
    assertThat(Utils.protocolFamilyOf(InetAddress.getByName("127.0.0.1")))
        .isEqualTo(StandardProtocolFamily.INET);
    assertThat(Utils.protocolFamilyOf(InetAddress.getByName("::1")))
        .isEqualTo(StandardProtocolFamily.INET6);
  }

  @SuppressWarnings("unchecked")
  private static Sinks.Many<String> mockSink() {
    return (Sinks.Many<String>) mock(Sinks.Many.class);
  }
}
