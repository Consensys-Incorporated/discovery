/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.ethereum.beacon.discovery.message.handler;

import static com.google.common.base.Preconditions.checkState;

import com.google.common.annotations.VisibleForTesting;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.ethereum.beacon.discovery.schema.NodeRecord;
import org.ethereum.beacon.discovery.storage.LocalNodeRecordStore;

public class DefaultExternalAddressSelector implements ExternalAddressSelector {

  static final int MIN_CONFIRMATIONS = 2;
  static final int MAX_EXTERNAL_ADDRESS_COUNT = 50;
  static final Duration TTL = Duration.ofMinutes(5);

  /**
   * Tracks an estimate of the number of nodes that have reported a particular external address. The
   * number of addresses we keep counts for is limited to avoid peers filling our memory by
   * reporting a large number of different address.
   *
   * <p>The count must never be greater than the number of unique nodes that have reported that
   * address.
   *
   * <p>Also tracks the last time an address is reported so that stale addresses can be removed even
   * if they have accumulated a lot of reports.
   */
  private final Map<InetSocketAddress, ReportData> reportedAddresses = new HashMap<>();

  private final LocalNodeRecordStore localNodeRecordStore;

  public DefaultExternalAddressSelector(final LocalNodeRecordStore localNodeRecordStore) {
    this.localNodeRecordStore = localNodeRecordStore;
  }

  @Override
  public void onExternalAddressReport(
      final Optional<InetSocketAddress> previouslyReportedAddress,
      final InetSocketAddress reportedAddress,
      final Instant reportedTime) {

    previouslyReportedAddress.ifPresent(this::removeVote);
    addVote(reportedAddress, reportedTime);

    removeStaleAddresses(reportedTime);
    limitTrackedAddresses();

    // Select best address per IP family independently to support dual-stack auto-discovery.
    // Without per-family selection, the dominant IP family (usually IPv4) always wins
    // and the other family's ENR fields are never populated.
    selectExternalIPV4Address().ifPresent(this::maybeUpdateAddress);
    selectExternalIPV6Address().ifPresent(this::maybeUpdateAddress);
  }

  private void removeStaleAddresses(final Instant now) {
    final Instant cutOffTime = now.minus(TTL);
    final List<InetSocketAddress> staleAddresses =
        reportedAddresses.entrySet().stream()
            .filter(entry -> entry.getValue().lastReportedBefore(cutOffTime))
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());
    staleAddresses.forEach(reportedAddresses::remove);
  }

  private void limitTrackedAddresses() {
    while (reportedAddresses.size() > MAX_EXTERNAL_ADDRESS_COUNT) {
      // Too many addresses being tracked, remove the one with the fewest votes
      reportedAddresses.entrySet().stream()
          .min(Map.Entry.comparingByValue(Comparator.comparing(ReportData::getLastReportedTime)))
          .map(Map.Entry::getKey)
          .ifPresent(reportedAddresses::remove);
    }
  }

  private void addVote(final InetSocketAddress reportedAddress, final Instant reportTime) {
    reportedAddresses.compute(
        reportedAddress,
        (key, currentValue) ->
            currentValue != null ? currentValue.addReport(reportTime) : new ReportData(reportTime));
  }

  private void removeVote(final InetSocketAddress previousAddress) {
    reportedAddresses.compute(
        previousAddress,
        (key, currentValue) -> currentValue != null ? currentValue.removeReport() : null);
  }

  private void maybeUpdateAddress(final InetSocketAddress selectedAddress) {
    final NodeRecord homeNodeRecord = localNodeRecordStore.getLocalNodeRecord();
    final Optional<InetSocketAddress> currentAddress =
        selectedAddress.getAddress() instanceof Inet6Address
            ? homeNodeRecord.getUdp6Address()
            : homeNodeRecord.getUdpAddress();
    if (currentAddress.map(current -> !current.equals(selectedAddress)).orElse(true)) {
      localNodeRecordStore.onSocketAddressChanged(selectedAddress);
    }
  }

  private Optional<InetSocketAddress> selectExternalIPV4Address() {
    return reportedAddresses.entrySet().stream()
        .filter(entry -> (entry.getKey().getAddress() instanceof Inet4Address))
        .filter(entry -> entry.getValue().getReportCount() >= MIN_CONFIRMATIONS)
        .max(Map.Entry.comparingByValue(Comparator.comparingInt(ReportData::getReportCount)))
        .map(Map.Entry::getKey);
  }

  private Optional<InetSocketAddress> selectExternalIPV6Address() {
    return reportedAddresses.entrySet().stream()
        .filter(entry -> (entry.getKey().getAddress() instanceof Inet6Address))
        .filter(entry -> entry.getValue().getReportCount() >= MIN_CONFIRMATIONS)
        .max(Map.Entry.comparingByValue(Comparator.comparingInt(ReportData::getReportCount)))
        .map(Map.Entry::getKey);
  }

  @VisibleForTesting
  void assertInvariants() {
    checkState(
        reportedAddresses.size() <= MAX_EXTERNAL_ADDRESS_COUNT,
        "Should limit number of tracked addresses. Size %s",
        reportedAddresses.size());
    checkState(
        reportedAddresses.values().stream().noneMatch(data -> data.getReportCount() <= 0),
        "Should not have counts less than 1 (%s)",
        reportedAddresses);
  }

  private static class ReportData {
    private int reportCount;
    private Instant lastReportedTime;

    public ReportData(final Instant time) {
      this.reportCount = 1;
      this.lastReportedTime = time;
    }

    public ReportData addReport(final Instant time) {
      lastReportedTime = time;
      reportCount++;
      return this;
    }

    public ReportData removeReport() {
      reportCount--;
      return reportCount > 0 ? this : null;
    }

    public Instant getLastReportedTime() {
      return lastReportedTime;
    }

    public int getReportCount() {
      return reportCount;
    }

    public boolean lastReportedBefore(final Instant cutOffTime) {
      return lastReportedTime.isBefore(cutOffTime);
    }
  }
}
