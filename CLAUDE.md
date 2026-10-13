# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Java 21 implementation of the [Ethereum Discovery v5](https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md) peer discovery protocol (discv5). Published to Maven Central as `io.consensys.protocols:discovery:<version>`.

## Build Commands

```bash
# Build (runs spotlessCheck, checkLicenses, compileJava, test)
./gradlew build

# Run all tests
./gradlew test

# Run a single test class
./gradlew test --tests "org.ethereum.beacon.discovery.SomeTest"

# Run a single test method
./gradlew test --tests "org.ethereum.beacon.discovery.SomeTest.methodName"

# Auto-format code (Google Java Format)
./gradlew spotlessApply

# Check formatting without applying
./gradlew spotlessCheck

# Check license headers
./gradlew checkLicenses

# Run the test discovery node
./gradlew runTestDiscovery
```

CI runs `./gradlew --no-daemon --parallel build`.

## Code Style & Quality

- **Formatter**: Spotless with Google Java Format 1.36.1 — run `spotlessApply` before committing.
- **License headers**: Apache 2.0 SPDX header required on all Java files (template: `gradle/java.license`).
- **Compiler**: All warnings treated as errors (`-Werror`). Error-Prone static analysis is enabled.
- **Import order**: `tech.pegasys`, `net.consensys`, `java`, then blank-separated third-party imports.

## Architecture

### Public API

`DiscoverySystem` is the library's single public interface. Consumers create one via `DiscoverySystemBuilder` (fluent builder) and call `start()`/`stop()` for lifecycle, then use:
- `findNodes(NodeRecord, distances)` — DHT-style peer lookup
- `ping(NodeRecord)` — liveness check
- `talk(NodeRecord, protocol, request)` — subprotocol messaging (TALKREQ/TALKRESP)
- `streamLiveNodes()` — active peer stream
- `updateCustomFieldValue()` — update ENR fields

`DiscoverySystemBuilder` wires together all internal components and sets production defaults.

### Internal Layers

```
DiscoverySystem / DiscoverySystemBuilder  ← public API
        │
DiscoveryManager / DiscoveryManagerImpl   ← protocol orchestration
        │
DiscoveryTaskManager                      ← background task scheduling
        │
        ├── pipeline/          Message processing pipeline (handler chain)
        ├── message/handler/   Per-message-type handlers (PING, FINDNODE, …)
        ├── network/           Netty UDP server + traffic rate limiting
        ├── packet/            Packet encode/decode (ordinary, WHOAREYOU, handshake)
        ├── storage/           KBuckets (k=16, XOR-distance DHT routing table)
        ├── schema/            ENR / NodeRecord (EIP-778)
        ├── crypto/            ECDSA signing, ECDH, HKDF, AES-GCM
        ├── liveness/          Periodic ping-based peer health checking
        ├── task/              RecursiveLookupTask, session state machines
        └── scheduler/         Async task execution with expiration
```

### Handshake State Machine

Nodes exchange three packet types during session establishment:

1. **Ordinary** — encrypted application message to an unknown peer triggers…
2. **WHOAREYOU** — challenge packet from the recipient (contains nonce + ENR sequence)
3. **Handshake** — response with static public key, ECDH ephemeral key, and encrypted message; both sides derive session keys via HKDF

Session state is managed in `task/` alongside `NodeSession`. The last WHOAREYOU is retained during retransmissions so it can be resent if needed (see recent fix in commit history).

### Key Dependencies

- **Netty** — UDP transport
- **Tuweni** (ConsenSys) — `Bytes`, RLP encoding, crypto utilities
- **BouncyCastle** — secp256k1 / ECDSA / AES
- **Project Reactor** — reactive streams for `streamLiveNodes()`
- **JUnit 5 + Mockito + AssertJ** — test stack

### Testing Patterns

- `TestManagerWrapper` provides a managed `DiscoveryManager` for integration tests.
- `ControlledSchedulers` lets tests advance time deterministically without real sleeps.
- Integration tests wire real packet encode/decode and message handlers; mock only the network layer.

## Commit Message Convention

Present tense, imperative mood: "Add feature" not "Added feature". Reference issues and PRs where relevant.
