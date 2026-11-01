# Dolly

**A messenger with no server.** Two phones talk directly to each other over the internet, end-to-end
encrypted. The only storage is the two devices themselves, and the only third parties involved are
public STUN servers that learn nothing but an IP address.

> **Status: early.** The cryptographic and networking core is built and tested on both iOS and
> Android stacks. There is no app yet, and the code has **not been independently audited**. Don't use
> it to protect anything that matters until it has been.

## How it works

```
 Alice                                                          Bob
   │  1. ask a STUN server "what's my public IP:port?"            │
   │  2. build a signed ticket (keys + address), share it         │
   │     out of band: QR code, or a text via RCS/SMS              │
   │ ◄──────────────────── tickets exchanged ──────────────────► │
   │  3. both derive the same secret from the two tickets         │
   │  4. both send UDP packets at each other at the same time     │
   │     (hole punching) to open their NATs                       │
   │ ◄═══════ encrypted, authenticated UDP, direct ═══════════► │
```

- **No server of ours.** There is no account, no message store and no relay. If the other person is
  offline the message does not send, and the app says so.
- **Encryption.** Tickets are signed with Ed25519. A handshake of X25519 key exchanges gives mutual
  authentication and forward secrecy, then a Double Ratchet (ChaCha20-Poly1305, HKDF-SHA256) gives
  fresh keys for every message, as in Signal.
- **No dependencies.** Only the platform's own crypto and networking: CryptoKit and POSIX sockets on
  iOS/macOS, the JDK/Android crypto and `java.net` on Android. No packages in the shipped code.
- **No compression.** Messages are padded to fixed sizes (256, 512 or 1024 bytes) to hide their length.
- **RCS fits as a courier, not a transport.** Neither OS lets third-party apps send RCS, so the ticket
  is handed over through whatever messaging app the user already has.

## What's here

| Path | What it is |
|---|---|
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md) | Tickets, handshake, Double Ratchet, packet format |
| [`docs/TRANSPORT.md`](docs/TRANSPORT.md) | STUN, hole punching, reliable delivery, chunking, failure handling |
| `core-swift/` | iOS/macOS core: Swift package `DollyCore` and the `dolly-selftest` checks |
| `core-kotlin/` | Android/JVM core: Kotlin library and tests |
| `test-vectors/` | Shared conformance vectors. Swift writes them, Kotlin must reproduce them byte for byte |

Both implementations are tested against each other, so an iPhone and an Android phone can talk. The
two share nothing but the spec and these vectors.

## Build and test

You need Swift 5.9+ (Command Line Tools are enough; Xcode is not required) and JDK 17+ with Gradle.

```sh
# Swift: unit checks, loss/reorder simulation, and replay of the shared vectors
cd core-swift
swift run dolly-selftest

# Optional: real-network checks
swift run dolly-selftest --loopback     # two real UDP sockets on this machine
swift run dolly-selftest --live-stun    # ask Google/Cloudflare STUN; reports your NAT type

# Kotlin: unit tests, simulation, and replay of the same vectors
cd ../core-kotlin
gradle test
```

Regenerating the vectors is only for deliberate wire-format changes, and must be done on the Swift
side first, then both suites re-run:

```sh
cd core-swift && swift run dolly-selftest --write-vectors
```

## Try it: chat in the terminal

A command-line chat exists in both languages. It is the quickest way to test a real connection between
two machines (or two networks), and a preview of how the apps will work.

```sh
# Swift
cd core-swift && swift run dolly

# Kotlin (JDK 17+)
cd core-kotlin && gradle -q --console=plain run
```

1. Each side prints a **ticket** (a long line of text) and its key **fingerprint**.
2. Send your ticket to the other person by any channel: text, RCS, email, chat.
3. Paste theirs into your terminal within a minute or so, and keep both running.
4. Compare the two fingerprints over a call to make sure you reached the right person.
5. Type messages. `/quit` leaves. Messages only send while both sides are online.

To check that the Swift and Kotlin implementations really interoperate over real UDP on one machine:

```sh
sh scripts/interop.sh
```

The tools have `--help`. Identities are created fresh on every run for now; permanent contacts come with
the encrypted storage work.

## Security notes

What is protected: message content and per-message keys, who you are talking to (via signed tickets,
once you verify the other person's key in person), and the integrity of every datagram.

What is **not** hidden:
- **IP addresses and timing.** The network, your carrier and the STUN servers see them.
- **Phone numbers**, if you send tickets by RCS/SMS. The carrier sees that.
- **Message metadata** such as packet counts and the ratchet public key in each header.
- **Identity, unless verified.** A ticket proves someone holds a key, not who they are. Compare keys
  in person (QR) or over a call.

Known limits are listed in [`docs/TRANSPORT.md`](docs/TRANSPORT.md#7-known-limits). The big one: with
no relay, **symmetric NATs and many mobile carrier NATs block hole punching**, so some phone-to-phone
connections will time out. Home Wi-Fi to home Wi-Fi usually works. `swift run dolly-selftest --live-stun`
tells you which kind of NAT you are behind.

Found a security problem? Please report it privately to the maintainer rather than opening a public issue.

## Roadmap

- [x] Protocol spec, ticket/handshake/ratchet core in Swift and Kotlin, with cross-checked vectors
- [x] STUN, hole punching, reliable delivery, chunking, simulated-network tests
- [ ] Test on real mobile networks (phone hotspot, carrier NAT) and decide whether a stateless
      ciphertext relay is needed as a fallback
- [ ] Encrypted local storage: message database and contacts, keys in the Secure Enclave / Android Keystore
- [ ] Apps: SwiftUI and Android, QR and RCS ticket exchange
- [ ] Android foreground service so the socket stays open; iOS stays foreground-only
- [ ] Groups, file transfer, post-quantum hybrid handshake (reserved in the spec, waiting on platform ML-KEM)

## License

[MIT](LICENSE)
