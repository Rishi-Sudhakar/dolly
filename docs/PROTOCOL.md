# Dolly Protocol v1

Serverless, end-to-end encrypted 1:1 messaging. Both peers must be online. Each device stores its own
history; the network is only a transport. All integers are big-endian. No compression anywhere.

## 1. Primitives (platform-provided only)

| Purpose | Algorithm | iOS | Android |
|---|---|---|---|
| Signatures | Ed25519 | CryptoKit | JCA `Ed25519` (API 33+) |
| Key agreement | X25519 | CryptoKit | JCA `X25519` (API 33+) |
| AEAD | ChaCha20-Poly1305 | CryptoKit | JCA (API 28+) |
| KDF | HKDF-SHA256 (RFC 5869) | CryptoKit | HMAC-SHA256, hand-rolled HKDF |
| Hash/MAC | SHA-256 / HMAC-SHA256 | CryptoKit | JCA |

Suite `0x01` is classical. Post-quantum (X25519 + ML-KEM-768 hybrid) is reserved as suite `0x02`:
ticket gains a KEM public key and the handshake mixes the KEM secret into `dh1||dh2||dh3`. Not in v1
because Android has no stable platform ML-KEM yet.

## 2. Ticket (out-of-band invitation)

```
version(1)=1 | suite(1)=1 | identityKey(32 Ed25519) | staticKey(32 X25519) | ephemeralKey(32 X25519)
| expiry(8, unix s) | endpointCount(1, <=8) | endpoint* | signature(64)
endpoint = kind(1: 4|6) | address(4|16) | port(2)
signature = Ed25519( "dolly/v1/ticket" || everything before signature )
```

Endpoints come from STUN (public mapped address) plus local IPv6. Tickets are single-use: generate a
fresh `ephemeralKey` per ticket. Transport: QR code, or a text via the user's RCS/SMS app (base64).
Reject expired or badly signed tickets. Verify the contact's `identityKey` out-of-band (QR in person or
safety-number comparison); a ticket alone proves possession of a key, not who holds it.

## 3. Handshake

Both sides exchange tickets, then derive the same root key with no further round trips.
`A` = peer whose `identityKey` is lexicographically lower (unsigned bytes), `B` = the other.

```
dh1 = X25519(static_A, eph_B)      dh2 = X25519(eph_A, static_B)      dh3 = X25519(eph_A, eph_B)
transcript = SHA256(ticket_A || ticket_B)                       (full encoded tickets)
RK0 = HKDF(ikm = dh1||dh2||dh3, salt = transcript, info = "dolly/v1/handshake", 32)
adPrefix = "dolly/v1/msg" || identity_A || identity_B
```

Mutual authentication comes from the static keys; forward secrecy from the ephemerals.

## 4. Double Ratchet

- `KDF_RK(rk, dh)`: `HKDF(ikm = dh, salt = rk, info = "dolly/v1/ratchet", 64)` -> `(rk', ck)` (32 + 32).
- `KDF_CK(ck)`: `mk = HMAC(ck, 0x01)`, `ck' = HMAC(ck, 0x02)`.
- Message key -> `HKDF(ikm = mk, salt = "", info = "dolly/v1/msg-key", 44)` = 32-byte key + 12-byte nonce.
  Each `mk` is used once, so the derived nonce never repeats.
- Initiator `A`: `dhs = new key`, `dhr = eph_B`, `(RK, CKs) = KDF_RK(RK0, DH(dhs, dhr))`.
- Responder `B`: `dhs = eph_B (keypair)`, `dhr = nil`, `RK = RK0`. `B` cannot send until it has received
  one packet, so `A` sends an automatic hello on connect.
- Receive DH ratchet (header key changed): skip rest of old chain up to `pn`, then
  `pn = ns; ns = nr = 0; dhr = new`, `(RK, CKr) = KDF_RK(RK, DH(dhs, dhr))`, `dhs = new key`,
  `(RK, CKs) = KDF_RK(RK, DH(dhs, dhr))`.
- At most 1000 skipped keys; a gap larger than that is rejected. Replays fail authentication.
- State is only committed after a packet authenticates, so forged packets cannot desync a session.

## 5. Data packet

```
version(1)=1 | type(1)=1 | dh(32) | pn(4) | ns(4) | ciphertext || tag(16)
AEAD ad = adPrefix || dh || pn || ns
plaintext = length(2) | payload | zero padding   (padded to 256, 512 or 1024 bytes)
```

Max payload 1022 bytes; whole packet <= 1082 bytes, under the ~1200-byte safe UDP MTU. Longer messages
and files are chunked by the transport layer (milestone 2). The header is authenticated but not
encrypted in v1 (ratchet key, counters visible to a network observer).

## 6. Not yet specified (milestone 2)

UDP hole punching, STUN client, keepalive, retransmission/ordering, message chunking, contact storage,
encrypted local database, QR/RCS ticket exchange UX, Android foreground service.

## 7. Conformance

`test-vectors/vectors.json` holds fixed seeds, both tickets and three packets. Every implementation must
reproduce the packets byte for byte. Swift generates it (`DOLLY_WRITE_VECTORS=1 swift run dolly-selftest`); Kotlin
must match it.
