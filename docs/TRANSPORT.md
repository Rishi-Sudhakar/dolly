# Dolly Transport v1

How two devices find each other and move encrypted packets over UDP with no server of ours. This
sits below the session described in `PROTOCOL.md`: the session produces opaque encrypted packets,
the transport gets them across the internet.

```
 app message (<= ~1 MiB)
   |  chunk (<= 1013 bytes each)              Messages
   |  session.encrypt  -> packet <= 1082 B    PROTOCOL.md
   |  reliable channel: seq, acks, retransmit Reliable
   |  frame: magic, kind, role, body, tag     Frame
   v  UDP datagram <= 1113 B (under the ~1200 B safe MTU)
```

## 1. Finding the peer (STUN)

A phone behind NAT does not know its public address. Public STUN servers (Google, Cloudflare)
answer one question: "what IP:port did you see this packet come from?" They store nothing and never
see message content or keys.

- Send an RFC 5389 Binding request from the **same UDP socket** you will use for the conversation.
  A different socket gets a different NAT mapping, and the reported address would be useless.
- Query at least two servers. If they report different ports for the same socket, the NAT is
  **symmetric** (a new mapping per destination): hole punching will usually fail. Surface this to the
  user instead of letting the connection time out.
- Put the mapped endpoints in the ticket (`PROTOCOL.md` section 2). Tickets expire, because mappings do.
- Parsing handles XOR-MAPPED-ADDRESS (IPv4 and IPv6) and falls back to MAPPED-ADDRESS. Requests are
  retried every 500 ms for about 2.5 s. Message integrity and fingerprint attributes are not
  checked: the answer is only an address hint, and a lie only makes the connection fail.

## 2. Frames

Every datagram: `0xD0 | kind | senderIsInitiator | body | tag(16)`.

| kind | body |
|---|---|
| 1 punch | nonce(8) |
| 2 punchAck | nonce(8) |
| 3 data | seq(4), ackNext(4), sack(4), payload = one session packet |
| 4 ack | ackNext(4), sack(4) |

`tag = HMAC-SHA256(transportKey, "dolly/v1/frame" || everything before the tag)[0..<16]`, and
`transportKey = HKDF(handshake root key, info "dolly/v1/transport")`, so only the two peers can
produce valid frames. A frame is dropped, before it can touch the ratchet, if the tag is wrong or
if it claims the receiver's own role (a reflected copy of our own packet). The first byte `0xD0`
cannot be confused with STUN replies on the same socket (those start with `0x00` or `0x01`).

Why authenticate outside the AEAD: sequence numbers and acks sit outside the encrypted payload. Without
a tag, an off-path attacker could forge acks (making us drop a message we never delivered) or spray
junk that makes the receiver run ratchet steps. The tag stops both for 16 bytes per datagram.

## 3. Reliability

UDP loses, reorders and duplicates packets; the transport repairs loss and duplication.

- Sender numbers each session packet (`seq`, from 0) and keeps it until acknowledged.
- Receiver acknowledges with `ackNext` (everything below it arrived) plus `sack`: bit *i* set means
  `ackNext + 1 + i` arrived. Acks piggyback on data frames; a lone ack frame is sent when there is
  nothing else to say.
- Window: a sender never has a gap of 32 or more between its oldest unacked packet and a new one, so
  every sequence number fits the receiver's sack range.
- Retransmission timeout starts at 500 ms, follows smoothed RTT (200 ms to 4 s, never sampling
  retransmitted packets), doubles per retry, and gives up after 8 retries (about 25 s). Giving up
  means the peer is offline or unreachable: the connection fails and `send` reports it, as the
  product requirement says.
- A sequence number counts as received only **after** the session successfully decrypted it, so a
  forgery cannot occupy a slot. A retransmitted copy is identical ciphertext and is dropped by
  sequence number before the ratchet sees it.
- Ordering is not enforced. The ratchet tolerates reordering (skipped message keys), and chunks
  reassemble in any order. No congestion control beyond the 32-packet window (about 34 KB in flight).

## 4. Chunking

Session payloads are at most 1022 bytes, so messages are split. Plaintext inside the session:

```
hello : 0x00                                     sent by the initiator when the path opens
chunk : 0x01 | messageId(4) | index(2) | count(2) | data (<= 1013 bytes)
```

Messages up to 1024 chunks (about 1 MiB) are accepted. The receiver reassembles with hard bounds:
16 partially received messages, 4 MiB buffered. Inconsistent or out-of-range chunks are discarded.
Anything larger is a job for a future file-transfer layer.

## 5. Connection state machine

```
punching --valid punch / punchAck / ack / data from any endpoint--> established
punching --15 s with nothing authenticated--------------------------> failed(punchTimeout)
established --8 retries without ack---------------------------------> failed(peerUnreachable)
established --60 s of silence---------------------------------------> failed(idleTimeout)
```

- **Punching:** every 250 ms send a `punch` to every endpoint in the peer's ticket. Both sides do this
  simultaneously, which opens a mapping in each NAT. Receiving a valid punch is answered with
  `punchAck` (always, even once established, because the other side may not have heard us yet).
  The endpoint the first valid frame came from becomes the peer address.
- **Established:** the initiator sends `hello`, which lets the responder (who cannot send before
  receiving one packet) start talking. Messages queued earlier wait until the session can send.
- **Keepalive:** an ack frame at least every 15 s, below the shortest common UDP NAT timeout
  (about 30 s), keeps the mapping open.
- **Roaming:** if fresh data that decrypts arrives from a different address, the peer address
  moves to it (the peer's NAT remapped). Replays cannot trigger this, since duplicates are dropped.

The state machine does no I/O and reads no clock. `receive(datagram, from, now)` and `poll(now)`
take and return plain values, so it is tested by simulation with loss, reordering and duplication,
and the same logic drives real sockets through a thin adapter (`UDPSocket` / `UdpSocket`, plus `pump`).

## 6. What this does and does not protect

- Content, message boundaries within a bucket and per-message keys: protected by the session.
- Datagram authenticity, anti-reflection, no forged acks: protected by the frame tag.
- Not hidden: IP addresses and timing (the network and STUN servers see them), packet counts, and
  the ratchet public key in each header. Frames can be replayed by an on-path attacker; the
  consequence is limited to a duplicate that is dropped.
- A fresh punch nonce is not checked for uniqueness. A replayed punch within the punching window
  could briefly steer the peer address; the next valid data frame corrects it.

## 7. Known limits

- **No relay.** Symmetric NAT and many carrier-grade NATs defeat hole punching, so some mobile-to-mobile
  connections will fail with `punchTimeout`. Wi-Fi to Wi-Fi works far more often. A stateless relay
  that forwards ciphertext (without storing anything) would be the fallback if this matters, but it
  is a server and so it is deliberately not part of v1.
- The socket adapters are IPv4 only; the frame and STUN codecs already handle IPv6.
- Both apps must be open (or, on Android, held by a foreground service). iOS cannot hold a socket in
  the background.
- No ticket-exchange UI, local storage or app screens yet.

## 8. Conformance

`test-vectors/transport.json` (generated by Swift, replayed by Kotlin) pins the transport key, one frame
of each kind, a multi-chunk message and STUN messages. Behaviour that depends on timing and loss is
covered by a deterministic simulation in both languages rather than by vectors.
