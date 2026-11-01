# Dolly local storage v1

Everything a device keeps lives in one directory, encrypted under a 32-byte **master key**. The core never
chooses where that key lives: the app keeps it in hardware-backed storage (Secure Enclave or Keychain on
iOS, Android Keystore on Android) and hands it to `Store` at startup. The format is device-local, so the
two implementations are not required to read each other's files.

## Keys and sealing

- Per-file key: `HKDF-SHA256(ikm = master, salt = empty, info = "dolly/v1/store/" || name, 32 bytes)`.
  Changing the layout or algorithm means changing `v1`, which makes old files fail cleanly.
- A sealed unit is `nonce(12) || ciphertext || tag(16)`: ChaCha20-Poly1305 with a fresh random nonce.
- Nothing is stored in the clear except file names, sizes and the number of records.

## Files

| File | Contents | Associated data | Writes |
|---|---|---|---|
| `identity` | signing seed, signing public, agreement seed, agreement public (4 x 32 bytes) | `"identity"` | atomic replace |
| `contacts` | `count(2)`, then per contact: `identityKey(32) nameLen(2) name verified(1) addedAt(8)` | `"contacts"` | atomic replace |
| `chat-<hex identity key>` | append-only log of sealed records | `name || index(8)` | append and fsync |

A chat log is a sequence of `length(4) || sealed unit`. Record plaintexts:

- message: `1 || id(16) || at(8) || outgoing(1) || textLen(4) || text`
- delivery receipt: `2 || id(16)`

Receipts are separate records so the log never has to be rewritten.

## What this defends against, and what it does not

- Reading the files without the master key reveals nothing but sizes and record counts.
- Changing a byte, swapping two records, moving a record to another log, or using the wrong key fails
  authentication. The record index in the associated data is what catches reordering.
- A crash in the middle of an append leaves a torn last record. It is ignored when reading and cut off
  at the next append.
- **Not detected:** removing records from the end of a log, or restoring an older copy of a whole file.
  Defending against that needs a counter held in hardware, which belongs to the app layer.
- The master key is only as safe as the platform's hardware key store. A device that is unlocked and
  compromised exposes the data.
