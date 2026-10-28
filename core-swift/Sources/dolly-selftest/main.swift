import CryptoKit
import DollyCore
import Foundation

// MARK: - Minimal harness

var failures = 0

func expect(_ ok: Bool, _ message: String = "", line: UInt = #line) {
    guard !ok else { return }
    failures += 1
    print("    FAIL (line \(line)) \(message)")
}

func expectThrows(_ expected: DollyError? = nil, line: UInt = #line, _ body: () throws -> Any) {
    do {
        _ = try body()
        failures += 1
        print("    FAIL (line \(line)) expected an error, got none")
    } catch {
        if let expected, (error as? DollyError) != expected {
            failures += 1
            print("    FAIL (line \(line)) expected \(expected), got \(error)")
        }
    }
}

func test(_ name: String, _ body: () throws -> Void) {
    print("• \(name)")
    do { try body() } catch {
        failures += 1
        print("    ERROR \(error)")
    }
}

// MARK: - Fixtures

let now: UInt64 = 1_800_000_000
let expiry: UInt64 = 4_102_444_800

func seeded(_ base: UInt8) -> Session.KeyGenerator {
    var counter: UInt8 = 0
    return {
        defer { counter += 1 }
        return try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: base + counter, count: 32))
    }
}

struct Peer {
    let identity: Identity
    let ephemeral: Curve25519.KeyAgreement.PrivateKey
    let ticket: Ticket

    init(seed: UInt8, endpoint: Endpoint) throws {
        identity = try Identity(
            signingSeed: Data(repeating: seed, count: 32),
            agreementSeed: Data(repeating: seed + 1, count: 32)
        )
        ephemeral = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: seed + 2, count: 32))
        ticket = try Ticket.create(identity: identity, ephemeral: ephemeral.publicKey, endpoints: [endpoint], expiry: expiry)
    }

    func session(with other: Peer, generatorBase: UInt8) throws -> Session {
        try Session(
            identity: identity, ephemeral: ephemeral, localTicket: ticket,
            remoteTicket: try Ticket.decode(other.ticket.encoded(), now: now),
            keyGenerator: seeded(generatorBase)
        )
    }
}

func makePeers() throws -> (Peer, Peer) {
    let v4 = try Endpoint(kind: .v4, address: Data([203, 0, 113, 5]), port: 40000)
    var v6Address = Data(count: 16)
    v6Address[0] = 0x20; v6Address[1] = 0x01; v6Address[2] = 0x0d; v6Address[3] = 0xb8; v6Address[15] = 1
    let v6 = try Endpoint(kind: .v6, address: v6Address, port: 40001)
    return (try Peer(seed: 0x01, endpoint: v4), try Peer(seed: 0x11, endpoint: v6))
}

func sessions() throws -> (Peer, Peer, Session, Session) {
    let (pa, pb) = try makePeers()
    return (pa, pb, try pa.session(with: pb, generatorBase: 0x41), try pb.session(with: pa, generatorBase: 0x51))
}

func bytes(_ s: String) -> Data { Data(s.utf8) }

// MARK: - Tickets

test("ticket round trip, tamper, expiry, truncation") {
    let (a, _) = try makePeers()
    expect(try Ticket.decode(a.ticket.encoded(), now: now) == a.ticket)

    var tampered = a.ticket.encoded()
    tampered[40] ^= 0x01
    expectThrows(.badSignature) { try Ticket.decode(tampered, now: now) }
    expectThrows(.expired) { try Ticket.decode(a.ticket.encoded(), now: expiry + 1) }
    expectThrows { try Ticket.decode(Data(a.ticket.encoded().dropLast()), now: now) }
}

// MARK: - Sessions

test("conversation in both directions, responder waits for first packet") {
    let (_, _, a, b) = try sessions()
    expect(a.isInitiator)
    expect(!b.isInitiator)
    expect(!b.canSend)
    expectThrows(.notReadyToSend) { try b.encrypt(bytes("early")) }

    expect(try b.decrypt(try a.encrypt(bytes("hello"))) == bytes("hello"))
    expect(b.canSend)
    for i in 0..<20 {
        expect(try a.decrypt(try b.encrypt(bytes("b\(i)"))) == bytes("b\(i)"))
        expect(try b.decrypt(try a.encrypt(bytes("a\(i)"))) == bytes("a\(i)"))
    }
}

test("out-of-order delivery works, replays are rejected") {
    let (_, _, a, b) = try sessions()
    _ = try b.decrypt(try a.encrypt(bytes("hello")))

    let p1 = try a.encrypt(bytes("one"))
    let p2 = try a.encrypt(bytes("two"))
    let p3 = try a.encrypt(bytes("three"))
    expect(try b.decrypt(p3) == bytes("three"))
    expect(try b.decrypt(p1) == bytes("one"))
    expect(try b.decrypt(p2) == bytes("two"))
    expectThrows(.authenticationFailed) { try b.decrypt(p2) }
    expectThrows(.authenticationFailed) { try b.decrypt(p3) }
}

test("forged packet does not corrupt session state") {
    let (_, _, a, b) = try sessions()
    let genuine = try a.encrypt(bytes("hello"))
    var forged = genuine
    forged[forged.count - 1] ^= 0x01
    expectThrows(.authenticationFailed) { try b.decrypt(forged) }
    expect(try b.decrypt(genuine) == bytes("hello"))
}

test("padding hides length within a bucket, oversize is rejected") {
    let (_, _, a, b) = try sessions()
    let short = try a.encrypt(bytes("hi"))
    let medium = try a.encrypt(Data(repeating: 0x61, count: 200))
    let long = try a.encrypt(Data(repeating: 0x61, count: 300))
    expect(short.count == medium.count)
    expect(medium.count != long.count)
    expectThrows(.messageTooLarge) { try a.encrypt(Data(count: Session.maxPayload + 1)) }
    expect(try b.decrypt(short) == bytes("hi"))
}

test("a third party cannot read the conversation") {
    let (pa, pb) = try makePeers()
    let eve = try Peer(seed: 0x31, endpoint: try Endpoint(kind: .v4, address: Data([1, 2, 3, 4]), port: 1))
    let a = try pa.session(with: pb, generatorBase: 0x41)
    let e = try eve.session(with: pa, generatorBase: 0x61)
    expectThrows { try e.decrypt(try a.encrypt(bytes("secret"))) }
}

// MARK: - Shared vectors (the Kotlin implementation must reproduce these bytes)

test("conformance vectors") {
    let (pa, pb, a, b) = try sessions()
    let m1 = bytes("hello"), m2 = bytes("hi back"), m3 = bytes("second")
    let p1 = try a.encrypt(m1)
    expect(try b.decrypt(p1) == m1)
    let p2 = try b.encrypt(m2)
    expect(try a.decrypt(p2) == m2)
    let p3 = try a.encrypt(m3)
    expect(try b.decrypt(p3) == m3)

    func pub(_ base: UInt8) -> String {
        try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: base, count: 32))
            .publicKey.rawRepresentation.hex
    }
    expect(a.transportKey == b.transportKey && a.transportKey.count == 32, "peers must derive the same transport key")
    let vectors: [String: Any] = [
        "now": now,
        "transportKey": a.transportKey.hex,
        "alice": [
            "signingSeed": Data(repeating: 0x01, count: 32).hex,
            "signingPublic": pa.identity.signing.publicKey.rawRepresentation.hex,
            "agreementSeed": Data(repeating: 0x02, count: 32).hex,
            "ephemeralSeed": Data(repeating: 0x03, count: 32).hex,
            "ratchetSeeds": [0x41, 0x42].map { Data(repeating: UInt8($0), count: 32).hex },
            "ratchetPublics": [pub(0x41), pub(0x42)],
            "ticket": pa.ticket.encoded().hex,
        ],
        "bob": [
            "signingSeed": Data(repeating: 0x11, count: 32).hex,
            "signingPublic": pb.identity.signing.publicKey.rawRepresentation.hex,
            "agreementSeed": Data(repeating: 0x12, count: 32).hex,
            "ephemeralSeed": Data(repeating: 0x13, count: 32).hex,
            "ratchetSeeds": [0x51, 0x52].map { Data(repeating: UInt8($0), count: 32).hex },
            "ratchetPublics": [pub(0x51), pub(0x52)],
            "ticket": pb.ticket.encoded().hex,
        ],
        "messages": [
            ["from": "alice", "plaintext": m1.hex, "packet": p1.hex],
            ["from": "bob", "plaintext": m2.hex, "packet": p2.hex],
            ["from": "alice", "plaintext": m3.hex, "packet": p3.hex],
        ],
    ]
    let json = try JSONSerialization.data(withJSONObject: vectors, options: [.prettyPrinted, .sortedKeys])

    // .../core-swift/Sources/dolly-selftest/main.swift -> repo root
    let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let url = root.appendingPathComponent("test-vectors/vectors.json")
    if CommandLine.arguments.contains("--write-vectors") || ProcessInfo.processInfo.environment["DOLLY_WRITE_VECTORS"] != nil {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try json.write(to: url)
        print("    wrote \(url.path)")
    }
    let committed = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? NSDictionary
    let current = try JSONSerialization.jsonObject(with: json) as? NSDictionary
    expect(committed == current, "wire format changed; re-run with DOLLY_WRITE_VECTORS=1 only if intentional")
}

runTransportChecks()

print(failures == 0 ? "\nALL CHECKS PASSED" : "\n\(failures) CHECK(S) FAILED")
exit(failures == 0 ? 0 : 1)
