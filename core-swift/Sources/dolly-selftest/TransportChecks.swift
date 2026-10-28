import CryptoKit
import Foundation
@testable import DollyCore

// MARK: - Fixtures

private func hexData(_ s: String) -> Data { Data(hex: s)! }

private let stunTransactionID = "b7e7a701bc34d686fa87dfae"
private let stunRequestHex = "000100002112a442b7e7a701bc34d686fa87dfae"
/// 192.0.2.1:32853 (RFC 5769 values)
private let stunV4Hex = "0101000c2112a442b7e7a701bc34d686fa87dfae002000080001a147e112a643"
/// [2001:db8:1234:5678:11:2233:4455:6677]:32853, computed independently with Python
private let stunV6Hex = "010100182112a442b7e7a701bc34d686fa87dfae002000140002a1470113a9faa5d3f179bc25f4b5bed2b9d9"
/// Same address as v4, but as a plain MAPPED-ADDRESS attribute
private let stunPlainHex = "0101000c2112a442b7e7a701bc34d686fa87dfae0001000800018055c0000201"

private struct XorShift {
    var state: UInt64
    mutating func next() -> UInt64 {
        state ^= state << 13
        state ^= state >> 7
        state ^= state << 17
        return state
    }
    mutating func unit() -> Double { Double(next() % 1_000_000) / 1_000_000 }
}

private let simA = try! Endpoint(kind: .v4, address: Data([198, 51, 100, 1]), port: 5000)
private let simB = try! Endpoint(kind: .v4, address: Data([203, 0, 113, 9]), port: 6000)

private func randomSessions() throws -> (Session, Session) {
    let ia = Identity(), ib = Identity()
    let ea = Curve25519.KeyAgreement.PrivateKey(), eb = Curve25519.KeyAgreement.PrivateKey()
    let ta = try Ticket.create(identity: ia, ephemeral: ea.publicKey, endpoints: [], expiry: expiry)
    let tb = try Ticket.create(identity: ib, ephemeral: eb.publicKey, endpoints: [], expiry: expiry)
    return (
        try Session(identity: ia, ephemeral: ea, localTicket: ta, remoteTicket: tb),
        try Session(identity: ib, ephemeral: eb, localTicket: tb, remoteTicket: ta)
    )
}

/// Two connections joined by a lossy, reordering, duplicating link on virtual time.
private final class Sim {
    struct Packet {
        let at: Int64
        let toA: Bool
        let from: Endpoint
        let bytes: Data
    }

    let a: Connection
    let b: Connection
    var rng: XorShift
    var loss: Double
    var inflight: [Packet] = []
    var t: Int64 = 0
    var gotAtA: [Data] = []
    var gotAtB: [Data] = []

    init(loss: Double, seed: UInt64) throws {
        let (sa, sb) = try randomSessions()
        a = Connection(session: sa, remoteEndpoints: [simB], now: 0)
        b = Connection(session: sb, remoteEndpoints: [simA], now: 0)
        rng = XorShift(state: seed | 1)
        self.loss = loss
    }

    private func transmit(_ out: [Connection.Outgoing], fromA: Bool) {
        for packet in out {
            guard packet.endpoint == (fromA ? simB : simA) else { continue }  // a NAT would drop anything else
            if rng.unit() < loss { continue }
            let delay = Int64(20 + rng.next() % 60)  // varying delay reorders packets
            let source = fromA ? simA : simB
            inflight.append(Packet(at: t + delay, toA: !fromA, from: source, bytes: packet.bytes))
            if rng.unit() < 0.05 {
                inflight.append(Packet(at: t + delay + Int64(rng.next() % 80), toA: !fromA, from: source, bytes: packet.bytes))
            }
        }
    }

    func step() {
        let ready = inflight.filter { $0.at <= t }.sorted { $0.at < $1.at }
        inflight.removeAll { $0.at <= t }
        for packet in ready {
            if packet.toA {
                gotAtA += a.receive(packet.bytes, from: packet.from, now: t)
            } else {
                gotAtB += b.receive(packet.bytes, from: packet.from, now: t)
            }
        }
        transmit(a.poll(now: t), fromA: true)
        transmit(b.poll(now: t), fromA: false)
        t += 10
    }
}

private func makeMessage(side: UInt8, index: Int) -> Data {
    let sizes = [0, 10, 1013, 1014, 3000, 20000]
    var message = Data([side])
    message.append(contentsOf: withUnsafeBytes(of: UInt32(index).bigEndian) { Array($0) })
    message.append(Data((0..<sizes[index % sizes.count]).map { UInt8((index * 7 + Int(side) + $0) & 0xff) }))
    return message
}

private func exchange(loss: Double, seed: UInt64, perSide: Int, limitMs: Int64) throws -> (ok: Bool, sim: Sim) {
    let sim = try Sim(loss: loss, seed: seed)
    let fromA = (0..<perSide).map { makeMessage(side: 1, index: $0) }
    let fromB = (0..<perSide).map { makeMessage(side: 2, index: $0) }
    for i in 0..<perSide {
        try sim.a.send(fromA[i])
        try sim.b.send(fromB[i])
    }
    while sim.t <= limitMs, !(sim.gotAtB.count == perSide && sim.gotAtA.count == perSide) { sim.step() }
    let exactlyOnce = sim.gotAtB.count == perSide && Set(sim.gotAtB) == Set(fromA)
        && sim.gotAtA.count == perSide && Set(sim.gotAtA) == Set(fromB)
    return (exactlyOnce, sim)
}

// MARK: - Checks

func runTransportChecks() {
    test("STUN: request and response vectors") {
        let txid = hexData(stunTransactionID)
        expect(Stun.bindingRequest(transactionID: txid) == hexData(stunRequestHex))

        let v4 = try Stun.parseBindingResponse(hexData(stunV4Hex), transactionID: txid)
        expect(v4.kind == .v4 && v4.address == Data([192, 0, 2, 1]) && v4.port == 32853)

        let v6 = try Stun.parseBindingResponse(hexData(stunV6Hex), transactionID: txid)
        expect(v6.kind == .v6 && v6.address == hexData("20010db8123456780011223344556677") && v6.port == 32853)

        let plain = try Stun.parseBindingResponse(hexData(stunPlainHex), transactionID: txid)
        expect(plain.address == Data([192, 0, 2, 1]) && plain.port == 32853)

        expectThrows(.badStunResponse) { try Stun.parseBindingResponse(hexData(stunV4Hex), transactionID: Data(count: 12)) }
        expectThrows(.badStunResponse) { try Stun.parseBindingResponse(hexData(stunV4Hex).dropLast(3), transactionID: txid) }
        expectThrows(.badStunResponse) { try Stun.parseBindingResponse(Data(), transactionID: txid) }
    }

    test("STUN: NAT mapping classification") {
        let e1 = try Endpoint(kind: .v4, address: Data([1, 2, 3, 4]), port: 1000)
        let e2 = try Endpoint(kind: .v4, address: Data([1, 2, 3, 4]), port: 1001)
        expect(Stun.mappingBehavior([e1]) == .unknown)
        expect(Stun.mappingBehavior([e1, e1]) == .endpointIndependent)
        expect(Stun.mappingBehavior([e1, e2]) == .symmetric)
    }

    test("frames: round trip, tamper, wrong key, reflection") {
        let key = Data(repeating: 0x42, count: 32)
        let nonce = hexData("0102030405060708")
        let frames: [Frame] = [
            .punch(nonce: nonce), .punchAck(nonce: nonce),
            .data(seq: 7, ackNext: 3, sack: 5, payload: Data([1, 2, 3])),
            .ack(ackNext: 9, sack: 0xFFFF_FFFF),
        ]
        for frame in frames {
            let wire = frame.encoded(key: key, isInitiator: true)
            expect(try Frame.decode(wire, key: key, localIsInitiator: false) == frame)
            expectThrows(.malformedPacket) { try Frame.decode(wire, key: key, localIsInitiator: true) }  // reflected
            expectThrows(.authenticationFailed) { try Frame.decode(wire, key: Data(repeating: 0x43, count: 32), localIsInitiator: false) }
            for position in [0, 1, 2, wire.count / 2, wire.count - 1] {
                var tampered = wire
                tampered[position] ^= 0x01
                expectThrows { try Frame.decode(tampered, key: key, localIsInitiator: false) }
            }
        }
        expectThrows(.truncated) { try Frame.decode(Data([0xD0, 1]), key: key, localIsInitiator: false) }
    }

    test("chunking: sizes round trip through the reassembler in any order") {
        var rng = XorShift(state: 99)
        for size in [0, 1, 1013, 1014, 2026, 2027, 5000, 100_000] {
            let message = Data((0..<size).map { UInt8($0 % 251) })
            var chunks = try AppMessage.encodeChunks(message, id: 1)
            expect(chunks.count == max(1, (size + 1012) / 1013), "chunk count for \(size)")
            expect(chunks.allSatisfy { $0.count <= Session.maxPayload }, "chunks must fit one packet")
            for i in stride(from: chunks.count - 1, to: 0, by: -1) { chunks.swapAt(i, Int(rng.next() % UInt64(i + 1))) }

            let reassembler = Reassembler()
            var result: Data?
            for chunk in chunks { result = try reassembler.add(chunk: Data(chunk.dropFirst())) ?? result }
            expect(result == message, "reassembly of \(size) bytes")
        }
        expectThrows(.messageTooLarge) { try AppMessage.encodeChunks(Data(count: AppMessage.maxMessageSize + 1), id: 1) }
        _ = try AppMessage.encodeChunks(Data(count: AppMessage.maxMessageSize), id: 1)
    }

    test("reassembler rejects malformed chunks and bounds memory") {
        let reassembler = Reassembler()
        var w = ByteWriter()
        w.u32(1); w.u16(5); w.u16(3)  // index >= count
        expectThrows(.malformedPacket) { try reassembler.add(chunk: w.data) as Any }

        // More than 16 half-finished messages: the oldest is dropped, nothing explodes.
        for id in 0..<40 {
            var c = ByteWriter()
            c.u32(UInt32(id)); c.u16(0); c.u16(2); c.bytes(Data([1]))
            _ = try reassembler.add(chunk: c.data)
        }
    }

    test("connection ignores forged datagrams and refuses oversize messages") {
        let (sa, _) = try randomSessions()
        let a = Connection(session: sa, remoteEndpoints: [simB], now: 0)
        expect(a.receive(Data(repeating: 0xD0, count: 60), from: simB, now: 1).isEmpty)
        expect(a.state == .punching)
        expectThrows(.messageTooLarge) { try a.send(Data(count: AppMessage.maxMessageSize + 1)) }
    }

    test("simulation: clean link, then 20% and 30% loss with reordering and duplicates") {
        for (loss, seed) in [(0.0, UInt64(1)), (0.2, 2), (0.3, 3)] {
            let (ok, sim) = try exchange(loss: loss, seed: seed, perSide: 40, limitMs: 600_000)
            expect(ok, "loss \(loss): messages must arrive exactly once (got \(sim.gotAtB.count)/\(sim.gotAtA.count) of 40)")
            expect(sim.a.state == .established && sim.b.state == .established, "loss \(loss): both ends established")
            print("    loss \(Int(loss * 100))%: done in \(sim.t / 1000)s virtual time")
        }
    }

    test("simulation: peer going offline is reported, nothing hangs") {
        let sim = try Sim(loss: 0, seed: 5)
        try sim.a.send(Data("first".utf8))
        while sim.t < 3000 { sim.step() }
        expect(sim.gotAtB == [Data("first".utf8)])

        sim.loss = 1.0  // peer vanishes
        let cut = sim.t
        try sim.a.send(Data("into the void".utf8))
        while sim.t < cut + 90_000, sim.a.state == .established { sim.step() }
        expect(sim.a.state == .failed(.peerUnreachable), "got \(sim.a.state)")
        expectThrows(.connectionFailed) { try sim.a.send(Data("more".utf8)) }
        print("    reported unreachable after \((sim.t - cut) / 1000)s")
    }

    test("simulation: hole punching gives up when nothing gets through") {
        let sim = try Sim(loss: 1.0, seed: 6)
        while sim.t < 16_000 { sim.step() }
        expect(sim.a.state == .failed(.punchTimeout) && sim.b.state == .failed(.punchTimeout))
    }

    test("transport conformance vectors") {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let url = root.appendingPathComponent("test-vectors/transport.json")

        // Use the key recorded in vectors.json (written moments ago in write mode) so both files agree.
        let handshake = try JSONSerialization.jsonObject(
            with: Data(contentsOf: root.appendingPathComponent("test-vectors/vectors.json"))
        ) as! [String: Any]
        let key = hexData(handshake["transportKey"] as! String)
        let nonce = hexData("0102030405060708")
        let payload = Data((0..<50).map { UInt8($0) })

        let frames: [[String: Any]] = [
            ["kind": "punch", "senderIsInitiator": true, "nonce": nonce.hex,
             "datagram": Frame.punch(nonce: nonce).encoded(key: key, isInitiator: true).hex],
            ["kind": "punchAck", "senderIsInitiator": false, "nonce": nonce.hex,
             "datagram": Frame.punchAck(nonce: nonce).encoded(key: key, isInitiator: false).hex],
            ["kind": "data", "senderIsInitiator": true, "seq": 7, "ackNext": 3, "sack": 5, "payload": payload.hex,
             "datagram": Frame.data(seq: 7, ackNext: 3, sack: 5, payload: payload).encoded(key: key, isInitiator: true).hex],
            ["kind": "ack", "senderIsInitiator": false, "ackNext": 9, "sack": Int(UInt32.max),
             "datagram": Frame.ack(ackNext: 9, sack: UInt32.max).encoded(key: key, isInitiator: false).hex],
        ]
        let chunkedMessage = Data((0..<2500).map { UInt8($0 % 251) })
        let vectors: [String: Any] = [
            "transportKey": key.hex,
            "frames": frames,
            "chunks": [["id": 5, "message": chunkedMessage.hex,
                        "chunks": try AppMessage.encodeChunks(chunkedMessage, id: 5).map { $0.hex }]],
            "stun": [
                "transactionID": stunTransactionID, "request": stunRequestHex,
                "responses": [
                    ["hex": stunV4Hex, "kind": "v4", "address": "c0000201", "port": 32853],
                    ["hex": stunV6Hex, "kind": "v6", "address": "20010db8123456780011223344556677", "port": 32853],
                    ["hex": stunPlainHex, "kind": "v4", "address": "c0000201", "port": 32853],
                ],
            ],
        ]
        let json = try JSONSerialization.data(withJSONObject: vectors, options: [.prettyPrinted, .sortedKeys])
        if CommandLine.arguments.contains("--write-vectors") {
            try json.write(to: url)
            print("    wrote \(url.path)")
        }
        try replayTransportVectors(at: url)
    }

    // Optional checks that touch the real network or real sockets.
    if CommandLine.arguments.contains("--loopback") { runLoopbackCheck() }
    if CommandLine.arguments.contains("--live-stun") { runLiveStunCheck() }
}

private func runLoopbackCheck() {
    test("loopback: two real UDP sockets exchange messages") {
        let sa = try UDPSocket(), sb = try UDPSocket()
        let (ka, kb) = try randomSessions()
        let localhost = Data([127, 0, 0, 1])
        let a = Connection(session: ka, remoteEndpoints: [try Endpoint(kind: .v4, address: localhost, port: sb.localPort)], now: monotonicMillis())
        let b = Connection(session: kb, remoteEndpoints: [try Endpoint(kind: .v4, address: localhost, port: sa.localPort)], now: monotonicMillis())

        let toB = (0..<5).map { makeMessage(side: 1, index: $0) }
        let toA = (0..<5).map { makeMessage(side: 2, index: $0) }
        for i in 0..<5 {
            try a.send(toB[i])
            try b.send(toA[i])
        }
        var gotB: [Data] = [], gotA: [Data] = []
        let start = monotonicMillis()
        while monotonicMillis() - start < 15_000, !(gotA.count == 5 && gotB.count == 5) {
            gotA += a.pump(socket: sa, timeoutMs: 5)
            gotB += b.pump(socket: sb, timeoutMs: 5)
        }
        expect(Set(gotA) == Set(toA) && gotA.count == 5 && Set(gotB) == Set(toB) && gotB.count == 5,
               "got \(gotA.count) and \(gotB.count) of 5 (states \(a.state) / \(b.state))")
        print("    delivered in \(monotonicMillis() - start) ms")
    }
}

private func runLiveStunCheck() {
    test("live STUN: public address and NAT mapping behaviour") {
        let socket = try UDPSocket()
        let servers = UDPSocket.resolve(host: "stun.l.google.com", port: 19302)
            + UDPSocket.resolve(host: "stun.cloudflare.com", port: 3478)
        print("    resolved \(servers.count) STUN server address(es)")
        let results = StunClient.discover(socket: socket, servers: servers)
        func dotted(_ e: Endpoint) -> String { e.address.map { String($0) }.joined(separator: ".") + ":" + String(e.port) }
        for r in results { print("    via \(dotted(r.server)) -> \(dotted(r.mapped))") }
        if results.isEmpty { print("    NOTE: no STUN answers (offline, or UDP blocked); not counted as a failure") }
        print("    NAT mapping: \(Stun.mappingBehavior(results.map { $0.mapped }))")
    }
}

// MARK: - Replaying committed vectors

/// Rebuilds both peers from the seeds and tickets in vectors.json and demands the exact recorded packets.
/// This is the same test the Kotlin implementation runs.
func replayCommittedVectors(at url: URL) throws {
    let v = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    let nowValue = (v["now"] as! NSNumber).uint64Value
    let alice = v["alice"] as! [String: Any]
    let bob = v["bob"] as! [String: Any]

    func generator(_ seeds: [String]) -> Session.KeyGenerator {
        var next = 0
        return {
            defer { next += 1 }
            return try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: hexData(seeds[next]))
        }
    }
    func session(_ me: [String: Any], _ other: [String: Any]) throws -> Session {
        let identity = try Identity(
            signingSeed: hexData(me["signingSeed"] as! String),
            agreementSeed: hexData(me["agreementSeed"] as! String)
        )
        return try Session(
            identity: identity,
            ephemeral: try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: hexData(me["ephemeralSeed"] as! String)),
            localTicket: try Ticket.decode(hexData(me["ticket"] as! String), now: nowValue),
            remoteTicket: try Ticket.decode(hexData(other["ticket"] as! String), now: nowValue),
            keyGenerator: generator(me["ratchetSeeds"] as! [String])
        )
    }

    let sessions = ["alice": try session(alice, bob), "bob": try session(bob, alice)]
    for peer in sessions.values {
        expect(peer.transportKey.hex == (v["transportKey"] as! String), "transport key differs from the committed vector")
    }
    for (i, message) in (v["messages"] as! [[String: Any]]).enumerated() {
        let from = message["from"] as! String
        let sender = sessions[from]!, receiver = sessions[from == "alice" ? "bob" : "alice"]!
        let plaintext = hexData(message["plaintext"] as! String)
        let recorded = message["packet"] as! String
        let packet = try sender.encrypt(plaintext)
        expect(packet.hex == recorded, "packet \(i) differs from the committed vector")
        expect(try receiver.decrypt(hexData(recorded)) == plaintext, "packet \(i) did not decrypt")
    }
}

func replayTransportVectors(at url: URL) throws {
    let v = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    let key = hexData(v["transportKey"] as! String)

    for (i, frame) in (v["frames"] as! [[String: Any]]).enumerated() {
        let senderIsInitiator = frame["senderIsInitiator"] as! Bool
        let datagram = hexData(frame["datagram"] as! String)
        let decoded = try Frame.decode(datagram, key: key, localIsInitiator: !senderIsInitiator)
        expect(decoded.encoded(key: key, isInitiator: senderIsInitiator) == datagram, "frame \(i) re-encodes differently")
    }
    for chunkCase in v["chunks"] as! [[String: Any]] {
        let message = hexData(chunkCase["message"] as! String)
        let id = UInt32(chunkCase["id"] as! Int)
        let encoded = try AppMessage.encodeChunks(message, id: id).map { $0.hex }
        expect(encoded == (chunkCase["chunks"] as! [String]), "chunk encoding differs from the committed vector")
    }
    let stun = v["stun"] as! [String: Any]
    let txid = hexData(stun["transactionID"] as! String)
    expect(Stun.bindingRequest(transactionID: txid).hex == (stun["request"] as! String), "STUN request differs")
    for response in stun["responses"] as! [[String: Any]] {
        let endpoint = try Stun.parseBindingResponse(hexData(response["hex"] as! String), transactionID: txid)
        expect(endpoint.address.hex == (response["address"] as! String) && Int(endpoint.port) == (response["port"] as! Int),
               "STUN response parsed differently")
    }
}
