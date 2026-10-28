import CryptoKit
import DollyCore
import Foundation

setvbuf(stdout, nil, _IOLBF, 0)

let helpText = """
dolly: serverless end-to-end encrypted chat in your terminal

usage: dolly [options]

  Run it on two machines. Each prints a ticket; paste the other's ticket into each side.
  Both sides must do this within about 15 seconds of each other, and keep the program running.
  Compare the fingerprints over a call or in person to be sure you reached the right person.

options:
  --loopback           do not use STUN; connect over 127.0.0.1 (testing on one machine)
  --send TEXT          queue a message as soon as possible (repeatable)
  --exit-after N       exit successfully after receiving N messages
  --ticket-out FILE    also write your ticket to FILE (for scripts)
  --ticket-in FILE     read the peer's ticket from FILE instead of stdin (waits for it to appear)
  -h, --help           show this help

in chat: type a message and press Enter. /quit leaves.
"""

struct Options {
    var loopback = false
    var sends: [String] = []
    var exitAfter: Int?
    var ticketOut: String?
    var ticketIn: String?
}

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

func parseOptions() -> Options {
    var options = Options()
    var arguments = CommandLine.arguments.dropFirst().makeIterator()
    func value(for flag: String) -> String {
        guard let next = arguments.next() else { fail("\(flag) needs a value (see --help)") }
        return next
    }
    while let argument = arguments.next() {
        switch argument {
        case "--loopback": options.loopback = true
        case "--send": options.sends.append(value(for: argument))
        case "--exit-after":
            guard let n = Int(value(for: argument)), n > 0 else { fail("--exit-after needs a positive number") }
            options.exitAfter = n
        case "--ticket-out": options.ticketOut = value(for: argument)
        case "--ticket-in": options.ticketIn = value(for: argument)
        case "-h", "--help":
            print(helpText)
            exit(0)
        default: fail("unknown option \(argument) (see --help)")
        }
    }
    return options
}

func describe(_ endpoint: Endpoint) -> String {
    if endpoint.kind == .v4 {
        return endpoint.address.map { String($0) }.joined(separator: ".") + ":" + String(endpoint.port)
    }
    let groups = stride(from: 0, to: 16, by: 2).map { i in
        String(Int(endpoint.address[i]) << 8 | Int(endpoint.address[i + 1]), radix: 16)
    }
    return "[" + groups.joined(separator: ":") + "]:" + String(endpoint.port)
}

/// Short, human-comparable digest of an identity key: "a1b2 c3d4 e5f6 0718 293a".
func fingerprint(_ identityKey: Data) -> String {
    let hex = Data(SHA256.hash(data: identityKey).prefix(10)).hex
    return stride(from: 0, to: hex.count, by: 4).map { i in
        String(hex.dropFirst(i).prefix(4))
    }.joined(separator: " ")
}

func unixNow() -> UInt64 { UInt64(Date().timeIntervalSince1970) }

func waitForFile(_ path: String, timeoutSeconds: Int) -> String {
    for _ in 0..<(timeoutSeconds * 5) {
        if let text = try? String(contentsOfFile: path, encoding: .utf8),
           !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return text
        }
        Thread.sleep(forTimeInterval: 0.2)
    }
    fail("timed out waiting for the peer's ticket in \(path)")
}

/// Lines typed on stdin, read on a background thread so the network loop never blocks.
final class Inbox {
    private let lock = NSLock()
    private var lines: [String] = []

    func start() {
        Thread.detachNewThread {
            while let line = readLine() {
                self.lock.lock()
                self.lines.append(line)
                self.lock.unlock()
            }
        }
    }

    func drain() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        let taken = lines
        lines = []
        return taken
    }
}

func run() throws {
    let options = parseOptions()
    guard let socket = try? UDPSocket() else { fail("could not open a UDP socket") }

    // 1. Where can the peer reach us?
    var candidates: [Endpoint] = []
    func offer(_ endpoint: Endpoint) {
        if candidates.count < 8 && !candidates.contains(endpoint) { candidates.append(endpoint) }
    }
    if options.loopback {
        offer(try Endpoint(kind: .v4, address: Data([127, 0, 0, 1]), port: socket.localPort))
    } else {
        print("Asking STUN servers for your public address...")
        let servers = UDPSocket.resolve(host: "stun.l.google.com", port: 19302)
            + UDPSocket.resolve(host: "stun.cloudflare.com", port: 3478)
        let results = StunClient.discover(socket: socket, servers: servers)
        results.forEach { offer($0.mapped) }
        switch Stun.mappingBehavior(results.map { $0.mapped }) {
        case .endpointIndependent: print("Your network should allow a direct connection.")
        case .symmetric: print("WARNING: your network gives a different public port per destination. A direct connection will probably fail.")
        case .unknown:
            print(results.isEmpty
                ? "WARNING: no STUN answer (offline or UDP blocked). Only your local network address is offered."
                : "Only one STUN server answered, so the network type is unknown.")
        }
        for address in UDPSocket.localIPv4Addresses() { offer(try Endpoint(kind: .v4, address: address, port: socket.localPort)) }
    }
    guard !candidates.isEmpty else { fail("no usable network address found") }

    // 2. Ticket exchange.
    let identity = Identity()
    let ephemeral = Curve25519.KeyAgreement.PrivateKey()
    let ticket = try Ticket.create(
        identity: identity, ephemeral: ephemeral.publicKey, endpoints: candidates, expiry: unixNow() + 15 * 60
    )
    let myTicket = ticket.encoded().base64EncodedString()
    print("\nYour key fingerprint: \(fingerprint(ticket.identityKey))")
    print("Reachable at: \(candidates.map(describe).joined(separator: ", "))")
    print("\nYour ticket (give it to your peer):\n\(myTicket)\n")
    if let path = options.ticketOut { try myTicket.write(toFile: path, atomically: true, encoding: .utf8) }

    let theirText: String
    if let path = options.ticketIn {
        theirText = waitForFile(path, timeoutSeconds: 120)
    } else {
        print("Paste your peer's ticket, then press Enter:")
        guard let line = readLine() else { fail("no ticket given") }
        theirText = line
    }
    guard let theirData = Data(base64Encoded: theirText.trimmingCharacters(in: .whitespacesAndNewlines)) else {
        fail("that does not look like a ticket (not valid base64)")
    }
    let remote: Ticket
    do {
        remote = try Ticket.decode(theirData, now: unixNow())
    } catch DollyError.expired {
        fail("that ticket has expired; ask your peer for a fresh one")
    } catch {
        fail("that ticket is not valid (\(error))")
    }
    print("Peer key fingerprint: \(fingerprint(remote.identityKey))  <- compare with them out of band")
    print("Peer is reachable at: \(remote.endpoints.map(describe).joined(separator: ", "))")

    // 3. Connect and chat.
    let session = try Session(identity: identity, ephemeral: ephemeral, localTicket: ticket, remoteTicket: remote)
    let maxAttempts = 6  // a punch attempt lasts 15 s, so we wait about 90 s for the peer to paste their side
    var attempts = 1
    var connection = Connection(session: session, remoteEndpoints: remote.endpoints, now: monotonicMillis())
    var beforeConnect: [Data] = []  // survive a restart of the punching phase
    var announced = false
    var received = 0
    var lingerUntil: Int64?

    func queue(_ text: String) {
        let message = Data(text.utf8)
        do { try connection.send(message) } catch { print("(could not send: \(error))") }
        if !announced { beforeConnect.append(message) }
    }

    options.sends.forEach(queue)
    let inbox = Inbox()
    inbox.start()
    print("Connecting... (type a message and press Enter; /quit leaves)")

    while true {
        for message in connection.pump(socket: socket, timeoutMs: 20) {
            received += 1
            print("peer> " + (String(data: message, encoding: .utf8) ?? "<\(message.count) bytes of binary data>"))
        }
        for line in inbox.drain() {
            if line == "/quit" { exit(0) }
            if !line.isEmpty { queue(line) }
        }

        switch connection.state {
        case .punching:
            break
        case .established:
            if !announced {
                announced = true
                beforeConnect.removeAll()
                print("Connected to \(connection.peerEndpoint.map(describe) ?? "peer"). Messages are end-to-end encrypted.")
            }
        case .failed(let reason):
            if reason == .punchTimeout && !announced && attempts < maxAttempts {
                attempts += 1
                print("Still trying to reach your peer... (\(attempts)/\(maxAttempts))")
                connection = Connection(session: session, remoteEndpoints: remote.endpoints, now: monotonicMillis())
                for message in beforeConnect { try? connection.send(message) }
            } else {
                switch reason {
                case .punchTimeout: print("Could not connect. Both sides must be running and paste each other's ticket within a minute or so. If you are on different networks, a firewall or mobile carrier NAT may be blocking direct connections.")
                case .peerUnreachable: print("Your peer stopped responding: offline, or their network changed.")
                case .idleTimeout: print("The connection went silent.")
                }
                exit(1)
            }
        }

        if let limit = options.exitAfter, received >= limit {
            // Stay a moment so our own messages and acknowledgements still get through.
            if lingerUntil == nil { lingerUntil = monotonicMillis() + 2000 }
        }
        if let until = lingerUntil, monotonicMillis() >= until { exit(0) }
    }
}

do {
    try run()
} catch {
    fail("error: \(error)")
}
