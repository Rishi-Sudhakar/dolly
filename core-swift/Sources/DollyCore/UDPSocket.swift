import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public func monotonicMillis() -> Int64 {
    Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000)
}

/// A bare IPv4 UDP socket (POSIX, no dependencies). The same socket must be used for STUN and for
/// talking to the peer, otherwise the NAT mapping STUN reported is not the one the peer reaches.
public final class UDPSocket {
    private let fd: Int32
    public let localPort: UInt16

    public init(port: UInt16 = 0) throws {
        let s = socket(AF_INET, SOCK_DGRAM, 0)
        guard s >= 0 else { throw DollyError.connectionFailed }

        var address = UDPSocket.sockaddrIn(address: in_addr(s_addr: 0), port: port)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else {
            close(s)
            throw DollyError.connectionFailed
        }

        var local = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &length) }
        }
        guard named == 0 else {
            close(s)
            throw DollyError.connectionFailed
        }
        fd = s
        localPort = UInt16(bigEndian: local.sin_port)
    }

    deinit { close(fd) }

    public func send(_ data: Data, to endpoint: Endpoint) throws {
        guard endpoint.kind == .v4 else { throw DollyError.badEndpoint }
        // The four address bytes are already in network order, which is how s_addr is laid out in memory.
        let raw = endpoint.address.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
        var address = UDPSocket.sockaddrIn(address: in_addr(s_addr: raw), port: endpoint.port)
        let sent = data.withUnsafeBytes { buffer in
            withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, buffer.baseAddress, buffer.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent >= 0 else { throw DollyError.connectionFailed }
    }

    /// Waits up to `timeoutMs` for one datagram.
    public func receive(timeoutMs: Int32) -> (Data, Endpoint)? {
        var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&descriptor, 1, timeoutMs) > 0, descriptor.revents & Int16(POLLIN) != 0 else { return nil }

        var buffer = [UInt8](repeating: 0, count: 2048)
        let capacity = buffer.count
        var from = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let count = withUnsafeMutablePointer(to: &from) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                recvfrom(fd, &buffer, capacity, 0, $0, &length)
            }
        }
        guard count > 0, let endpoint = UDPSocket.endpoint(from) else { return nil }
        return (Data(buffer[0..<count]), endpoint)
    }

    /// IPv4 addresses of `host` (DNS lookup).
    public static func resolve(host: String, port: UInt16) -> [Endpoint] {
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_DGRAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &result) == 0, let first = result else { return [] }
        defer { freeaddrinfo(result) }

        var endpoints: [Endpoint] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let current = cursor {
            if current.pointee.ai_family == AF_INET, let sa = current.pointee.ai_addr {
                let sin = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                if let endpoint = UDPSocket.endpoint(sin) { endpoints.append(endpoint) }
            }
            cursor = current.pointee.ai_next
        }
        return endpoints
    }

    private static func sockaddrIn(address: in_addr, port: UInt16) -> sockaddr_in {
        var sin = sockaddr_in()
        #if canImport(Darwin)
        sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        #endif
        sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = port.bigEndian
        sin.sin_addr = address
        return sin
    }

    private static func endpoint(_ sin: sockaddr_in) -> Endpoint? {
        let bytes = withUnsafeBytes(of: sin.sin_addr.s_addr) { Data($0) }
        return try? Endpoint(kind: .v4, address: bytes, port: UInt16(bigEndian: sin.sin_port))
    }
}

public extension Connection {
    /// One turn of the I/O loop: read what arrived (waiting up to `timeoutMs` for the first
    /// datagram), then transmit whatever is due. Returns messages that completed.
    func pump(socket: UDPSocket, timeoutMs: Int32 = 20) -> [Data] {
        var messages: [Data] = []
        var wait = timeoutMs
        while let (datagram, from) = socket.receive(timeoutMs: wait) {
            messages += receive(datagram, from: from, now: monotonicMillis())
            wait = 0
        }
        for packet in poll(now: monotonicMillis()) { try? socket.send(packet.bytes, to: packet.endpoint) }
        return messages
    }
}

public struct StunResult {
    public let server: Endpoint
    public let mapped: Endpoint
}

public enum StunClient {
    /// Asks each server for the public address of `socket`. Retries a few times because UDP drops packets.
    public static func discover(socket: UDPSocket, servers: [Endpoint], timeoutMs: Int64 = 2500) -> [StunResult] {
        var transactions: [Data: Endpoint] = [:]
        for server in servers { transactions[Stun.newTransactionID()] = server }
        var results: [StunResult] = []

        let start = monotonicMillis()
        var lastSend: Int64 = -1_000_000
        while monotonicMillis() - start < timeoutMs, !transactions.isEmpty {
            if monotonicMillis() - lastSend >= 500 {
                lastSend = monotonicMillis()
                for (txid, server) in transactions {
                    try? socket.send(Stun.bindingRequest(transactionID: txid), to: server)
                }
            }
            guard let (datagram, _) = socket.receive(timeoutMs: 50), datagram.count >= 20 else { continue }
            let txid = datagram.subdata(in: 8..<20)
            if let server = transactions[txid], let mapped = try? Stun.parseBindingResponse(datagram, transactionID: txid) {
                results.append(StunResult(server: server, mapped: mapped))
                transactions[txid] = nil
            }
        }
        return results
    }
}
