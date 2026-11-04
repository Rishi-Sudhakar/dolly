import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

public func monotonicMillis() -> Int64 {
    Int64(DispatchTime.now().uptimeNanoseconds / 1_000_000)
}

/// A bare dual-stack UDP socket (POSIX, no dependencies): one socket carries both IPv6 and IPv4 traffic,
/// with IPv4 peers addressed as IPv4-mapped IPv6 addresses. The same socket must be used for STUN and for
/// talking to the peer, otherwise the NAT mapping STUN reported is not the one the peer reaches.
public final class UDPSocket {
    private static let v4MappedPrefix = Data([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])

    private let fd: Int32
    public let localPort: UInt16

    public init(port: UInt16 = 0) throws {
        let s = socket(AF_INET6, SOCK_DGRAM, 0)
        guard s >= 0 else { throw DollyError.connectionFailed }

        var v6Only: Int32 = 0
        let dualStack = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &v6Only, socklen_t(MemoryLayout<Int32>.size))
        var address = UDPSocket.sockaddrIn6(address: Data(count: 16), port: port)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(s, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
            }
        }
        guard dualStack == 0, bound == 0 else {
            close(s)
            throw DollyError.connectionFailed
        }

        var local = sockaddr_in6()
        var length = socklen_t(MemoryLayout<sockaddr_in6>.size)
        let named = withUnsafeMutablePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &length) }
        }
        guard named == 0 else {
            close(s)
            throw DollyError.connectionFailed
        }
        fd = s
        localPort = UInt16(bigEndian: local.sin6_port)
    }

    deinit { close(fd) }

    public func send(_ data: Data, to endpoint: Endpoint) throws {
        var address = UDPSocket.sockaddrIn6(
            address: endpoint.kind == .v6 ? endpoint.address : UDPSocket.v4MappedPrefix + endpoint.address,
            port: endpoint.port
        )
        let sent = data.withUnsafeBytes { buffer in
            withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, buffer.baseAddress, buffer.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
                }
            }
        }
        guard sent >= 0 else { throw DollyError.connectionFailed }
    }

    /// Waits up to `timeoutMs` for one datagram. IPv4 senders are reported as IPv4 endpoints.
    public func receive(timeoutMs: Int32) -> (Data, Endpoint)? {
        var descriptor = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&descriptor, 1, timeoutMs) > 0, descriptor.revents & Int16(POLLIN) != 0 else { return nil }

        var buffer = [UInt8](repeating: 0, count: 2048)
        let capacity = buffer.count
        var from = sockaddr_in6()
        var length = socklen_t(MemoryLayout<sockaddr_in6>.size)
        let count = withUnsafeMutablePointer(to: &from) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                recvfrom(fd, &buffer, capacity, 0, $0, &length)
            }
        }
        guard count > 0, let endpoint = UDPSocket.endpoint(from) else { return nil }
        return (Data(buffer[0..<count]), endpoint)
    }

    /// IPv4 and IPv6 addresses of `host` (DNS lookup).
    public static func resolve(host: String, port: UInt16) -> [Endpoint] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &result) == 0, let first = result else { return [] }
        defer { freeaddrinfo(result) }

        var endpoints: [Endpoint] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let current = cursor {
            if let sa = current.pointee.ai_addr {
                switch current.pointee.ai_family {
                case AF_INET:
                    let sin = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                    if let endpoint = UDPSocket.endpoint(sin) { endpoints.append(endpoint) }
                case AF_INET6:
                    let sin6 = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                    if let endpoint = UDPSocket.endpoint(sin6) { endpoints.append(endpoint) }
                default:
                    break
                }
            }
            cursor = current.pointee.ai_next
        }
        return endpoints
    }

    /// Addresses of this machine's active network interfaces at `port`: IPv4 (loopback and link-local
    /// excluded) and global IPv6 (2000::/3). Candidates for peers on the same LAN, where a router often
    /// cannot loop packets back through its public address, and for peers reachable over IPv6 without NAT.
    public static func localAddresses(port: UInt16) -> [Endpoint] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return [] }
        defer { freeifaddrs(list) }

        var endpoints: [Endpoint] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            let flags = Int32(current.pointee.ifa_flags)
            if let sa = current.pointee.ifa_addr, flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0 {
                if sa.pointee.sa_family == sa_family_t(AF_INET) {
                    let sin = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                    let bytes = withUnsafeBytes(of: sin.sin_addr.s_addr) { Data($0) }
                    if !(bytes[0] == 169 && bytes[1] == 254), let endpoint = try? Endpoint(kind: .v4, address: bytes, port: port) {
                        endpoints.append(endpoint)
                    }
                } else if sa.pointee.sa_family == sa_family_t(AF_INET6) {
                    let sin6 = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                    let bytes = withUnsafeBytes(of: sin6.sin6_addr) { Data($0) }
                    if bytes[0] & 0xE0 == 0x20, let endpoint = try? Endpoint(kind: .v6, address: bytes, port: port) {
                        endpoints.append(endpoint)
                    }
                }
            }
            cursor = current.pointee.ifa_next
        }
        return endpoints
    }

    private static func sockaddrIn6(address: Data, port: UInt16) -> sockaddr_in6 {
        var sin6 = sockaddr_in6()
        #if canImport(Darwin)
        sin6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        #endif
        sin6.sin6_family = sa_family_t(AF_INET6)
        sin6.sin6_port = port.bigEndian
        withUnsafeMutableBytes(of: &sin6.sin6_addr) { $0.copyBytes(from: address) }
        return sin6
    }

    private static func endpoint(_ sin: sockaddr_in) -> Endpoint? {
        let bytes = withUnsafeBytes(of: sin.sin_addr.s_addr) { Data($0) }
        return try? Endpoint(kind: .v4, address: bytes, port: UInt16(bigEndian: sin.sin_port))
    }

    private static func endpoint(_ sin6: sockaddr_in6) -> Endpoint? {
        let bytes = withUnsafeBytes(of: sin6.sin6_addr) { Data($0) }
        let port = UInt16(bigEndian: sin6.sin6_port)
        if bytes.prefix(12) == v4MappedPrefix { return try? Endpoint(kind: .v4, address: Data(bytes.suffix(4)), port: port) }
        return try? Endpoint(kind: .v6, address: bytes, port: port)
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
