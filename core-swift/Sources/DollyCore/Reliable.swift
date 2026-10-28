import Foundation

/// Selective-ack reliable delivery of opaque datagram payloads over a lossy link. No I/O, no clock:
/// the caller passes `now` (milliseconds) so behaviour is deterministic and testable.
///
/// Ordering is not enforced: the ratchet tolerates reordering and chunks reassemble out of order.
/// A sequence number only counts as received after the caller authenticated it via `markReceived`.
final class ReliableChannel {
    static let window: UInt32 = 32
    static let maxRetries = 8
    static let initialRTO: Int64 = 500
    static let minRTO: Int64 = 200
    static let maxRTO: Int64 = 4000

    private struct Pending {
        let payload: Data
        var sentAt: Int64
        var retries = 0
    }

    // Sender
    private var pending: [UInt32: Pending] = [:]
    private var queue: [Data] = []
    private(set) var nextSeq: UInt32 = 0
    private(set) var failed = false
    private var srtt: Double?
    private var rttvar: Double = 0
    private(set) var rto: Int64 = ReliableChannel.initialRTO

    // Receiver
    private(set) var ackNext: UInt32 = 0
    private var ahead = Set<UInt32>()
    var ackDue = false

    // MARK: Sender

    func enqueue(_ payload: Data) { queue.append(payload) }

    /// Retransmissions that timed out, then new packets that fit the window.
    func dueTransmissions(now: Int64) -> [(seq: UInt32, payload: Data)] {
        var out: [(seq: UInt32, payload: Data)] = []
        for seq in pending.keys.sorted() {
            guard var p = pending[seq] else { continue }
            let timeout = min(rto * Int64(1 << p.retries), ReliableChannel.maxRTO)
            guard now - p.sentAt >= timeout else { continue }
            if p.retries >= ReliableChannel.maxRetries {
                failed = true
                return []
            }
            p.retries += 1
            p.sentAt = now
            pending[seq] = p
            out.append((seq, p.payload))
        }
        while !queue.isEmpty {
            let base = pending.keys.min() ?? nextSeq
            guard nextSeq - base < ReliableChannel.window else { break }
            let payload = queue.removeFirst()
            let seq = nextSeq
            nextSeq += 1
            pending[seq] = Pending(payload: payload, sentAt: now)
            out.append((seq, payload))
        }
        return out
    }

    func onAck(ackNext: UInt32, sack: UInt32, now: Int64) {
        guard ackNext <= nextSeq else { return }  // acknowledges something we never sent
        for seq in pending.keys.sorted() {
            var acked = seq < ackNext
            if !acked {
                let distance = seq - ackNext
                if distance >= 1 && distance <= 32 { acked = (sack >> (distance - 1)) & 1 == 1 }
            }
            guard acked, let p = pending.removeValue(forKey: seq) else { continue }
            if p.retries == 0 { sampleRTT(Double(now - p.sentAt)) }  // Karn: skip retransmitted packets
        }
    }

    private func sampleRTT(_ sample: Double) {
        if let s = srtt {
            rttvar = 0.75 * rttvar + 0.25 * abs(s - sample)
            srtt = 0.875 * s + 0.125 * sample
        } else {
            srtt = sample
            rttvar = sample / 2
        }
        let estimate = Int64((srtt ?? sample) + 4 * rttvar)
        rto = min(max(estimate, ReliableChannel.minRTO), ReliableChannel.maxRTO)
    }

    var hasUnacked: Bool { !pending.isEmpty || !queue.isEmpty }

    // MARK: Receiver

    func hasReceived(_ seq: UInt32) -> Bool { seq < ackNext || ahead.contains(seq) }

    /// Inside the window the peer is allowed to use.
    func canAccept(_ seq: UInt32) -> Bool { seq >= ackNext && seq - ackNext <= 32 }

    func markReceived(_ seq: UInt32) {
        if seq == ackNext {
            ackNext += 1
            while ahead.remove(ackNext) != nil { ackNext += 1 }
        } else if seq > ackNext {
            ahead.insert(seq)
        }
        ackDue = true
    }

    /// Bit i set means `ackNext + 1 + i` was received.
    var sack: UInt32 {
        var bits: UInt32 = 0
        for seq in ahead {
            let distance = seq - ackNext
            if distance >= 1 && distance <= 32 { bits |= 1 << (distance - 1) }
        }
        return bits
    }
}
