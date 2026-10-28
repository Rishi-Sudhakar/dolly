package com.dolly.core

import java.util.TreeMap

/**
 * Selective-ack reliable delivery of opaque datagram payloads over a lossy link. No I/O, no clock:
 * the caller passes `now` (milliseconds) so behaviour is deterministic and testable.
 *
 * Ordering is not enforced: the ratchet tolerates reordering and chunks reassemble out of order.
 * A sequence number only counts as received after the caller authenticated it via [markReceived].
 */
internal class ReliableChannel {
    companion object {
        const val WINDOW = 32L
        const val MAX_RETRIES = 8
        const val INITIAL_RTO = 500L
        const val MIN_RTO = 200L
        const val MAX_RTO = 4000L
    }

    class Transmission(val seq: Long, val payload: ByteArray)

    private class Pending(val payload: ByteArray, var sentAt: Long, var retries: Int = 0)

    // Sender
    private val pending = TreeMap<Long, Pending>()
    private val queue = ArrayDeque<ByteArray>()
    var nextSeq = 0L
        private set
    var failed = false
        private set
    private var srtt: Double? = null
    private var rttvar = 0.0
    private var rto = INITIAL_RTO

    // Receiver
    var ackNext = 0L
        private set
    private val ahead = HashSet<Long>()
    var ackDue = false

    // region Sender

    fun enqueue(payload: ByteArray) = queue.addLast(payload)

    /** Retransmissions that timed out, then new packets that fit the window. */
    fun dueTransmissions(now: Long): List<Transmission> {
        val out = ArrayList<Transmission>()
        for ((seq, p) in pending) {
            val timeout = minOf(rto * (1L shl p.retries), MAX_RTO)
            if (now - p.sentAt < timeout) continue
            if (p.retries >= MAX_RETRIES) {
                failed = true
                return emptyList()
            }
            p.retries++
            p.sentAt = now
            out.add(Transmission(seq, p.payload))
        }
        while (queue.isNotEmpty()) {
            val base = if (pending.isEmpty()) nextSeq else pending.firstKey()
            if (nextSeq - base >= WINDOW) break
            val payload = queue.removeFirst()
            val seq = nextSeq++
            pending[seq] = Pending(payload, now)
            out.add(Transmission(seq, payload))
        }
        return out
    }

    fun onAck(ackNext: Long, sack: Long, now: Long) {
        if (ackNext > nextSeq) return  // acknowledges something we never sent
        val entries = pending.entries.iterator()
        while (entries.hasNext()) {
            val (seq, p) = entries.next()
            var acked = seq < ackNext
            if (!acked) {
                val distance = seq - ackNext
                if (distance in 1L..32L) acked = ((sack shr (distance - 1).toInt()) and 1L) == 1L
            }
            if (!acked) continue
            entries.remove()
            if (p.retries == 0) sampleRtt((now - p.sentAt).toDouble())  // Karn: skip retransmitted packets
        }
    }

    private fun sampleRtt(sample: Double) {
        val s = srtt
        if (s != null) {
            rttvar = 0.75 * rttvar + 0.25 * Math.abs(s - sample)
            srtt = 0.875 * s + 0.125 * sample
        } else {
            srtt = sample
            rttvar = sample / 2
        }
        val estimate = ((srtt ?: sample) + 4 * rttvar).toLong()
        rto = minOf(maxOf(estimate, MIN_RTO), MAX_RTO)
    }

    // endregion

    // region Receiver

    fun hasReceived(seq: Long): Boolean = seq < ackNext || seq in ahead

    /** Inside the window the peer is allowed to use. */
    fun canAccept(seq: Long): Boolean = seq >= ackNext && seq - ackNext <= 32

    fun markReceived(seq: Long) {
        if (seq == ackNext) {
            ackNext++
            while (ahead.remove(ackNext)) ackNext++
        } else if (seq > ackNext) {
            ahead.add(seq)
        }
        ackDue = true
    }

    /** Bit i set means `ackNext + 1 + i` was received. */
    val sack: Long
        get() {
            var bits = 0L
            for (seq in ahead) {
                val distance = seq - ackNext
                if (distance in 1L..32L) bits = bits or (1L shl (distance - 1).toInt())
            }
            return bits
        }

    // endregion
}
