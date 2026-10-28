import Foundation

/// Application messages carried inside encrypted session payloads.
///
/// ```
/// hello : 0x00
/// chunk : 0x01 | messageId(4) | index(2) | count(2) | data   (data <= 1013 bytes)
/// ```
enum AppMessage {
    static let hello: UInt8 = 0
    static let chunk: UInt8 = 1
    static let chunkHeaderLength = 9
    static let maxChunkData = Session.maxPayload - chunkHeaderLength
    static let maxChunks = 1024
    /// About 1 MiB. Larger transfers belong to a future file-transfer layer.
    static var maxMessageSize: Int { maxChunks * maxChunkData }

    static func encodeChunks(_ message: Data, id: UInt32) throws -> [Data] {
        let count = max(1, (message.count + maxChunkData - 1) / maxChunkData)
        guard count <= maxChunks else { throw DollyError.messageTooLarge }
        return (0..<count).map { index in
            let start = message.startIndex + index * maxChunkData
            let end = min(start + maxChunkData, message.endIndex)
            var w = ByteWriter()
            w.u8(chunk)
            w.u32(id)
            w.u16(UInt16(index))
            w.u16(UInt16(count))
            w.bytes(Data(message[start..<end]))
            return w.data
        }
    }
}

/// Puts chunks back together, in any arrival order, within fixed memory bounds.
final class Reassembler {
    static let maxPartialMessages = 16
    static let maxBufferedBytes = 4 * 1024 * 1024

    private struct Partial {
        let count: Int
        var chunks: [Int: Data] = [:]
    }

    private var partials: [UInt32: Partial] = [:]
    private var arrival: [UInt32] = []
    private var bufferedBytes = 0

    /// `chunk` is the payload after the leading type byte. Returns the whole message when complete.
    func add(chunk: Data) throws -> Data? {
        var r = ByteReader(chunk)
        let id = try r.u32()
        let index = Int(try r.u16())
        let count = Int(try r.u16())
        let data = try r.bytes(r.remaining)
        guard (1...AppMessage.maxChunks).contains(count), index < count,
              data.count <= AppMessage.maxChunkData
        else { throw DollyError.malformedPacket }

        if let existing = partials[id] {
            guard existing.count == count else { throw DollyError.malformedPacket }
        } else {
            if partials.count >= Reassembler.maxPartialMessages { evictOldest() }
            partials[id] = Partial(count: count)
            arrival.append(id)
        }
        guard partials[id]?.chunks[index] == nil else { return nil }  // duplicate chunk
        guard bufferedBytes + data.count <= Reassembler.maxBufferedBytes else { throw DollyError.malformedPacket }

        partials[id]?.chunks[index] = data
        bufferedBytes += data.count

        guard let partial = partials[id], partial.chunks.count == partial.count else { return nil }
        var message = Data()
        for i in 0..<partial.count { message.append(partial.chunks[i]!) }
        discard(id)
        return message
    }

    private func evictOldest() {
        if let oldest = arrival.first { discard(oldest) }
    }

    private func discard(_ id: UInt32) {
        if let partial = partials.removeValue(forKey: id) {
            bufferedBytes -= partial.chunks.values.reduce(0) { $0 + $1.count }
        }
        arrival.removeAll { $0 == id }
    }
}
