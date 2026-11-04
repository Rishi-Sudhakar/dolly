import CryptoKit
import DollyCore
import Foundation

nonisolated enum Fingerprint {
    /// A short digest of an identity key ("a1b2 c3d4 e5f6 0718 293a"), for comparing out of band.
    static func of(_ identityKey: Data) -> String {
        let hex = Data(SHA256.hash(data: identityKey).prefix(10)).hex
        return stride(from: 0, to: hex.count, by: 4).map { String(hex.dropFirst($0).prefix(4)) }.joined(separator: " ")
    }
}
