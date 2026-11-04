import CryptoKit
import DollyCore
import Foundation
import Security

nonisolated struct KeychainError: Error { let status: OSStatus }

/// Keeps the store's master key where the app cannot be talked into revealing it. On a device the key is
/// sealed to a Secure Enclave P-256 key that never leaves the chip: unsealing needs the Enclave, on this
/// phone, while it is unlocked. The simulator has no Secure Enclave, so there the key sits in the Keychain
/// directly (still this-device-only).
nonisolated enum KeyVault {
    private static let service = "app.dolly.keys"
    private static let wrappedKey = "master"
    private static let enclaveKey = "enclave"
    private static let info = Data("dolly/v1/master-key".utf8)
    private static let publicKeyLength = 65  // uncompressed P-256 point

    static func masterKey() throws -> Data {
        if let stored = read(wrappedKey) { return try unwrap(stored) }
        let master = Store.newMasterKey()
        try write(wrappedKey, wrap(master))
        return master
    }

    private static func wrap(_ master: Data) throws -> Data {
        guard SecureEnclave.isAvailable else { return master }
        let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, nil)!
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        try write(enclaveKey, key.dataRepresentation)

        let ephemeral = P256.KeyAgreement.PrivateKey()
        let sealed = try ChaChaPoly.seal(master, using: wrappingKey(ephemeral.sharedSecretFromKeyAgreement(with: key.publicKey))).combined
        return ephemeral.publicKey.x963Representation + sealed
    }

    private static func unwrap(_ stored: Data) throws -> Data {
        guard let enclave = read(enclaveKey) else { return stored }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: enclave)
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: stored.prefix(publicKeyLength))
        let secret = try key.sharedSecretFromKeyAgreement(with: ephemeral)
        return try ChaChaPoly.open(ChaChaPoly.SealedBox(combined: stored.dropFirst(publicKeyLength)), using: wrappingKey(secret))
    }

    private static func wrappingKey(_ secret: SharedSecret) -> SymmetricKey {
        secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: info, outputByteCount: 32)
    }

    private static func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    }

    private static func read(_ account: String) -> Data? {
        var request = query(account)
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        return SecItemCopyMatching(request as CFDictionary, &result) == errSecSuccess ? result as? Data : nil
    }

    /// Stores `data`, replacing any earlier item (a first attempt may have been interrupted).
    private static func write(_ account: String, _ data: Data) throws {
        SecItemDelete(query(account) as CFDictionary)
        var item = query(account)
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }
}
