import DollyCore
import Foundation

/// The encrypted store, behind an actor so file I/O never runs on the main thread.
actor Database {
    private let store: Store

    init() throws {
        var directory = try FileManager.default
            .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
            .appendingPathComponent("Vault", isDirectory: true)
        store = try Store(directory: directory, masterKey: KeyVault.masterKey())
        // The master key never leaves this device, so a restored backup could not be read anyway.
        var excluded = URLResourceValues()
        excluded.isExcludedFromBackup = true
        try directory.setResourceValues(excluded)
    }

    func identity() throws -> Identity { try store.identity() }
    func contacts() throws -> [Contact] { try store.contacts() }
    func save(_ contact: Contact) throws { try store.save(contact) }
    func append(_ message: Message, with contact: Data) throws { try store.append(message, with: contact) }
    func messages(with contact: Data) throws -> [Message] { try store.messages(with: contact) }
}
