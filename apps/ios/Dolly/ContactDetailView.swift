import DollyCore
import SwiftUI

struct ContactDetailView: View {
    @Environment(AppModel.self) private var model
    let contact: Contact
    let connect: (Contact) -> Void
    @State private var history: [Message] = []
    @State private var showingInfo = false

    /// The latest saved version, since renaming or verifying changes it while this screen is open.
    private var current: Contact { model.contacts.first { $0.identityKey == contact.identityKey } ?? contact }

    var body: some View {
        Group {
            if history.isEmpty {
                ContentUnavailableView("No messages yet", systemImage: "bubble.left", description: Text("Tap Connect when you both have Dolly open."))
            } else {
                MessageList(messages: history)
            }
        }
        .navigationTitle(current.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .secondaryAction) {
                Button("Details", systemImage: "info.circle") { showingInfo = true }
            }
            ToolbarItem(placement: .primaryAction) {
                Button("Connect", systemImage: "bolt.horizontal.fill") { connect(current) }
            }
        }
        .task { history = await model.history(with: contact) }
        .sheet(isPresented: $showingInfo) { ContactInfoView(contact: current) }
    }
}

private struct ContactInfoView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let contact: Contact
    @State private var name: String

    init(contact: Contact) {
        self.contact = contact
        _name = State(initialValue: contact.name)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Name") { TextField("Name", text: $name) }
                Section {
                    Text(Fingerprint.of(contact.identityKey)).font(.title3.monospaced()).textSelection(.enabled)
                    Toggle("I compared this with them", isOn: verified)
                } header: {
                    Text("Their key")
                } footer: {
                    Text("Compare it with what they see under My key, over a call or in person.")
                }
            }
            .navigationTitle("Details")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        var renamed = contact
                        renamed.name = name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? contact.name : name
                        Task {
                            await model.update(renamed)
                            dismiss()
                        }
                    }
                }
            }
        }
        .presentationDetents([.medium])
    }

    private var verified: Binding<Bool> {
        Binding(
            get: { contact.verified },
            set: { newValue in
                var changed = contact
                changed.verified = newValue
                Task { await model.update(changed) }
            }
        )
    }
}
