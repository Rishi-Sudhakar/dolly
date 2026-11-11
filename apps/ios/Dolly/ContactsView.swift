import DollyCore
import SwiftUI

struct ContactsView: View {
    @Environment(AppModel.self) private var model
    @State private var inSession = false
    @State private var showingMyKey = false

    var body: some View {
        NavigationStack {
            List {
                ForEach(model.contacts, id: \.identityKey) { contact in
                    NavigationLink {
                        ContactDetailView(contact: contact, connect: connect)
                    } label: {
                        Label {
                            Text(contact.name)
                        } icon: {
                            Image(systemName: contact.verified ? "checkmark.seal.fill" : "person.crop.circle")
                        }
                    }
                }
            }
            .overlay {
                if model.contacts.isEmpty {
                    ContentUnavailableView(
                        "No contacts yet",
                        systemImage: "person.2",
                        description: Text("Tap + to connect with someone. You each send the other one link, by RCS or any messenger.")
                    )
                }
            }
            .navigationTitle("Dolly")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("My key", systemImage: "key") { showingMyKey = true }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("New connection", systemImage: "plus") { connect(nil) }
                }
            }
        }
        .fullScreenCover(isPresented: $inSession, onDismiss: { model.endSession() }) { SessionView() }
        .sheet(isPresented: $showingMyKey) { MyKeyView() }
        .alert("Dolly", isPresented: noticeShown) {
        } message: {
            Text(model.notice ?? "")
        }
    }

    /// Problems during a session are shown inside it; this alert is for the rest (such as storage errors).
    private var noticeShown: Binding<Bool> {
        Binding(get: { !inSession && model.notice != nil }, set: { if !$0 { model.notice = nil } })
    }

    private func connect(_ contact: Contact?) {
        inSession = true
        Task { await model.beginPairing(with: contact) }
    }
}

private struct MyKeyView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(model.myFingerprint).font(.title3.monospaced()).textSelection(.enabled)
                } footer: {
                    Text("This identifies you to your contacts. Compare it with theirs over a call to be sure no one is in the middle. It is created on this phone and never leaves it.")
                }
            }
            .navigationTitle("My key")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
        .presentationDetents([.medium])
    }
}
