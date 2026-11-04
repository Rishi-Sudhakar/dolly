import DollyCore
import SwiftUI
import UIKit

/// Everything between "tap connect" and "leave": swap links, connect, chat.
struct SessionView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                switch model.phase {
                case .idle, .preparing:
                    ProgressView("Finding your network address…")
                case .ready, .connecting:
                    Pairing()
                case .connected, .ended:
                    Chat()
                }
            }
            .navigationTitle(model.peer?.name ?? "New connection")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(model.phase == .connected ? "Leave" : "Close") { dismiss() }
                }
            }
        }
        .interactiveDismissDisabled(model.phase == .connected)
    }
}

private struct Pairing: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Form {
            Section {
                Text(model.myTicket)
                    .font(.caption.monospaced())
                    .lineLimit(3)
                ShareLink(item: model.myTicket) { Label("Share your link", systemImage: "square.and.arrow.up") }
                Button("Copy your link", systemImage: "doc.on.doc") { UIPasteboard.general.string = model.myTicket }
            } header: {
                Text("1. Send your link")
            } footer: {
                Text("Send it in any messenger or by RCS. Your key fingerprint is \(model.myFingerprint); read it to your contact on a call to be sure the link is really yours.")
            }

            Section {
                if model.phase == .connecting {
                    HStack(spacing: 12) {
                        ProgressView()
                        Text("Connecting…")
                    }
                    LabeledContent("Their fingerprint", value: model.peerFingerprint)
                } else {
                    PasteButton(payloadType: String.self) { strings in
                        Task { @MainActor in model.connect(pasted: strings.joined()) }
                    }
                }
                if let notice = model.notice {
                    Text(notice).foregroundStyle(.red)
                }
            } header: {
                Text("2. Paste their link")
            } footer: {
                Text("Both phones must be open and have each other's link within about a minute.")
            }

            if let warning = model.networkWarning {
                Section { Text(warning).foregroundStyle(.orange) }
            }
        }
    }
}

private struct Chat: View {
    @Environment(AppModel.self) private var model
    @State private var draft = ""

    var body: some View {
        VStack(spacing: 0) {
            MessageList(messages: model.messages)
            if case .ended(let reason) = model.phase {
                Text(reason)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding()
            } else {
                composer
            }
        }
    }

    private var composer: some View {
        HStack(alignment: .bottom, spacing: 8) {
            TextField("Message", text: $draft, axis: .vertical)
                .lineLimit(1...5)
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .background(Color(.secondarySystemBackground), in: .rect(cornerRadius: 18))
            Button("Send", systemImage: "arrow.up.circle.fill") {
                model.send(draft)
                draft = ""
            }
            .labelStyle(.iconOnly)
            .font(.title)
            .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
        .padding()
    }
}
