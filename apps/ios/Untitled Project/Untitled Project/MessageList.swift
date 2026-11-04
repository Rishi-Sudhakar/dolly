import DollyCore
import SwiftUI

struct MessageList: View {
    let messages: [Message]

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 6) {
                    ForEach(messages, id: \.id) { message in
                        Bubble(message: message).id(message.id)
                    }
                }
                .padding()
            }
            .defaultScrollAnchor(.bottom)
            .onChange(of: messages.count) {
                if let last = messages.last { withAnimation { proxy.scrollTo(last.id, anchor: .bottom) } }
            }
        }
    }
}

private struct Bubble: View {
    let message: Message

    var body: some View {
        HStack {
            if message.outgoing { Spacer(minLength: 48) }
            Text(message.text)
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .foregroundStyle(message.outgoing ? Color.white : Color.primary)
                .background(message.outgoing ? Color.accentColor : Color(.secondarySystemBackground), in: .rect(cornerRadius: 18))
            if !message.outgoing { Spacer(minLength: 48) }
        }
    }
}
