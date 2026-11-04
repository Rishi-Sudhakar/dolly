import SwiftUI

@main
struct DollyApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContactsView()
                .environment(model)
                .task { await model.start() }
        }
    }
}
