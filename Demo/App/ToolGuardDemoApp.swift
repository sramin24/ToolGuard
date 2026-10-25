import SwiftUI

@main
struct ToolGuardDemoApp: App {
    @State private var model = DemoModel()

    var body: some Scene {
        WindowGroup("ToolGuard Demo") {
            ContentView()
                .environment(model)
                .frame(minWidth: 1100, minHeight: 640)
        }
    }
}
