import SwiftUI

@main
struct PortScannerApp: App {
    init() {
        FileDescriptorLimit.raise()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
        }
    }
}
