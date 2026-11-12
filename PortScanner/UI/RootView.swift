import SwiftUI

/// The two tabs: finding devices, and scanning ports. Tapping "scan" on a
/// device switches to the port scan tab and starts the scan.
struct RootView: View {
    enum Tab: Hashable {
        case devices
        case scan
    }

    @StateObject private var scanModel = ScanViewModel()
    @StateObject private var discoveryModel = DiscoveryViewModel()
    @State private var tab: Tab = .devices
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        TabView(selection: $tab) {
            DevicesView(model: discoveryModel) { device, preset in
                tab = .scan
                scanModel.scan(device.address, preset: preset)
            }
            .tabItem {
                Label("Devices", systemImage: "network")
            }
            .tag(Tab.devices)

            ScanView(model: scanModel)
                .tabItem {
                    Label("Port scan", systemImage: "dot.radiowaves.left.and.right")
                }
                .tag(Tab.scan)
        }
        .onChange(of: scenePhase) { phase in
            switch phase {
            case .active:
                scanModel.refreshLocalNetwork()
                discoveryModel.refreshNetwork()
            case .background:
                scanModel.appMovedToBackground()
                discoveryModel.appMovedToBackground()
            default:
                break
            }
        }
    }
}
