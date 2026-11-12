import SwiftUI

struct DevicesView: View {
    @ObservedObject var model: DiscoveryViewModel
    /// Called when the user asks to port-scan a device.
    let onScan: (Device, PortPreset) -> Void

    var body: some View {
        NavigationStack {
            List {
                controlSection
                if model.permissionDenied {
                    permissionSection
                }
                if !model.devices.isEmpty {
                    Section {
                        ForEach(model.devices) { device in
                            NavigationLink(value: device.address) {
                                DeviceRow(device: device)
                            }
                        }
                    } header: {
                        Text(verbatim: model.devices.count == 1 ? "1 device" : "\(model.devices.count) devices")
                    }
                }
            }
            .navigationTitle("Devices")
            .navigationDestination(for: String.self) { address in
                DeviceDetailView(model: model, address: address, onScan: onScan)
            }
        }
    }

    private var controlSection: some View {
        Section {
            if let network = model.network {
                LabeledContent("Network", value: network.cidr)
                if network.prefix < 20 {
                    Text(verbatim: "Your network has more than 4,096 addresses, so only the 256 around this device are searched.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } else {
                Text("Not connected to Wi-Fi")
                    .foregroundStyle(.secondary)
            }

            if model.isRunning {
                VStack(alignment: .leading, spacing: 8) {
                    ProgressView(value: model.progress)
                    Text(verbatim: model.status)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .padding(.vertical, 4)

                Button("Stop", role: .destructive) {
                    model.stop()
                }
            } else {
                Button {
                    model.start()
                } label: {
                    Label("Find devices", systemImage: "magnifyingglass")
                }
            }

            if let summary = model.summary {
                Text(verbatim: summary)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            ForEach(model.notes, id: \.self) { note in
                Text(verbatim: note)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        } footer: {
            Text("Finds devices on your Wi-Fi with ping, TCP and Bonjour. iOS does not let apps read hardware (MAC) addresses, so manufacturers are not shown.")
        }
    }

    private var permissionSection: some View {
        Section {
            Label {
                Text("iOS blocked access to the local network. If you were just asked, tap Allow and search again. Otherwise turn on Port Scanner in Settings, under Privacy & Security, Local Network.")
                    .font(.footnote)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
        }
    }
}

struct DeviceDetailView: View {
    @ObservedObject var model: DiscoveryViewModel
    let address: String
    let onScan: (Device, PortPreset) -> Void

    var body: some View {
        let device = model.device(at: address) ?? Device(address: address)
        List {
            Section {
                LabeledContent("Address", value: device.address)
                if let hostName = device.hostName {
                    LabeledContent("Host name", value: hostName)
                }
                if let deviceModel = device.model {
                    let family = device.modelDescription ?? deviceModel
                    LabeledContent("Model", value: family == deviceModel ? deviceModel : "\(family) (\(deviceModel))")
                }
                if let latency = device.latency {
                    LabeledContent("Response time", value: Device.format(latency: latency))
                }
                LabeledContent("Found by", value: device.methodsText)
            }

            Section {
                Button("Quick scan (top 100 ports)") {
                    onScan(device, .quick)
                }
                Button("Standard scan (top 1000 ports)") {
                    onScan(device, .standard)
                }
                Button("All ports (1-65535)") {
                    onScan(device, .all)
                }
            } header: {
                Text("Scan this device")
            }

            if !device.services.isEmpty {
                Section {
                    ForEach(device.services, id: \.self) { service in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(verbatim: service.title)
                            Text(verbatim: service.detail)
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text("Bonjour services")
                }
            }
        }
        .navigationTitle(device.title)
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct DeviceRow: View {
    let device: Device

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: device.symbolName(thisDevice: UIDevice.current.userInterfaceIdiom == .pad ? "ipad" : "iphone"))
                .font(.title3)
                .frame(width: 32)
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: device.title)
                Text(verbatim: device.subtitle)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }
}

extension Device {
    /// An SF Symbol that suggests what kind of device this is.
    /// `thisDevice` is the symbol for the iPhone or iPad running the app.
    func symbolName(thisDevice: String) -> String {
        if isThisDevice {
            return thisDevice
        }
        switch modelDescription {
        case "Apple TV": return "appletv"
        case "HomePod", "HomePod mini": return "homepod"
        case "iPhone", "iPod touch": return "iphone"
        case "iPad": return "ipad"
        case "MacBook", "MacBook Pro", "MacBook Air": return "laptopcomputer"
        case "Mac mini": return "macmini"
        case "iMac", "Mac Pro", "Mac": return "desktopcomputer"
        default: break
        }

        let model = (self.model ?? "").lowercased()
        let types = Set(services.map { $0.type })
        func has(_ candidates: [String]) -> Bool {
            !types.isDisjoint(with: candidates)
        }
        if has(["_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_uscan._tcp", "_scanner._tcp"]) { return "printer" }
        if has(["_googlecast._tcp"]) {
            // Google Home and Nest speakers also announce Google Cast.
            let speakerWords = ["home", "nest", "speaker", "audio"]
            return speakerWords.contains { model.contains($0) } ? "hifispeaker" : "tv"
        }
        if has(["_amzn-wplay._tcp", "_androidtvremote2._tcp"]) || (has(["_airplay._tcp"]) && model.contains("tv")) { return "tv" }
        if has(["_raop._tcp", "_sonos._tcp", "_spotify-connect._tcp"]) { return "hifispeaker" }
        if has(["_hap._tcp", "_homekit._tcp", "_hue._tcp", "_esphomelib._tcp"]) { return "homekit" }
        if has(["_companion-link._tcp"]) { return "laptopcomputer.and.iphone" }
        if has(["_smb._tcp", "_afpovertcp._tcp", "_nfs._tcp", "_adisk._tcp", "_workstation._tcp", "_device-info._tcp", "_ssh._tcp", "_rfb._tcp"]) { return "desktopcomputer" }
        return "network"
    }
}
