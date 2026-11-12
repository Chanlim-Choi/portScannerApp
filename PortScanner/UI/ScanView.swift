import SwiftUI

struct ScanView: View {
    @ObservedObject var model: ScanViewModel
    @FocusState private var keyboardFocused: Bool

    var body: some View {
        NavigationStack {
            List {
                targetSection
                optionsSection
                runSection
                if model.permissionDenied {
                    permissionSection
                }
                ForEach(model.hosts) { host in
                    HostSection(host: host)
                }
            }
            .navigationTitle("Port Scanner")
            .scrollDismissesKeyboard(.immediately)
            .alert("Check the input", isPresented: errorIsPresented) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(verbatim: model.errorMessage ?? "")
            }
        }
    }

    private var errorIsPresented: Binding<Bool> {
        Binding(
            get: { model.errorMessage != nil },
            set: { isPresented in
                if !isPresented {
                    model.errorMessage = nil
                }
            }
        )
    }

    private var targetSection: some View {
        Section {
            TextField("192.168.1.0/24", text: $model.targetText)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.numbersAndPunctuation)
                .font(.body.monospaced())
                .focused($keyboardFocused)
                .submitLabel(.go)
                .onSubmit {
                    model.start()
                }

            if let network = model.localNetwork {
                Button {
                    model.targetText = network.cidr
                } label: {
                    Label("Use my network (\(network.cidr))", systemImage: "wifi")
                }
            }
        } header: {
            Text("Target")
        } footer: {
            Text("An IP address, a hostname, a CIDR block (10.0.0.0/24) or a range (10.0.0.1-50). Separate several targets with spaces.")
        }
        .disabled(model.isScanning)
    }

    private var optionsSection: some View {
        Section {
            Picker("Ports", selection: $model.preset) {
                ForEach(PortPreset.allCases) { preset in
                    Text(verbatim: preset.title).tag(preset)
                }
            }

            if model.preset == .custom {
                TextField("22,80,443,8000-8100", text: $model.customPorts)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.numbersAndPunctuation)
                    .font(.body.monospaced())
            }

            Picker("Speed", selection: $model.timing) {
                ForEach(TimingTemplate.allCases) { timing in
                    Text(verbatim: timing.title).tag(timing)
                }
            }

            Toggle("Skip host discovery (-Pn)", isOn: $model.skipDiscovery)
        } header: {
            Text("Options")
        }
        .disabled(model.isScanning)
    }

    private var runSection: some View {
        Section {
            if model.isScanning {
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
                    keyboardFocused = false
                    model.start()
                } label: {
                    Label("Start scan", systemImage: "play.fill")
                }
                .disabled(!model.canStart)
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
        }
    }

    private var permissionSection: some View {
        Section {
            Label {
                Text("iOS blocked access to the local network. If you were just asked, tap Allow and scan again. Otherwise turn on Port Scanner in Settings, under Privacy & Security, Local Network.")
                    .font(.footnote)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
        }
    }
}

private struct HostSection: View {
    let host: HostResult

    var body: some View {
        Section {
            if host.ports.isEmpty {
                Text(verbatim: emptyText)
                    .foregroundStyle(.secondary)
            }
            ForEach(host.ports) { result in
                PortRow(result: result)
            }
        } header: {
            Text(verbatim: host.title)
                .textCase(nil)
        } footer: {
            if host.isFinished {
                Text(verbatim: host.footnote)
            } else if host.wasStopped {
                Text("Stopped before this host was finished.")
            }
        }
    }

    private var emptyText: String {
        if host.isFinished {
            return "No open ports"
        }
        if host.wasStopped {
            return "No open ports found before the scan stopped"
        }
        return "Scanning…"
    }
}

private struct PortRow: View {
    let result: PortResult

    var body: some View {
        HStack(spacing: 12) {
            Text(verbatim: "\(result.port)/tcp")
                .font(.body.monospaced())
            Text(verbatim: result.service)
                .foregroundStyle(.secondary)
            Spacer()
            Text(verbatim: result.state.rawValue)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(stateColor)
        }
    }

    private var stateColor: Color {
        switch result.state {
        case .open: return .green
        case .closed: return .secondary
        case .filtered: return .orange
        }
    }
}
