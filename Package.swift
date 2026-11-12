// swift-tools-version:5.9
//
// Builds and tests the platform-independent part of the scanner (parsers and
// scan engine) without Xcode, on a Mac or on Linux. From a Windows Command
// Prompt, Docker works:
//
//   swift test
//   docker run --rm -v "%cd%:/src:ro" -w /src swift:6.2 swift test --scratch-path /tmp/build
//
// The iPhone app itself is built from PortScanner.xcodeproj; this package is
// only for checking the engine. The files left out below need Apple-only
// frameworks (Network) or Darwin-only system calls.
import PackageDescription

let package = Package(
    name: "ScannerCore",
    platforms: [.macOS(.v13), .iOS(.v16)],
    targets: [
        .target(
            name: "ScannerCore",
            path: "PortScanner/Engine",
            exclude: ["NetworkInfo.swift", "TCPProbe.swift", "LiveDependencies.swift", "BonjourBrowser.swift"]
        ),
        .testTarget(
            name: "ScannerCoreTests",
            dependencies: ["ScannerCore"],
            path: "Tests/ScannerCoreTests"
        ),
    ]
)
