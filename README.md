# Port Scanner (personal iOS build)

A small nmap-inspired port scanner for your own iPhone. Built in Xcode and signed
with a free Apple ID, so there is nothing to pay for and no ads.

## Build and install (Mac + Xcode)

You need Xcode 16 or newer, and an Xcode that supports your iPhone's iOS
version (for example Xcode 26 for an iPhone on iOS 26). If Xcode later says the
iPhone is unsupported or it "failed to prepare the device", update Xcode.

1. Copy this whole folder to the Mac (or clone it from GitHub).
2. Double-click `PortScanner.xcodeproj`. Do not open the folder itself or
   `Package.swift`: that opens the engine test package, which has no app.
3. Plug in the iPhone, unlock it and tap Trust.
4. Turn on Developer Mode: on the iPhone go to Settings > Privacy & Security >
   Developer Mode. After the restart, unlock the phone, tap Turn On and enter
   your passcode. If the switch is missing, keep the phone plugged in with
   Xcode open and look again.
5. In Xcode, pick the iPhone as the run destination in the bar at the top.
6. Xcode > Settings > Accounts: add your Apple ID. A free one is enough.
7. Click the PortScanner project, then the PortScanner target, then
   Signing & Capabilities. Set Team to your "Personal Team".
   - If Xcode says your team has no devices, check that the iPhone is plugged
     in and selected (step 5), then click Try Again.
   - If Xcode says the bundle identifier is not available, change it once to
     something unique, for example `dev.local.portscanner.<random letters>`,
     and keep it (see the limits below).
8. Press Run. If the Mac asks for your login password for codesign, enter it
   and click Always Allow.
9. The first time, Xcode installs the app but cannot open it. On the iPhone go
   to Settings > General > VPN & Device Management, tap your Apple ID under
   Developer App, tap Trust (this needs internet), then press Run again.

If Xcode offers "Update to recommended settings", you can accept or ignore it.

### Limits of a free Apple ID

- The app stops opening after 7 days. Plug the phone in and press Run again;
  your settings stay.
- At most 3 of your own free-signed apps can be on a phone at once.
- At most 10 new bundle identifiers per 7 days, so pick one and keep it.

### If the project file will not open

Create a new project instead. Save it somewhere else (not in this folder,
which already has a `PortScanner` folder):

1. File > New > Project > iOS App, named PortScanner, Interface SwiftUI,
   Language Swift.
2. Delete the two Swift files it generates, and drag in the contents of this
   folder's `PortScanner` folder (the `Engine` and `UI` folders and
   `PortScannerApp.swift`).
3. In the target's Build Settings set: Minimum Deployments iOS 16.0, Swift
   Language Version Swift 5. On Xcode 26 also set Default Actor Isolation to
   nonisolated and Approachable Concurrency to No.
4. In the target's Info tab add "Privacy - Local Network Usage Description"
   (any short sentence) and "Bundle display name" = Port Scanner.

## First scan

The first device search or scan makes iOS ask for Local Network access. Tap
Allow, then run it again: probes sent while the question was on screen are
counted as unanswered.

Keep the app on screen while it scans. The screen will not auto-lock during a
scan; if you switch apps, the scan stops and says so.

## What it does now

### Devices tab (phase 2)

- "Find devices" sweeps your Wi-Fi network (like `nmap -sn`): ping (ICMP)
  first, then TCP connections for devices that ignore ping, while listening
  for Bonjour announcements from about 37 kinds of services (AirPlay, Google
  Cast, printers, file sharing, HomeKit, Sonos, SSH and more).
- Each device shows the best name found (its Bonjour name or reverse-DNS
  name), its model when the device announces one, response time, and how it
  was found. Your own iPhone is labelled.
- Tap a device for its details and Bonjour services, then Quick, Standard or
  All-ports scan it in one tap.

### Port scan tab (phase 1)

- Targets: single IP, hostname, CIDR block, nmap-style ranges (`10.0.0.1-50`,
  `10.0.0.100-`, `10.0.0-2.*`), full ranges (`10.0.0.1-10.0.0.20`), IPv6, and
  several targets separated by spaces. Up to 4096 addresses per scan.
  "Use my network" fills in the Wi-Fi subnet (the /24 around the phone on very
  large networks).
- TCP connect scan (nmap `-sT`) reporting open / closed / filtered.
- Port sets: top 100, top 1000, all 65535, or a custom list (`22,80,8000-8100`).
- Speed presets modelled on nmap `-T2` to `-T5`. Each scan starts with a few
  connections and widens, so the first packets to a device are not dropped.
- Host discovery before scanning a range (ping, then TCP for quiet hosts),
  with a `-Pn` switch to skip it.

## What iOS does not allow

No raw sockets, so no SYN/FIN/Xmas scans, no OS fingerprinting, no MAC
addresses or vendor lookup, no packet spoofing.

## Checking the engine without an iPhone

The parsers and scan engine are plain Swift and have unit tests that use a fake
network. On a Mac run `swift test` in this folder. On Windows, with Docker,
from a Command Prompt in this folder:

```
docker run --rm -v "%cd%:/src:ro" -w /src swift:6.2 swift test --scratch-path /tmp/build
```

Every push to GitHub also runs these tests on Linux and builds the iPhone app,
unsigned, on a macOS runner (`.github/workflows/build.yml`). The result is on
the repository's Actions tab.

## Next phases

3. Service detection: banners, HTTP title and server, TLS certificate, SSH version.
4. Convenience: saved profiles, scan history, export, app icon, optional UDP.

Scan only networks you own or are allowed to test.
