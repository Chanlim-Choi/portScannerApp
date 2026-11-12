import UIKit

/// Keeps the screen from auto-locking while a scan or a device search runs;
/// iOS would otherwise send the app to the background and pause the work.
@MainActor
enum KeepAwake {
    private static var holders = 0

    static func begin() {
        holders += 1
        UIApplication.shared.isIdleTimerDisabled = true
    }

    static func end() {
        holders = max(0, holders - 1)
        if holders == 0 {
            UIApplication.shared.isIdleTimerDisabled = false
        }
    }
}
