import Foundation

extension ScanDependencies {
    /// The real network: Network.framework connections, the system resolver,
    /// an ICMP socket and Bonjour browsing.
    static let live = ScanDependencies(
        probe: { address, port, timeout in
            await TCPProbe.run(address: address, port: port, timeout: timeout)
        },
        resolve: { name in
            await Resolver.resolve(name)
        },
        ping: { addresses, timeout in
            await Pinger.sweep(addresses, timeout: timeout)
        },
        reverseName: { address in
            await Resolver.reverseName(address)
        },
        browse: { duration in
            BonjourBrowser.browse(for: duration)
        }
    )
}
