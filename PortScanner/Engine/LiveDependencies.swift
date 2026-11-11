import Foundation

extension ScanDependencies {
    /// Real TCP connections through Network.framework and the system resolver.
    static let live = ScanDependencies(
        probe: { address, port, timeout in
            await TCPProbe.run(address: address, port: port, timeout: timeout)
        },
        resolve: { name in
            await Resolver.resolve(name)
        }
    )
}
