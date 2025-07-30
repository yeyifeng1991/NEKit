import Foundation
import Network
import CocoaLumberjackSwift

class TrojanAdapter: AdapterSocket {
    private var connection: NWConnection?

    let host: String
    let port: Int
    let password: String
    let sni: String?

    init(host: String, port: Int, password: String, sni: String? = nil) {
        self.host = host
        self.port = port
        self.password = password
        self.sni = sni
        super.init()
    }

    override func openSocketWith(session: ConnectSession) {
        super.openSocketWith(session: session)

        let tlsOptions = NWProtocolTLS.Options()
        if let sni = sni {
            sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, sni)
        }

        let params = NWParameters(tls: tlsOptions)

        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: UInt16(port))
        )

        connection = NWConnection(to: endpoint, using: params)

        connection?.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                DDLogInfo("TrojanAdapter TLS connected to \(self?.host ?? ""):\(self?.port ?? 0)")
                if let self = self {
                    self.sendHandshake(session: session)
                    self.delegate?.didConnectWith(adapterSocket: self)
                }
            case .failed(let error):
                DDLogError("TrojanAdapter failed with error: \(error)")
                self?.disconnect(becauseOf: error)
            default:
                break
            }
        }

        connection?.start(queue: .global())
    }

    private func sendHandshake(session: ConnectSession) {
        let request = "\(password)\r\n\(session.host):\(session.port)\r\n"
        let data = request.data(using: .utf8) ?? Data()

        connection?.send(content: data, completion: .contentProcessed({ [weak self] error in
            if let error = error {
                DDLogError("Handshake failed: \(error)")
                self?.disconnect(becauseOf: error)
            } else {
                DDLogInfo("Trojan handshake sent")
            }
        }))
    }

    override func write(data: Data) {
        guard !isCancelled else { return }
        connection?.send(content: data, completion: .contentProcessed({ _ in }))
    }

    override func readData() {
        guard !isCancelled else { return }

        connection?.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, isComplete, error in
            guard let self = self else { return }
            if let data = data {
                self.delegate?.didRead(data: data, from: self)
            }

            if let error = error {
                self.disconnect(becauseOf: error)
            }

            if isComplete {
                self.disconnect(becauseOf: nil)
            }
        }
    }

    override func disconnect(becauseOf error: Error? = nil) {
        super.disconnect(becauseOf: error)
        connection?.cancel()
        connection = nil
    }
}

