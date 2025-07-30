import Foundation

public class TrojanAdapterFactory: AdapterFactory {
    private let host: String
    private let port: Int
    private let password: String
    private let sni: String?

    public init(host: String, port: Int, password: String, sni: String? = nil) {
        self.host = host
        self.port = port
        self.password = password
        self.sni = sni
    }

    public override func getAdapterFor(session: ConnectSession) -> AdapterSocket {
        
        return TrojanAdapter(
              host: host,
              port: port,
              password: password,
              sni: sni
          )
    }
}

