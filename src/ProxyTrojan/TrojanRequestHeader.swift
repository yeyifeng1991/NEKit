import Foundation
import CryptoKit
import CommonCrypto
// Data 扩展，添加 SHA224 支持
extension Data {
    func sha224() -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
        self.withUnsafeBytes { buffer in
            _ = CC_SHA224(buffer.baseAddress, CC_LONG(self.count), &hash)
        }
        return Data(hash)
    }
}

struct TrojanRequestHeader {
    let password: String
    let targetHost: String
    let targetPort: Int

    func build() -> Data {
           var data = Data()
           let passwordData = password.data(using: .utf8)!
           let hashData = passwordData.sha224()
           let passwordHex = hashData.map { String(format: "%02x", $0) }.joined()
           data.append(passwordHex.data(using: .utf8)!)
           data.append("\r\n".data(using: .utf8)!)
           let destLine = "\(targetHost):\(targetPort)\r\n"
           data.append(destLine.data(using: .utf8)!)
           return data
       }
}
