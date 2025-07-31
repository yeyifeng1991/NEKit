//
//  AES256GCMCrypto.swift
//  NEKit
//
//  Created by yyf on 2025/7/30.
//  Copyright © 2025 Zhuhao Wang. All rights reserved.
//

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#endif

@available(iOS 13.0, *)
public class AES256GCMCrypto: StreamCryptoProtocol {
    private let key: SymmetricKey
    private var buffer = Data()

    public init(keyData: Data) {
        self.key = SymmetricKey(data: keyData)
    }

    public func update(_ data: inout Data) {
        buffer.append(data)
    }

    public func encrypt(nonce: Data) throws -> Data {
        let nonceObj = try AES.GCM.Nonce(data: nonce)
        let sealedBox = try AES.GCM.seal(buffer, using: key, nonce: nonceObj)
        return sealedBox.ciphertext + sealedBox.tag
    }

    public func decrypt(ciphertextAndTag: Data, nonce: Data) throws -> Data {
        guard ciphertextAndTag.count >= 16 else {
            throw NSError(domain: "AES256GCMCrypto", code: -1, userInfo: nil)
        }

        let nonceObj = try AES.GCM.Nonce(data: nonce)
        let ciphertext = ciphertextAndTag.prefix(ciphertextAndTag.count - 16)
        let tag = ciphertextAndTag.suffix(16)

        let sealedBox = try AES.GCM.SealedBox(nonce: nonceObj, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(sealedBox, using: key)
    }

    public func reset() {
        buffer.removeAll()
    }
}
