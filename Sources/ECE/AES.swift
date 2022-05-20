@_implementationOnly import ECEC
import Foundation

public enum AESGCM {
    public struct Metadata {
        public let salt: Data
        public let senderPublicKey: Data
        public let rs: UInt32

        public init(salt: Data, senderPublicKey: Data, rs: UInt32) {
            self.salt = salt
            self.senderPublicKey = senderPublicKey
            self.rs = rs
        }

        public init(cryptoKey: String, encryption: String) throws {
            let saltBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(ECE_SALT_LENGTH))
            let pubBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(ECE_WEBPUSH_PUBLIC_KEY_LENGTH))
            var rs: UInt32 = 0
            do {
                try ECEError.check(ece_webpush_aesgcm_headers_extract_params(
                    cryptoKey, encryption,
                    saltBuf.baseAddress, saltBuf.count,
                    pubBuf.baseAddress, pubBuf.count,
                    &rs
                ))
            } catch {
                saltBuf.deallocate()
                pubBuf.deallocate()
            }
            salt = Data(bytesNoCopy: saltBuf.baseAddress!, count: saltBuf.count, deallocator: .deallocate)
            senderPublicKey = Data(bytesNoCopy: pubBuf.baseAddress!, count: pubBuf.count, deallocator: .deallocate)
            self.rs = rs
        }
    }

    public static func decrypt(_ ciphertext: Data, receiverKeys: ECEKeys, metadata: Metadata) throws -> Data {
        var plaintextLen = ece_aesgcm_plaintext_max_length(metadata.rs, ciphertext.count)
        guard plaintextLen != 0 else { throw ECEError.decrypt }
        let plaintextBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: plaintextLen)
        do {
            try receiverKeys.privateKey.withUnsafeBytes { privBuf in
                try receiverKeys.auth.withUnsafeBytes { authBuf in
                    try metadata.salt.withUnsafeBytes { saltBuf in
                        try metadata.senderPublicKey.withUnsafeBytes { senderPubBuf in
                            try ciphertext.withUnsafeBytes { cipherBuf in
                                try ECEError.check(ece_webpush_aesgcm_decrypt(
                                    privBuf.baseAddress, privBuf.count,
                                    authBuf.baseAddress, authBuf.count,
                                    saltBuf.baseAddress, saltBuf.count,
                                    senderPubBuf.baseAddress, senderPubBuf.count,
                                    metadata.rs,
                                    cipherBuf.baseAddress, cipherBuf.count,
                                    plaintextBuf.baseAddress, &plaintextLen
                                ))
                            }
                        }
                    }
                }
            }
        } catch {
            plaintextBuf.deallocate()
            throw error
        }
        return Data(bytesNoCopy: plaintextBuf.baseAddress!, count: plaintextLen, deallocator: .deallocate)
    }
}

public enum AES128GCM {
    public static func decrypt(_ payload: Data, receiverKeys: ECEKeys) throws -> Data {
        var plaintextLen = payload.withUnsafeBytes { ece_aes128gcm_plaintext_max_length($0.baseAddress, $0.count) }
        guard plaintextLen != 0 else { throw ECEError.decrypt }
        let plaintextBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: plaintextLen)
        do {
            try receiverKeys.privateKey.withUnsafeBytes { privBuf in
                try receiverKeys.auth.withUnsafeBytes { authBuf in
                    try payload.withUnsafeBytes { payBuf in
                        try ECEError.check(ece_webpush_aes128gcm_decrypt(
                            privBuf.baseAddress, privBuf.count,
                            authBuf.baseAddress, authBuf.count,
                            payBuf.baseAddress, payBuf.count,
                            plaintextBuf.baseAddress, &plaintextLen
                        ))
                    }
                }
            }
        } catch {
            plaintextBuf.deallocate()
            throw error
        }
        return Data(bytesNoCopy: plaintextBuf.baseAddress!, count: plaintextLen, deallocator: .deallocate)
    }
}
