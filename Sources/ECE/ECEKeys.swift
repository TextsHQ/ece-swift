@_implementationOnly import ECEC
import Foundation

public struct ECEKeys {
    public let privateKey: Data
    public let publicKey: Data
    public let auth: Data
}

extension Data.Deallocator {
    static var deallocate: Self {
        .custom { ptr, _ in ptr.deallocate() }
    }
}

extension ECEKeys {
    public static func generate() throws -> ECEKeys {
        let privBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(ECE_WEBPUSH_PRIVATE_KEY_LENGTH))
        let pubBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(ECE_WEBPUSH_PUBLIC_KEY_LENGTH))
        let authBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(ECE_WEBPUSH_AUTH_SECRET_LENGTH))
        do {
            try ECEError.check(ece_webpush_generate_keys(
                privBuf.baseAddress, privBuf.count,
                pubBuf.baseAddress, pubBuf.count,
                authBuf.baseAddress, authBuf.count
            ))
        } catch {
            privBuf.deallocate()
            pubBuf.deallocate()
            authBuf.deallocate()
            throw error
        }
        let priv = Data(bytesNoCopy: privBuf.baseAddress!, count: privBuf.count, deallocator: .deallocate)
        let pub = Data(bytesNoCopy: pubBuf.baseAddress!, count: pubBuf.count, deallocator: .deallocate)
        let auth = Data(bytesNoCopy: authBuf.baseAddress!, count: authBuf.count, deallocator: .deallocate)
        return ECEKeys(privateKey: priv, publicKey: pub, auth: auth)
    }
}
