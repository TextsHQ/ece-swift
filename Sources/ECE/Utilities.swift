import Foundation
import Crypto

extension Data {
    // base64url encoding
    public func eceBase64EncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "=", with: "")
    }

    public init?(eceBase64Encoded base64: String) {
        var base64 = base64
            .replacingOccurrences(of: "_", with: "/")
            .replacingOccurrences(of: "-", with: "+")
        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        self.init(base64Encoded: base64)
    }

    init(randomByteCount count: Int) {
        // SymmetricKey.init(size:) uses CryptoKit's private SecureBytes API
        self = SymmetricKey(size: .init(bitCount: count * 8)).withUnsafeBytes(Data.init(_:))
    }
}

extension Data.Deallocator {
    static var deallocate: Self {
        .custom { ptr, _ in ptr.deallocate() }
    }
}
