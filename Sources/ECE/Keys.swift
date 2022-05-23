import Foundation
import Crypto

extension ECE {
    public struct Secrets {
        private static let authLength = 16

        public let privateKey: P256.KeyAgreement.PrivateKey
        public let auth: Data

        public init() {
            privateKey = .init()
            auth = .init(randomByteCount: Self.authLength)
        }

        public init(privateKey: P256.KeyAgreement.PrivateKey, auth: Data) {
            precondition(auth.count >= Self.authLength)
            self.privateKey = privateKey
            self.auth = auth
        }

        public var webpushKeys: (auth: String, p256dh: String) {
            (
                auth: auth.eceBase64EncodedString(),
                p256dh: privateKey.publicKey.x963Representation.eceBase64EncodedString()
            )
        }
    }
}
