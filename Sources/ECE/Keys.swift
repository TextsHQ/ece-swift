import Foundation
import Crypto

extension ECE {
    public struct Secrets {
        private static let authLength = 16

        let privateKey: any P256PrivateKey
        public let auth: Data

        public init(privateKey: any P256PrivateKey, auth: Data? = nil) {
            self.privateKey = privateKey
            if let auth {
                precondition(auth.count >= Self.authLength)
                self.auth = auth
            } else {
                self.auth = Data(randomByteCount: Self.authLength)
            }
        }

        public var webpushKeys: (auth: String, p256dh: String) {
            (
                auth: auth.eceBase64EncodedString(),
                p256dh: privateKey.publicKey.x963Representation.eceBase64EncodedString()
            )
        }
    }
}

public protocol P256PrivateKey {
    var publicKey: P256.KeyAgreement.PublicKey { get }
    func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws -> SharedSecret
}
extension P256.KeyAgreement.PrivateKey: P256PrivateKey {}
extension SecureEnclave.P256.KeyAgreement.PrivateKey: P256PrivateKey {}
