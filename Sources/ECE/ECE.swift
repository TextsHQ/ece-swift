import Foundation
import Crypto

public enum ECE {
    public enum AESGCM {}
    public enum AES128GCM {}
}

extension ECE {
    static let tagLength = 16
    static let ikmLength = 32
    static let keyLength = 16
    static let saltLength = 16
    static let nonceLength = 12
    public static let defaultRS = 4096

    static func computeIV(nonce: Data, counter: UInt64) throws -> AES.GCM.Nonce {
        // TODO: Use loadUnaligned once SE-0349 lands
        #if swift(>=5.7)
        #warning("Replace this with loadUnaligned")
        #endif
        let updated = nonce.advanced(by: 4).withUnsafeBytes { $0.load(as: UInt64.self) } ^ counter.byteSwapped
        return try .init(data: nonce[..<4] + withUnsafeBytes(of: updated) { Data($0) })
    }
}

extension ECE.AESGCM {
    static let padSize = 2

    public struct Parameters {
        public let senderPublicKey: P256.KeyAgreement.PublicKey
        public let salt: Data
        public let rs: Int

        public init(senderPublicKey: P256.KeyAgreement.PublicKey, salt: Data, rs: Int = ECE.defaultRS) {
            self.senderPublicKey = senderPublicKey
            self.salt = salt
            self.rs = rs
        }

        public init(cryptoKey: String, encryption: String) throws {
            guard let enc = EncryptionSequence(header: encryption).first(where: { _ in true }),
                  let salt = enc.salt,
                  salt.count == ECE.saltLength else {
                throw ECEError.invalidEncryptionHeader
            }
            let rs = enc.rs ?? ECE.defaultRS
            guard rs > 1 else {
                throw ECEError.invalidRS
            }
            self.salt = salt
            self.rs = rs

            let cks = CryptoKeySequence(header: cryptoKey).compactMap(\.dh)
            guard cks.count == 1 else {
                throw ECEError.invalidCryptoKeyHeader
            }
            self.senderPublicKey = try P256.KeyAgreement.PublicKey(x963Representation: cks[0])
        }
    }

    static func generateInfo(
        receiverKey: P256.KeyAgreement.PublicKey,
        senderKey: P256.KeyAgreement.PublicKey,
        prefix: String
    ) -> Data {
        var info = Data(prefix.utf8)
        withUnsafeBytes(of: UInt16(receiverKey.x963Representation.count).bigEndian) { info.append(contentsOf: $0) }
        info.append(receiverKey.x963Representation)
        withUnsafeBytes(of: UInt16(senderKey.x963Representation.count).bigEndian) { info.append(contentsOf: $0) }
        info.append(senderKey.x963Representation)
        return info
    }

    static func deriveKeyAndNonce(
        forDecryption isDecrypting: Bool,
        secrets: ECE.Secrets,
        parameters: Parameters
    ) throws -> (key: SymmetricKey, nonce: Data) {
        let receiverKey = isDecrypting ? secrets.privateKey.publicKey : parameters.senderPublicKey
        let senderKey = isDecrypting ? parameters.senderPublicKey : secrets.privateKey.publicKey

        let secret = try secrets.privateKey.sharedSecretFromKeyAgreement(with: parameters.senderPublicKey)
        let ikm = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: secrets.auth,
            sharedInfo: Data("Content-Encoding: auth\0".utf8),
            outputByteCount: ECE.ikmLength
        )
        let key = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: parameters.salt,
            info: generateInfo(
                receiverKey: receiverKey,
                senderKey: senderKey,
                prefix: "Content-Encoding: aesgcm\0P-256\0"
            ),
            outputByteCount: ECE.keyLength
        )
        let nonce = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: parameters.salt,
            info: generateInfo(
                receiverKey: receiverKey,
                senderKey: senderKey,
                prefix: "Content-Encoding: nonce\0P-256\0"
            ),
            outputByteCount: ECE.nonceLength
        ).withUnsafeBytes(Data.init(_:))
        return (key, nonce)
    }
}

extension ECE.AES128GCM {
    static let padSize = 1

    public struct Parameters {
        // 86 bytes
        public static let headerLength =
            ECE.saltLength
          + MemoryLayout<UInt32>.size
          + MemoryLayout<UInt8>.size
          + 65 // keylen for a P-256 public key

        public let senderPublicKey: P256.KeyAgreement.PublicKey
        public let salt: Data
        public let rs: Int

        public init(senderPublicKey: P256.KeyAgreement.PublicKey, salt: Data, rs: Int) {
            self.senderPublicKey = senderPublicKey
            self.salt = salt
            self.rs = rs
        }

        // first `headerLength` bytes
        public init(header: Data) throws {
            // +-----------+--------+-----------+---------------+
            // | salt (16) | rs (4) | idlen (1) | keyid (idlen) |
            // +-----------+--------+-----------+---------------+
            // for web push, idlen is 65 (P-256 public key)
            salt = header.prefix(ECE.saltLength)
            rs = Int(header.dropFirst(ECE.saltLength).withUnsafeBytes { $0.load(as: UInt32.self) }.byteSwapped)
            // TODO: Use loadUnaligned once SE-0349 lands
            let keyLength = Int(header.advanced(by: ECE.saltLength + 4).withUnsafeBytes { $0.load(as: UInt8.self) })
            senderPublicKey = try P256.KeyAgreement.PublicKey(
                x963Representation: header.dropFirst(ECE.saltLength + 4 + 1).prefix(keyLength)
            )
        }
    }
}
