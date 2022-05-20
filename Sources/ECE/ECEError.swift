@_implementationOnly import ECEC

public enum ECEError: Error {
    case outOfMemory
    case invalidPrivateKey
    case invalidPublicKey
    case computeSecret
    case encodePublicKey
    case decrypt
    case decryptPadding
    case zeroPlaintext
    case shortBlock
    case shortHeader
    case zeroCiphertext
    case hkdf
    case invalidEncryptionHeader
    case invalidCryptoKeyHeader
    case invalidRS
    case invalidSalt
    case invalidDH
    case encrypt
    case encryptPadding
    case invalidAuthSecret
    case generateKeys
    case decryptTruncated
    case unknown

    init?(rawValue: Int32) {
        switch rawValue {
        case ECE_OK:
            return nil
        case ECE_ERROR_OUT_OF_MEMORY:
            self = .outOfMemory
        case ECE_ERROR_INVALID_PRIVATE_KEY:
            self = .invalidPrivateKey
        case ECE_ERROR_INVALID_PUBLIC_KEY:
            self = .invalidPublicKey
        case ECE_ERROR_COMPUTE_SECRET:
            self = .computeSecret
        case ECE_ERROR_ENCODE_PUBLIC_KEY:
            self = .encodePublicKey
        case ECE_ERROR_DECRYPT:
            self = .decrypt
        case ECE_ERROR_DECRYPT_PADDING:
            self = .decryptPadding
        case ECE_ERROR_ZERO_PLAINTEXT:
            self = .zeroPlaintext
        case ECE_ERROR_SHORT_BLOCK:
            self = .shortBlock
        case ECE_ERROR_SHORT_HEADER:
            self = .shortHeader
        case ECE_ERROR_ZERO_CIPHERTEXT:
            self = .zeroCiphertext
        case ECE_ERROR_HKDF:
            self = .hkdf
        case ECE_ERROR_INVALID_ENCRYPTION_HEADER:
            self = .invalidEncryptionHeader
        case ECE_ERROR_INVALID_CRYPTO_KEY_HEADER:
            self = .invalidCryptoKeyHeader
        case ECE_ERROR_INVALID_RS:
            self = .invalidRS
        case ECE_ERROR_INVALID_SALT:
            self = .invalidSalt
        case ECE_ERROR_INVALID_DH:
            self = .invalidDH
        case ECE_ERROR_ENCRYPT:
            self = .encrypt
        case ECE_ERROR_ENCRYPT_PADDING:
            self = .encryptPadding
        case ECE_ERROR_INVALID_AUTH_SECRET:
            self = .invalidAuthSecret
        case ECE_ERROR_GENERATE_KEYS:
            self = .generateKeys
        case ECE_ERROR_DECRYPT_TRUNCATED:
            self = .decryptTruncated
        default:
            self = .unknown
        }
    }

    static func check(_ value: Int32) throws {
        if let error = ECEError(rawValue: value) { throw error }
    }
}
