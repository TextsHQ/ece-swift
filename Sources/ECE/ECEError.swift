// same error list as ECEC; we aren't using all of them atm.
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
}
