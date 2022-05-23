import Foundation
import Crypto

extension ECE {
    struct Decryptor {
        let key: SymmetricKey
        let nonce: Data
        let rs: Int
        let padSize: Int
        let unpad: (Data, _ isFinal: Bool) throws -> Data

        private var counter: UInt64 = 0
        // count always < rs
        private var buffer: [UInt8]

        init(key: SymmetricKey, nonce: Data, rs: Int, padSize: Int, unpad: @escaping (Data, _ isFinal: Bool) throws -> Data) {
            self.key = key
            self.nonce = nonce
            self.rs = rs
            self.padSize = padSize
            self.unpad = unpad
            self.buffer = []
            self.buffer.reserveCapacity(rs)
        }

        private mutating func decrypt<C: Collection>(record data: C, isFinal: Bool) throws -> Data where C.Element == UInt8 {
            defer { counter += 1 }
            let iv = try ECE.computeIV(nonce: nonce, counter: counter)
            let decrypted = try AES.GCM.open(.init(
                nonce: iv,
                ciphertext: data.dropLast(ECE.tagLength),
                tag: data.suffix(ECE.tagLength)
            ), using: key)
            return try unpad(decrypted, isFinal)
        }

        mutating func update<C: Collection>(with data: C, isFinal: Bool) throws -> Data where C.Element == UInt8 {
            // parse as many entire records of `buffer + data` as possible, putting the remainder in `buffer`
            var output: Data
            var remainingData: C.SubSequence
            if buffer.isEmpty {
                output = Data()
                remainingData = data[...]
            } else {
                let needed = rs - buffer.count
                if data.count >= needed {
                    // handle the data in the buffer, and drain it
                    buffer.append(contentsOf: data.prefix(needed))
                    remainingData = data.dropFirst(needed)
                    output = try decrypt(record: buffer, isFinal: isFinal && remainingData.isEmpty)
                    buffer.removeAll()
                } else {
                    // just append and exit
                    buffer.append(contentsOf: data)
                    return Data()
                }
            }
            while !remainingData.isEmpty {
                let isFinalRecord = isFinal && remainingData.count <= rs
                if remainingData.count < rs && !isFinal {
                    buffer.append(contentsOf: remainingData)
                    return output
                }
                let record = remainingData.prefix(rs)
                output.append(contentsOf: try decrypt(record: record, isFinal: isFinalRecord))
                remainingData = remainingData.dropFirst(rs)
            }
            return output
        }
    }
}

extension ECE.AESGCM {
    struct Decryptor {
        var decryptor: ECE.Decryptor

        init(secrets: ECE.Secrets, parameters: Parameters) throws {
            let (key, nonce) = try ECE.AESGCM.deriveKeyAndNonce(forDecryption: true, secrets: secrets, parameters: parameters)
            decryptor = .init(
                key: key, nonce: nonce,
                rs: parameters.rs + ECE.AESGCM.padSize,
                padSize: ECE.AESGCM.padSize
            ) { record, isFinal in
                if isFinal && record.count == parameters.rs + ECE.AESGCM.padSize {
                    // needs trailer
                    throw ECEError.decryptTruncated
                }
                let padSize = Int(record.withUnsafeBytes { $0.load(as: UInt16.self) }.byteSwapped)
                guard record[ECE.AESGCM.padSize..<(ECE.AESGCM.padSize + padSize)].allSatisfy({ $0 == 0 }) else {
                    throw ECEError.decryptPadding
                }
                return record[(ECE.AESGCM.padSize + padSize)...]
            }
        }

        mutating func update<C: Collection>(with data: C, isFinal: Bool) throws -> Data where C.Element == UInt8, C.Index == Int {
            try decryptor.update(with: data, isFinal: isFinal)
        }
    }

    public static func decrypt(_ ciphertext: Data, using secrets: ECE.Secrets, parameters: Parameters) throws -> Data {
        var decryptor = try Decryptor(secrets: secrets, parameters: parameters)
        return try decryptor.update(with: ciphertext, isFinal: true)
    }
}

extension ECE.AES128GCM {
    struct Decryptor {
        var decryptor: ECE.Decryptor

        init(secrets: ECE.Secrets, parameters: Parameters) throws {
            let (key, nonce) = try ECE.AES128GCM.deriveKeyAndNonce(forDecryption: true, secrets: secrets, parameters: parameters)
            decryptor = .init(
                key: key, nonce: nonce,
                rs: parameters.rs,
                padSize: ECE.AES128GCM.padSize
            ) { record, isFinal in
                let padDelim: UInt8 = isFinal ? 2 : 1
                guard let delimIdx = record.lastIndex(where: { $0 != 0 }) else {
                    throw ECEError.zeroPlaintext
                }
                guard record[delimIdx] == padDelim else {
                    throw ECEError.decryptPadding
                }
                return record[..<delimIdx]
            }
        }

        mutating func update<C: Collection>(with data: C, isFinal: Bool) throws -> Data where C.Element == UInt8, C.Index == Int {
            try decryptor.update(with: data, isFinal: isFinal)
        }
    }

    public static func decrypt(ciphertext: Data, using secrets: ECE.Secrets, parameters: Parameters) throws -> Data {
        var decryptor = try Decryptor(secrets: secrets, parameters: parameters)
        return try decryptor.update(with: ciphertext, isFinal: true)
    }

    public static func decrypt(webPushPayload: Data, using secrets: ECE.Secrets) throws -> Data {
        let parameters = try Parameters(header: webPushPayload.prefix(Parameters.headerLength))
        var decryptor = try Decryptor(secrets: secrets, parameters: parameters)
        let ciphertext = webPushPayload.dropFirst(Parameters.headerLength)
        return try decryptor.update(with: ciphertext, isFinal: true)
    }
}
