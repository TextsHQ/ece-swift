import Foundation

// based on
// https://github.com/chromium/chromium/blob/69177730ed8780c42db97d01d68550ef1e36de80/components/gcm_driver/crypto/encryption_header_parsers.cc

enum CodeUnits {
    static let space = " ".utf8.first!
    static let tab = "\t".utf8.first!
    static let comma = ",".utf8.first!
    static let quote = "\"".utf8.first!
    static let backslash = "\\".utf8.first!
    static let semicolon = ";".utf8.first!
    static let equal = "=".utf8.first!

    static let lws: Set = [space, tab]
}

struct TokenizedSequence<C: Collection>: Sequence where C.Element: Hashable {
    struct Options {
        let delimiters: Set<C.Element>
        let quotes: Set<C.Element>
        let escape: C.Element?
    }

    private struct AdvanceState {
        let options: Options
        private(set) var curQuote: C.Element?
        private(set) var inEscape = false

        mutating func advance(with element: C.Element) -> Bool {
            if let curQuote = curQuote {
                if inEscape {
                    inEscape = false
                } else if element == options.escape {
                    inEscape = true
                } else if element == curQuote {
                    self.curQuote = nil
                }
                return true
            }

            if options.delimiters.contains(element) {
                return false
            }

            if options.quotes.contains(element) {
                curQuote = element
            }

            return true
        }
    }

    let collection: C
    let options: Options

    init(_ collection: C, options: Options) {
        self.collection = collection
        self.options = options
    }

    struct Iterator: IteratorProtocol {
        let options: Options
        let collection: C

        var tokenStart: C.Index
        var tokenEnd: C.Index
        var isDelimiter: Bool

        init(options: Options, collection: C) {
            self.options = options
            self.collection = collection
            self.tokenStart = collection.startIndex
            self.tokenEnd = tokenStart
            self.isDelimiter = true
        }

        mutating func next() -> C.SubSequence? {
            var state = AdvanceState(options: options)
            while true {
                if isDelimiter {
                    isDelimiter = false
                    tokenStart = tokenEnd
                    while tokenEnd != collection.endIndex && state.advance(with: collection[tokenEnd]) {
                        tokenEnd = collection.index(after: tokenEnd)
                    }
                    return collection[tokenStart..<tokenEnd]
                } else {
                    isDelimiter = true
                    tokenStart = tokenEnd
                    if tokenEnd == collection.endIndex {
                        return nil
                    }
                    tokenEnd = collection.index(after: tokenEnd)
                }
            }
        }
    }

    func makeIterator() -> Iterator {
        Iterator(options: options, collection: collection)
    }
}

extension TokenizedSequence.Options where C.Element == UTF8.CodeUnit {
    init(delimiter: C.Element) {
        self.init(delimiters: [delimiter], quotes: [CodeUnits.quote], escape: CodeUnits.backslash)
    }
}

extension Substring.UTF8View {
    fileprivate func trimmingCharacters(in set: Set<Element>) -> SubSequence {
        var start = startIndex
        var end = endIndex
        while start < end && set.contains(self[start]) {
            start = index(after: start)
        }
        while start < end && set.contains(self[index(before: end)]) {
            end = index(before: end)
        }
        return self[start..<end]
    }

    fileprivate func httpUnquoted() -> [Element] {
        guard count >= 2 && first == CodeUnits.quote && last == first else {
            return .init(self)
        }
        let cleaned = dropFirst().dropLast()
        var unescaped: [Element] = []
        var prevEscape = false
        for char in cleaned {
            if prevEscape || char != CodeUnits.quote {
                prevEscape = false
                unescaped.append(char)
            } else {
                prevEscape = true
            }
        }
        return unescaped
    }
}

struct ValuesSequence: Sequence {
    let base: AnySequence<Substring.UTF8View>
    init(_ string: String) {
        base = AnySequence(
            TokenizedSequence(string.utf8, options: .init(delimiter: CodeUnits.comma))
                .lazy
                .map { $0.trimmingCharacters(in: CodeUnits.lws) }
                .filter { !$0.isEmpty }
        )
    }
    func makeIterator() -> AnyIterator<Substring.UTF8View> {
        base.makeIterator()
    }
}

struct NameValueSequence: Sequence {
    typealias Element = [(String, String)]
    let base: AnySequence<Element>
    init(_ string: String) {
        base = AnySequence(ValuesSequence(string).lazy.map {
            TokenizedSequence($0, options: .init(delimiter: CodeUnits.semicolon)).compactMap { part in
                guard let firstEqual = part.firstIndex(of: CodeUnits.equal), firstEqual != part.startIndex else {
                    return nil
                }
                if let firstQuote = part.firstIndex(of: CodeUnits.quote) {
                    guard firstQuote > firstEqual else { return nil }
                }
                let afterEqual = part.index(after: firstEqual)
                let key = part[..<firstEqual].trimmingCharacters(in: CodeUnits.lws)
                let value = part[afterEqual...].trimmingCharacters(in: CodeUnits.lws).httpUnquoted()
                return (
                    String(decoding: key, as: UTF8.self),
                    String(decoding: value, as: UTF8.self)
                )
            }
        })
    }
    func makeIterator() -> AnyIterator<Element> {
        base.makeIterator()
    }
}

struct EncryptionSequence: Sequence {
    struct Element {
        var keyID: String?
        var salt: Data?
        var rs: Int?
    }

    let base: AnySequence<Element>
    init(header: String) {
        base = .init(NameValueSequence(header).lazy.compactMap { pairs in
            var element = Element(keyID: nil, salt: nil, rs: nil)
            for (key, value) in pairs {
                if key == "keyid" {
                    guard element.keyID == nil else { return nil }
                    element.keyID = value
                } else if key == "salt" {
                    guard element.salt == nil, let data = Data(eceBase64Encoded: value) else {
                        return nil
                    }
                    element.salt = data
                } else if key == "rs" {
                    guard element.rs == nil, let rs = Int(value) else {
                        return nil
                    }
                    element.rs = rs
                }
            }
            return element
        })
    }

    func makeIterator() -> AnyIterator<Element> {
        base.makeIterator()
    }
}

struct CryptoKeySequence: Sequence {
    struct Element {
        var keyid: String?
        var dh: Data?
        var aesgcm128: Data?
    }

    let base: AnySequence<Element>
    init(header: String) {
        base = .init(NameValueSequence(header).lazy.compactMap { pairs in
            var element = Element(keyid: nil, dh: nil, aesgcm128: nil)
            for (key, value) in pairs {
                if key == "keyid" {
                    guard element.keyid == nil else { return nil }
                    element.keyid = value
                } else if key == "aesgcm128" {
                    guard element.aesgcm128 == nil, let data = Data(eceBase64Encoded: value) else {
                        return nil
                    }
                    element.aesgcm128 = data
                } else if key == "dh" {
                    guard element.dh == nil, let data = Data(eceBase64Encoded: value) else {
                        return nil
                    }
                    element.dh = data
                }
            }
            return element
        })
    }

    func makeIterator() -> AnyIterator<Element> {
        base.makeIterator()
    }
}
