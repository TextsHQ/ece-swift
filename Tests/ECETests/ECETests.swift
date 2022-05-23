import XCTest
@testable import ECE

final class ECETests: XCTestCase {
    private static let simpleTestSecrets = try! ECE.Secrets(
        privateKey: .init(rawRepresentation: Data(base64Encoded: "WIy1EpNFwHbFbM+cVHtLgxmq53fTqfiPdcuT0lcAmrg=")!),
        auth: Data(base64Encoded: "ysX4+bphFG9rbxwGX02KLw==")!
    )

    // TODO: Add more tests

    func testHeaderParser() throws {
        let metadata = try ECE.AESGCM.Parameters(
            cryptoKey: "; p256ecdsa=BF5oEo0xDUpgylKDTlsd8pZmxQA1leYINiY-rSscWYK_3tWAkz4VMbtf1MLE_Yyd6iII6o-e3Q9TCN5vZMzVMEs;dh=BPJ2QOjWQYhxfrDCHD8Tfl-cfW2oNW8-SLbg8rOczOeqiZYk1D-AtxRiIV4zXGbIUpzySn_IsFPH_U84pNwpSr0=",
            encryption: "; salt=UcL4p2WIgy9DgogBw5HnGQ"
        )
        XCTAssertEqual(metadata.rs, 4096)
        XCTAssertEqual(metadata.salt, Data(base64Encoded: "UcL4p2WIgy9DgogBw5HnGQ==")!)
        XCTAssertEqual(metadata.senderPublicKey.x963Representation, Data(base64Encoded: "BPJ2QOjWQYhxfrDCHD8Tfl+cfW2oNW8+SLbg8rOczOeqiZYk1D+AtxRiIV4zXGbIUpzySn/IsFPH/U84pNwpSr0=")!)
    }

    func testAESGCM() throws {
        let body = Data(base64Encoded: "BKgfgeGuNv8pxky4LNdIe4CTT+zXwj2wf19m9HS34w==")!
        let params = try ECE.AESGCM.Parameters(
            senderPublicKey: .init(rawRepresentation: Data(base64Encoded: "qv68I+z2Qpq6BuADoNhMfQhy0CTAb/9Aw2o3bzEtdDdA+Z9JBN/SD0bmH8XCW7VXpbjvI6o3efLJSdWDe30s5g==")!),
            salt: Data(base64Encoded: "ALSD7TvNq7Lwv3JXjjzdQw==")!
        )
        let plain = try ECE.AESGCM.decrypt(body, using: Self.simpleTestSecrets, parameters: params)
        XCTAssertEqual(String(decoding: plain, as: UTF8.self), "Hello, world!")
    }

    func testAES128GCM() throws {
        let body = Data(base64Encoded: "NMfqlA8xzjKo4arGJ0a2GQAAEABBBDFDylhF6YZTsaWVX9A9BymfC25eybUMwgS3Bgmhd5TFEeCNvJlrVfCG377ARrHsfZExxREb2YPKyH42kLCiwpo3dtwWfzFi8MedFuxuzxcLjKMdrDBWpOupyKkGNk8=")!
        let plain = try ECE.AES128GCM.decrypt(webPushPayload: body, using: Self.simpleTestSecrets)
        XCTAssertEqual(String(decoding: plain, as: UTF8.self), "Hello, world!")
    }
}
