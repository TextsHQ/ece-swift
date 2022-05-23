// swift-tools-version: 5.6

import PackageDescription

let package = Package(
    name: "ece-swift",
    platforms: [.iOS(.v14), .macOS(.v11)],
    products: [
        .library(
            name: "ECE",
            targets: ["ECE"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "3.0.0"),
    ],
    targets: [
        .target(
            name: "ECE",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "ECETests",
            dependencies: ["ECE"]
        ),
    ]
)
