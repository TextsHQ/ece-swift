// swift-tools-version: 5.6

import PackageDescription

let package = Package(
    name: "ece-swift",
    platforms: [.iOS(.v14)],
    products: [
        .library(
            name: "ECE",
            targets: ["ECE"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/OpenSSL.git", .upToNextMinor(from: "1.1.180")),
    ],
    targets: [
        .target(
            name: "ECEC",
            dependencies: ["OpenSSL"]
        ),
        .target(
            name: "ECE",
            dependencies: ["ECEC"]
        ),
        .testTarget(
            name: "ECETests",
            dependencies: ["ECE"]
        ),
    ]
)
