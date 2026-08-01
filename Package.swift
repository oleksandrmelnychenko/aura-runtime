// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AuraAgent",
    platforms: [
        .iOS(.v18),
    ],
    products: [
        .library(
            name: "AuraAgent",
            targets: ["AuraAgent", "AuraAgentFFI"]
        )
    ],
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-protobuf.git",
            exact: "1.38.1"
        )
    ],
    targets: [
        .binaryTarget(
            name: "AuraAgentFFI",
            path: "dist/apple/AuraAgentFFI.xcframework"
        ),
        .target(
            name: "AuraAgent",
            dependencies: [
                "AuraAgentFFI",
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            path: "swift/Sources/AuraAgent"
        ),
    ]
)
