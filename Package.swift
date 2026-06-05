// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "AuraAgent",
    platforms: [
        .iOS(.v18),
        .macOS(.v15),
    ],
    products: [
        .library(
            name: "AuraAgent",
            targets: ["AuraAgent", "AuraAgentFFI"]
        )
    ],
    targets: [
        .binaryTarget(
            name: "AuraAgentFFI",
            path: "dist/apple/AuraAgentFFI.xcframework"
        ),
        .target(
            name: "AuraAgent",
            dependencies: ["AuraAgentFFI"],
            path: "swift/Sources/AuraAgent"
        ),
    ]
)
