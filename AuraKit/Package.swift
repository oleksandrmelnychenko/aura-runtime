// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AuraKit",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "AuraKit", targets: ["AuraKit"]),
    ],
    targets: [
        .binaryTarget(
            name: "AuraFFI",
            path: "AuraFFI.xcframework"
        ),
        .target(
            name: "AuraKit",
            dependencies: ["AuraFFI"],
            path: "Sources/AuraKit"
        ),
        .testTarget(
            name: "AuraKitTests",
            dependencies: ["AuraKit"],
            path: "Tests/AuraKitTests"
        ),
    ]
)
