// swift-tools-version: 6.0
import PackageDescription

// gulp-beacon: the self-hostable OAST server (docs/features/F10-beacon-oast.md §2.2).
// Separate package so it deploys on Linux/Docker without GulpKit's macOS pieces.

let package = Package(
    name: "Beacon",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "gulp-beacon", targets: ["gulp-beacon"])
    ],
    dependencies: [
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.0.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.6.0"),
    ],
    targets: [
        .executableTarget(
            name: "gulp-beacon",
            dependencies: [
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
            ]),
        // Standalone until Beacon logic moves into a library target (M11); importing
        // an executable target is avoided deliberately.
        .testTarget(name: "BeaconTests"),
    ],
    swiftLanguageModes: [.v6]
)
