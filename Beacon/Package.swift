// swift-tools-version: 6.0
import PackageDescription

// gulp-beacon: the OAST interaction server (docs/features/F10-beacon-oast.md §2.2). Separate package
// so it deploys on Linux/Docker without GulpKit. v1 ships only the dev mode (BCN-024): HTTP + DNS on
// high ports, in memory, speaking the interactsh client protocol that Gulp uses for every server.

let package = Package(
    name: "Beacon",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "gulp-beacon", targets: ["gulp-beacon"]),
        .library(name: "BeaconKit", targets: ["BeaconKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.0.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.6.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "4.5.1"..<"5.0.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.70.0"),
    ],
    targets: [
        // The protocol, storage and DNS codec: no networking, so tests drive it directly.
        .target(
            name: "BeaconKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]),
        .executableTarget(
            name: "gulp-beacon",
            dependencies: [
                "BeaconKit",
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
            ]),
        .testTarget(
            name: "BeaconTests",
            dependencies: [
                "BeaconKit", .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]),
    ],
    swiftLanguageModes: [.v6]
)
