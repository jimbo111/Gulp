// swift-tools-version: 6.0
import PackageDescription

// GulpKit holds all of Gulp's logic (see docs/01-architecture.md §2–§4).
//
// Platform rule: every target below is defined on all platforms so the package
// graph is identical on macOS and Linux. Modules that need Apple frameworks
// (GulpBrowser, GulpScript, GulpUI, GulpFeatures) guard their platform code with
// `#if canImport(AppKit)` / `#if canImport(JavaScriptCore)` and compile to an
// empty shell on Linux. This keeps the manifest free of platform branches and
// lets `swift build`/`swift test` run the core on Linux (docs/07 ADR-010).

let nioCore: [Target.Dependency] = [
    .product(name: "NIOCore", package: "swift-nio"),
    .product(name: "NIOPosix", package: "swift-nio"),
]
let nioHTTP: [Target.Dependency] =
    nioCore + [
        .product(name: "NIOHTTP1", package: "swift-nio"),
        .product(name: "NIOHTTP2", package: "swift-nio-http2"),
        .product(name: "NIOSSL", package: "swift-nio-ssl"),
        .product(name: "NIOExtras", package: "swift-nio-extras"),
    ]
let nioConcurrency: [Target.Dependency] = [.product(name: "NIOConcurrencyHelpers", package: "swift-nio")]

let package = Package(
    name: "GulpKit",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "GulpWorkspace", targets: ["GulpWorkspace"]),
        .library(name: "GulpAutomation", targets: ["GulpAutomation"]),
        .library(name: "GulpFeatures", targets: ["GulpFeatures"]),  // real content only on macOS
        .executable(name: "gulp-cli", targets: ["gulp-cli"]),
        .executable(name: "gulp-vulnlab", targets: ["gulp-vulnlab"]),
    ],
    dependencies: [
        // Minimum versions; bump to the latest compatible releases and commit Package.resolved.
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.27.0"),
        .package(url: "https://github.com/apple/swift-nio-http2.git", from: "1.33.0"),
        .package(url: "https://github.com/apple/swift-nio-extras.git", from: "1.22.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.1.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.7.0"),
        .package(url: "https://github.com/apple/swift-collections.git", from: "1.1.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.6.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "7.0.0"),
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.0.0"),
    ],
    targets: [
        // ---- Foundation layer ----
        .target(
            name: "GulpCore",
            dependencies: [
                .product(name: "Collections", package: "swift-collections"),
                .product(name: "Logging", package: "swift-log"),
            ]),

        // ---- Services layer ----
        .target(
            name: "GulpCodec",
            dependencies: [
                "GulpCore", "CZlib", .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]),
        .target(name: "GulpQuery", dependencies: ["GulpCore"]),
        .target(name: "GulpDiff", dependencies: ["GulpCore"]),
        // System zlib: blob compression (GulpStore) and decompression helpers (GulpHTTP, HTTP-007).
        // Headers ship with the macOS SDK and with zlib1g-dev on Linux.
        .systemLibrary(name: "CZlib", path: "Sources/CZlib"),
        .target(
            name: "GulpStore",
            dependencies: [
                "GulpCore", "GulpQuery", "CZlib", .product(name: "GRDB", package: "GRDB.swift"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]),
        .target(
            name: "GulpTLS",
            dependencies: [
                "GulpCore",
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
            ]),

        // ---- Engine layer ----
        .target(
            name: "GulpHTTP",
            dependencies: ["GulpCore", "GulpTLS", "CZlib"] + nioHTTP + nioConcurrency + [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOTLS", package: "swift-nio"),
                .product(name: "NIOHPACK", package: "swift-nio-http2"),
                .product(name: "NIOHTTPCompression", package: "swift-nio-extras"),
                .product(name: "NIOSOCKS", package: "swift-nio-extras"),
            ]),
        .target(
            name: "GulpProxy",
            dependencies: ["GulpCore", "GulpHTTP", "GulpTLS", "GulpQuery"] + nioHTTP + nioConcurrency + [
                .product(name: "NIOTLS", package: "swift-nio"),
                .product(name: "NIOHPACK", package: "swift-nio-http2"),
            ]),
        .target(name: "GulpSession", dependencies: ["GulpCore", "GulpHTTP"]),
        .target(name: "GulpRepeater", dependencies: ["GulpCore", "GulpHTTP"]),
        .target(name: "GulpOAST", dependencies: ["GulpCore", "GulpHTTP"]),
        .target(
            name: "GulpFuzzer",
            dependencies: ["GulpCore", "GulpHTTP", "GulpCodec", "GulpOAST", "GulpSession"],
            resources: [.copy("Wordlists")]),
        // GulpCrawler defines the BrowserDriver protocol; it must NOT import GulpBrowser (ADR-010).
        .target(name: "GulpCrawler", dependencies: ["GulpCore", "GulpHTTP", "GulpSession"]),
        .target(
            name: "GulpScanner",
            dependencies: [
                "GulpCore", "GulpHTTP", "GulpOAST", "GulpCrawler", "GulpSession",
            ]),
        .target(name: "GulpSequencer", dependencies: ["GulpCore", "GulpHTTP"]),
        .target(name: "GulpReport", dependencies: ["GulpCore"]),
        .target(name: "GulpExtensions", dependencies: ["GulpCore", "GulpHTTP"]),
        // GulpAI is an orchestration-layer consumer (architecture §3 rule 6): it builds on the
        // GulpWorkspace agent tool surface, so it depends on GulpWorkspace, not the other way round.
        .target(name: "GulpAI", dependencies: ["GulpCore", "GulpWorkspace", "GulpReport"]),

        // macOS-capability modules (empty shells on Linux). GulpBrowser implements
        // GulpCrawler's BrowserDriver; GulpWorkspace injects it on macOS.
        .target(name: "GulpBrowser", dependencies: ["GulpCore", "GulpHTTP", "GulpCrawler"] + nioConcurrency),
        .target(name: "GulpScript", dependencies: ["GulpCore"]),
        .target(name: "GulpUI", dependencies: ["GulpCore"]),

        // ---- Orchestration layer ----
        .target(
            name: "GulpWorkspace",
            dependencies: [
                "GulpCore", "GulpCodec", "GulpQuery", "GulpDiff", "GulpStore", "GulpTLS",
                "GulpHTTP", "GulpProxy", "GulpSession", "GulpRepeater", "GulpFuzzer", "GulpOAST",
                "GulpCrawler", "GulpScanner", "GulpSequencer", "GulpReport", "GulpExtensions",
                "GulpBrowser", "GulpScript",
            ]),
        .target(
            name: "GulpAutomation",
            dependencies: [
                "GulpCore", "GulpWorkspace", "GulpStore", "GulpHTTP",
                .product(name: "Hummingbird", package: "hummingbird"),
            ]),

        // ---- UI layer (macOS content; empty on Linux) ----
        .target(
            name: "GulpFeatures",
            dependencies: [
                "GulpCore", "GulpCodec", "GulpStore", "GulpProxy", "GulpTLS", "GulpWorkspace", "GulpUI",
                "GulpAI", "GulpHTTP", "GulpRepeater", "GulpDiff", "GulpFuzzer", "GulpQuery",
            ]),

        // ---- Executables ----
        .executableTarget(
            name: "gulp-cli",
            dependencies: [
                "GulpWorkspace", "GulpAutomation", "GulpHTTP", "GulpProxy", "GulpStore", "GulpTLS",
                "GulpCodec", "GulpCore", "GulpBrowser", "GulpDiff", "GulpRepeater", "GulpFuzzer",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]),
        .executableTarget(
            name: "gulp-vulnlab",
            dependencies: ["GulpCore", "GulpTLS", "GulpCodec"] + nioCore + nioConcurrency + [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOTLS", package: "swift-nio"),
                .product(name: "NIOHTTP2", package: "swift-nio-http2"),
                .product(name: "NIOHPACK", package: "swift-nio-http2"),
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]),

        // ---- Tests (one per module + integration) ----
        .testTarget(name: "GulpCoreTests", dependencies: ["GulpCore"], resources: [.copy("Fixtures")]),
        .testTarget(name: "GulpCodecTests", dependencies: ["GulpCodec", "GulpCore"]),
        .testTarget(name: "GulpQueryTests", dependencies: ["GulpQuery", "GulpCore"]),
        .testTarget(name: "GulpDiffTests", dependencies: ["GulpDiff"]),
        .testTarget(name: "GulpStoreTests", dependencies: ["GulpStore", "GulpQuery"]),
        .testTarget(
            name: "GulpTLSTests",
            dependencies: ["GulpTLS"] + nioCore + [
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOTLS", package: "swift-nio"),
            ]),
        .testTarget(
            name: "GulpHTTPTests",
            dependencies: ["GulpHTTP", "GulpTLS"] + nioCore + nioConcurrency + [
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOHTTP2", package: "swift-nio-http2"),
                .product(name: "NIOHPACK", package: "swift-nio-http2"),
            ]),
        .testTarget(
            name: "GulpProxyTests",
            dependencies: ["GulpProxy", "GulpTLS", "GulpQuery"] + nioCore + nioConcurrency + [
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOHTTP2", package: "swift-nio-http2"),
                .product(name: "NIOHPACK", package: "swift-nio-http2"),
            ]),
        .testTarget(name: "GulpSessionTests", dependencies: ["GulpSession"]),
        .testTarget(
            name: "GulpRepeaterTests",
            dependencies: ["GulpRepeater", "GulpHTTP", "GulpCore"] + nioConcurrency + nioCore),
        .testTarget(name: "GulpOASTTests", dependencies: ["GulpOAST"]),
        .testTarget(name: "GulpFuzzerTests", dependencies: ["GulpFuzzer", "GulpCodec"]),
        .testTarget(name: "GulpCrawlerTests", dependencies: ["GulpCrawler"]),
        .testTarget(name: "GulpScannerTests", dependencies: ["GulpScanner", "GulpCore"]),
        .testTarget(name: "GulpSequencerTests", dependencies: ["GulpSequencer"]),
        .testTarget(name: "GulpReportTests", dependencies: ["GulpReport"]),
        .testTarget(name: "GulpExtensionsTests", dependencies: ["GulpExtensions"]),
        .testTarget(name: "GulpAITests", dependencies: ["GulpAI"]),
        .testTarget(name: "GulpBrowserTests", dependencies: ["GulpBrowser"]),
        .testTarget(name: "GulpScriptTests", dependencies: ["GulpScript"]),
        .testTarget(name: "GulpUITests", dependencies: ["GulpUI", "GulpCore"]),
        .testTarget(name: "GulpFeaturesTests", dependencies: ["GulpFeatures"]),
        .testTarget(
            name: "GulpWorkspaceTests",
            dependencies: [
                "GulpWorkspace", "GulpTLS", "GulpRepeater", "GulpCodec", "GulpFuzzer", "GulpQuery",
            ]),
        .testTarget(
            name: "GulpAutomationTests", dependencies: ["GulpAutomation", "GulpWorkspace", "GulpStore"]),
        .testTarget(name: "IntegrationTests", dependencies: ["GulpWorkspace"]),
    ],
    swiftLanguageModes: [.v6]
)
