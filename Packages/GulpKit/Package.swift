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
        .target(name: "GulpCodec", dependencies: ["GulpCore"]),
        .target(name: "GulpQuery", dependencies: ["GulpCore"]),
        .target(name: "GulpDiff", dependencies: ["GulpCore"]),
        .target(
            name: "GulpStore",
            dependencies: [
                "GulpCore", .product(name: "GRDB", package: "GRDB.swift"),
            ]),
        .target(
            name: "GulpTLS",
            dependencies: [
                "GulpCore",
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
            ]),

        // ---- Engine layer ----
        .target(
            name: "GulpHTTP",
            dependencies: ["GulpCore", "GulpTLS"] + nioHTTP + [
                .product(name: "NIOHTTPCompression", package: "swift-nio-extras"),
                .product(name: "NIOSOCKS", package: "swift-nio-extras"),
            ]),
        .target(name: "GulpProxy", dependencies: ["GulpCore", "GulpHTTP", "GulpTLS"] + nioHTTP),
        .target(name: "GulpSession", dependencies: ["GulpCore", "GulpHTTP"]),
        .target(name: "GulpRepeater", dependencies: ["GulpCore", "GulpHTTP"]),
        .target(name: "GulpOAST", dependencies: ["GulpCore", "GulpHTTP"]),
        .target(name: "GulpFuzzer", dependencies: ["GulpCore", "GulpHTTP", "GulpOAST", "GulpSession"]),
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
        .target(name: "GulpBrowser", dependencies: ["GulpCore", "GulpHTTP", "GulpCrawler"]),
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
                "GulpCore", "GulpWorkspace", .product(name: "Hummingbird", package: "hummingbird"),
            ]),

        // ---- UI layer (macOS content; empty on Linux) ----
        .target(name: "GulpFeatures", dependencies: ["GulpCore", "GulpWorkspace", "GulpUI", "GulpAI"]),

        // ---- Executables ----
        .executableTarget(
            name: "gulp-cli",
            dependencies: [
                "GulpWorkspace", "GulpAutomation", "GulpHTTP", "GulpCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]),
        .executableTarget(
            name: "gulp-vulnlab",
            dependencies: ["GulpCore"] + nioCore + [
                .product(name: "Hummingbird", package: "hummingbird"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]),

        // ---- Tests (one per module + integration) ----
        .testTarget(name: "GulpCoreTests", dependencies: ["GulpCore"], resources: [.copy("Fixtures")]),
        .testTarget(name: "GulpCodecTests", dependencies: ["GulpCodec"]),
        .testTarget(name: "GulpQueryTests", dependencies: ["GulpQuery"]),
        .testTarget(name: "GulpDiffTests", dependencies: ["GulpDiff"]),
        .testTarget(name: "GulpStoreTests", dependencies: ["GulpStore"]),
        .testTarget(name: "GulpTLSTests", dependencies: ["GulpTLS"]),
        .testTarget(name: "GulpHTTPTests", dependencies: ["GulpHTTP"] + nioCore + nioConcurrency),
        .testTarget(name: "GulpProxyTests", dependencies: ["GulpProxy"]),
        .testTarget(name: "GulpSessionTests", dependencies: ["GulpSession"]),
        .testTarget(name: "GulpRepeaterTests", dependencies: ["GulpRepeater"]),
        .testTarget(name: "GulpOASTTests", dependencies: ["GulpOAST"]),
        .testTarget(name: "GulpFuzzerTests", dependencies: ["GulpFuzzer"]),
        .testTarget(name: "GulpCrawlerTests", dependencies: ["GulpCrawler"]),
        .testTarget(name: "GulpScannerTests", dependencies: ["GulpScanner"]),
        .testTarget(name: "GulpSequencerTests", dependencies: ["GulpSequencer"]),
        .testTarget(name: "GulpReportTests", dependencies: ["GulpReport"]),
        .testTarget(name: "GulpExtensionsTests", dependencies: ["GulpExtensions"]),
        .testTarget(name: "GulpAITests", dependencies: ["GulpAI"]),
        .testTarget(name: "GulpBrowserTests", dependencies: ["GulpBrowser"]),
        .testTarget(name: "GulpScriptTests", dependencies: ["GulpScript"]),
        .testTarget(name: "GulpUITests", dependencies: ["GulpUI"]),
        .testTarget(name: "GulpFeaturesTests", dependencies: ["GulpFeatures"]),
        .testTarget(name: "GulpWorkspaceTests", dependencies: ["GulpWorkspace"]),
        .testTarget(name: "GulpAutomationTests", dependencies: ["GulpAutomation"]),
        .testTarget(name: "IntegrationTests", dependencies: ["GulpWorkspace"]),
    ],
    swiftLanguageModes: [.v6]
)
