# 02 — Build, development setup, CI and distribution

## 1. Prerequisites (macOS development machine)

| Tool | Version | Install |
|---|---|---|
| macOS | 14 Sonoma or later (Apple Silicon recommended) | — |
| Xcode | Latest stable (Swift 6.x toolchain) | App Store or developer.apple.com |
| Command Line Tools | Matching Xcode | `xcode-select --install` |
| Homebrew | latest | https://brew.sh |
| XcodeGen | latest | `brew install xcodegen` |
| swift-format | matches the toolchain | ships with Xcode 16+ (`swift format`), or `brew install swift-format` |
| Google Chrome or Chromium | any recent | Optional; Gulp can download Chrome for Testing (F16) |
| Docker | optional | For Beacon packaging and optional third-party vulnerable apps |

`make bootstrap` checks for these and installs the Homebrew tools that are missing.

## 2. First-time setup

```bash
git clone <repo> Gulp && cd Gulp
make bootstrap        # brew deps + `swift package resolve`
make generate         # creates Gulp.xcodeproj from project.yml
make run              # builds Debug and launches Gulp.app
```

To work in Xcode, run `open Gulp.xcodeproj` after `make generate`. The project file is generated and
git-ignored, so re-run `make generate` after editing `project.yml` or adding targets.

## 3. Makefile (create in M0)

The Makefile is the single entry point. Every target must work from a clean checkout.

| Target | Command(s) it runs |
|---|---|
| `bootstrap` | `brew bundle` (Brewfile: xcodegen, swift-format), `swift package --package-path Packages/GulpKit resolve` |
| `generate` | `xcodegen generate` |
| `build` | `xcodebuild -project Gulp.xcodeproj -scheme Gulp -configuration Debug -destination 'platform=macOS' build` |
| `run` | `build`, then `open` the built `.app` from DerivedData (use `-derivedDataPath .build/xcode` so the path is predictable) |
| `test-core` | `swift test --package-path Packages/GulpKit --parallel` |
| `test` | `test-core`, then `xcodebuild test -scheme Gulp` (app and UI tests) |
| `lint` | `swift format lint --strict --recursive App Packages Beacon` |
| `format` | `swift format --in-place --recursive App Packages Beacon` |
| `vulnlab` | `swift run --package-path Packages/GulpKit gulp-vulnlab --port 8088` |
| `beacon` | `swift run --package-path Beacon gulp-beacon --dev` |
| `release` | `Scripts/release.sh` (archive → sign → notarize → staple → DMG → Sparkle appcast) |
| `clean` | remove `.build`, `Gulp.xcodeproj` |

## 4. `project.yml` (XcodeGen) — required contents

- Target `Gulp` (application, macOS 14.0) with:
  - Sources in `App/`, and a dependency on the local package `Packages/GulpKit` (products
    `GulpFeatures`, `GulpWorkspace`).
  - Sparkle as a package dependency.
  - `Info.plist` keys: `CFBundleIdentifier = com.gulp.app` (change it if the user picks a different
    reverse-DNS ID), `LSMinimumSystemVersion`, `NSHumanReadableCopyright`, a document type for
    `*.gulp` (UTI `com.gulp.project`, conforms to `public.database` / `public.data`), and
    `SUFeedURL` for Sparkle.
  - Entitlements (`App/Gulp.entitlements`): **no App Sandbox**; Hardened Runtime on;
    `com.apple.security.cs.allow-jit` only if JavaScriptCore JIT is needed (measure first; without
    it, JSC falls back to its interpreter).
  - A post-build phase that embeds `gulp-cli` in `Gulp.app/Contents/Helpers/gulp` (so users can
    symlink it into `/usr/local/bin`).
- Target `GulpAppUITests` (XCUITest bundle for the app). Named with the `App` prefix to avoid
  colliding with the `GulpUI` module's own SwiftPM test target (`GulpUITests`).
- Scheme `Gulp`: test action runs `GulpAppUITests`. The SwiftPM tests run through `make test-core`.

## 5. `Package.swift` (GulpKit) — outline

```swift
// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "GulpKit",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "GulpWorkspace", targets: ["GulpWorkspace"]),
        .library(name: "GulpFeatures", targets: ["GulpFeatures"]),   // macOS only
        .executable(name: "gulp-cli", targets: ["gulp-cli"]),
        .executable(name: "gulp-vulnlab", targets: ["gulp-vulnlab"]),
    ],
    dependencies: [
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
    targets: [ /* one target per module in docs/01-architecture.md §2, plus test targets */ ]
)
```

The version numbers are minimums. Use the latest compatible releases when you create the file, and
commit `Package.resolved`.

Platform-only targets: put macOS-only targets in a conditional block
(`#if os(macOS) targets += [...] #endif`). This works because `Package.swift` is ordinary Swift
evaluated on the host.

**Platform modules are empty shells on Linux (not conditional targets).** A module breaks the Linux
build only if its *sources* fail to compile there (e.g. `import AppKit`). Rather than conditionalize
the manifest, the macOS-capability modules (`GulpBrowser`, `GulpScript`, `GulpUI`, `GulpFeatures`)
are **defined on every platform** and wrap their AppKit/JavaScriptCore code in `#if canImport(...)`,
compiling to an empty shell on Linux. Consequences:
- Every target and product exists identically on macOS and Linux; `Package.swift` has **no**
  platform `#if` and dependencies on these modules are plain and unconditional. On Linux the shells
  link as empty libraries (harmless); `swift build`/`swift test` run the whole graph.
- `GulpWorkspace` depends on `GulpBrowser`/`GulpScript` directly and injects the concrete
  `BrowserDriver` (from `GulpBrowser`) into `GulpCrawler`/`GulpScanner`, which only know the protocol
  (architecture §3 rule 5). On Linux the shell provides no driver, so static crawling is used.
- `GulpExtensions` lists no JavaScriptCore dependency; its JS host is guarded by
  `#if canImport(JavaScriptCore)` so the JSON-RPC runtime still builds on Linux.
- Trade-off vs. `.when(platforms:)` conditional dependencies: empty shells build (fast, empty) on
  Linux instead of being skipped. We accept that for a branch-free manifest; revisit if shell build
  time ever matters.

## 6. Building on Linux (core modules only)

Use this for CI or for Claude cloud sessions that run on Linux.

```bash
# Install a Swift 6 toolchain (e.g. via swiftly: https://swift.org/install/linux/)
sudo apt-get install -y libsqlite3-dev
swift build --package-path Packages/GulpKit
swift test  --package-path Packages/GulpKit
swift build --package-path Beacon
```

The macOS-only targets are excluded automatically (see §5).

## 7. Continuous integration (`.github/workflows/ci.yml`)

| Job | Runner | Steps |
|---|---|---|
| `core-linux` | `ubuntu-latest` + Swift 6 container | `swift build` + `swift test` for GulpKit and Beacon |
| `macos` | `macos-15` (or newer) | `make bootstrap generate lint test` |
| `release` (on tag `v*`) | `macos-15` | `make release` using signing secrets in GitHub encrypted secrets |

Cache `.build` and SwiftPM checkouts keyed on `Package.resolved`.

## 8. Code signing, notarization and distribution

You need these secrets for releases (only for `make release`, never committed):

- Developer ID Application certificate (.p12 + password) → imported into a temporary keychain in CI
- App Store Connect API key (for `notarytool`)
- Sparkle EdDSA private key (`generate_keys` from Sparkle) for signing the appcast

Release script steps (`Scripts/release.sh`):

1. `xcodebuild archive -scheme Gulp -configuration Release -archivePath .build/Gulp.xcarchive`
2. `xcodebuild -exportArchive` with `ExportOptions.plist` (method `developer-id`).
3. Sign the embedded helpers (`gulp-cli`) with Hardened Runtime and the same identity
   (`codesign --options runtime --timestamp`). Sign inside-out: helpers and frameworks first, then
   the app.
4. `ditto -c -k --keepParent Gulp.app Gulp.zip` →
   `xcrun notarytool submit Gulp.zip --key ... --key-id ... --issuer ... --wait`
5. `xcrun stapler staple Gulp.app`
6. Create the DMG (`hdiutil create` or `create-dmg`), then notarize and staple the DMG as well.
7. Generate and sign the Sparkle appcast entry (`generate_appcast`).

> **Concept: why notarize?** Gatekeeper on macOS blocks downloaded apps that aren't signed by an
> identified developer *and* checked by Apple's notary service. Notarization is an automated malware
> scan. Stapling attaches the ticket to the app so it opens even when the Mac is offline.

## 9. Local development tips

- `make vulnlab`, then in Gulp set the browser to proxy through 127.0.0.1:8080 and browse
  `http://localhost:8088`. VulnLab is the reference target for every feature (doc 06).
- Use `GULP_LOG_LEVEL=trace` to get verbose logs from the app or the CLI.
- `defaults delete com.gulp.app` resets user settings during development.
- To test the TLS path without touching the system trust store, use the Gulp Browser (F16). It
  trusts the Gulp CA through the `--ignore-certificate-errors-spki-list` flag.
