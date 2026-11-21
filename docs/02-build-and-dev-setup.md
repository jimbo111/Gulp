# 02 — Build, development setup, CI and distribution

## 1. Prerequisites (macOS development machine)

| Tool | Version | Install |
|---|---|---|
| macOS | 14 Sonoma or later (Apple Silicon recommended) | — |
| Xcode | Latest stable; Swift 6.1 or later (swift-crypto ≥ 4.5.1 needs tools 6.1). Verified: Xcode 27.2 / Swift 6.4 | App Store or developer.apple.com |
| Command Line Tools | Matching Xcode | `xcode-select --install` |
| Homebrew | latest | https://brew.sh |
| XcodeGen | latest | `brew install xcodegen` |
| swift-format | ships with the toolchain | `swift format` (Xcode 16+ and Swift 6 toolchains); nothing to install |
| Google Chrome or Chromium | any recent | Optional; Gulp can download Chrome for Testing (F16) |
| Docker | optional | For Beacon packaging and optional third-party vulnerable apps |

`make bootstrap` runs `brew bundle` (installs XcodeGen) and resolves both SwiftPM packages; it does
not check the other tools.

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
| `bootstrap` | `brew bundle` (Brewfile: xcodegen), `swift package resolve` for `Packages/GulpKit` and `Beacon` |
| `generate` | `xcodegen generate` |
| `build` | `xcodebuild -project Gulp.xcodeproj -scheme Gulp -configuration Debug -destination 'platform=macOS' build` |
| `run` | `build`, then `open` the built `.app` from DerivedData (use `-derivedDataPath .build/xcode` so the path is predictable) |
| `test-core` | `swift test --package-path Packages/GulpKit --parallel $(SWIFTPM_FLAGS)` |
| `test` | `test-core`, then `xcodebuild test -scheme Gulp` (app and UI tests) |
| `perf` | `swift test --package-path Packages/GulpKit --filter PerformanceTests` (the performance budgets in doc 06 §5; kept out of `test` because it is slow). **No `PerformanceTests` exist yet**, so it currently runs nothing; the M9 and M8 DoD scripts measure the GulpQL and Fuzzer budgets instead |
| `lint` | `make rules`, then `swift format lint --strict --recursive App Packages Beacon UITests` |
| `rules` | `Scripts/arch-check.sh` + `Scripts/rules-check.sh` (grep-only; works on Linux) |
| `format` | `swift format --in-place --recursive App Packages Beacon UITests` |
| `vulnlab` | `swift run --package-path Packages/GulpKit gulp-vulnlab --port 8088` |
| `beacon` | `swift run --package-path Beacon gulp-beacon --dev` |
| `release` | `Scripts/release.sh` (archive → sign → notarize → staple → DMG → Sparkle appcast) |
| `clean` | remove `.build`, `Gulp.xcodeproj`, `Packages/GulpKit/.build`, `Beacon/.build` |

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
        .library(name: "GulpAutomation", targets: ["GulpAutomation"]),
        .library(name: "GulpFeatures", targets: ["GulpFeatures"]),   // real content only on macOS
        .executable(name: "gulp-cli", targets: ["gulp-cli"]),
        .executable(name: "gulp-vulnlab", targets: ["gulp-vulnlab"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.27.0"),
        .package(url: "https://github.com/apple/swift-nio-http2.git", from: "1.33.0"),
        .package(url: "https://github.com/apple/swift-nio-extras.git", from: "1.22.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.1.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.5.1"),   // < 4.5.1: RSA double-free
        .package(url: "https://github.com/apple/swift-collections.git", from: "1.1.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.6.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
        .package(url: "https://github.com/groue/GRDB.swift.git", from: "7.0.0"),
        .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.0.0"),
    ],
    targets: [ /* one target per module in docs/01-architecture.md §2, plus test targets */ ]
)
```

The version numbers are minimums; `Package.swift` is the authority. Commit `Package.resolved`.
`swift-crypto` must stay ≥ 4.5.1: older versions double-free an `EVP_PKEY` when RSA public-key DER
parsing fails. 4.5.x needs Swift tools 6.1, so building needs a Swift 6.1+ toolchain even though the
manifest declares tools 6.0.

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
# Install a Swift 6.1+ toolchain (e.g. via swiftly: https://swift.org/install/linux/), or use the
# swift:6.1-noble Docker image that CI uses.
swift build --package-path Packages/GulpKit
swift test  --package-path Packages/GulpKit
swift build --package-path Beacon
```

SQLite: GRDB 7 needs `sqlite3_snapshot_*`, which Ubuntu's `libsqlite3` lacks, so install a SQLite
built with `SQLITE_ENABLE_SNAPSHOT` and FTS5 into `/usr/local` (the `core-linux` job in
`.github/workflows/ci.yml` shows the exact steps) and pass
`SWIFTPM_FLAGS="-Xcc -I/usr/local/include -Xlinker -L/usr/local/lib"`.

The macOS-capability targets are not excluded: they build on Linux as empty shells (see §5).

## 7. Continuous integration (`.github/workflows/ci.yml`)

**CI cannot run at the moment** (GitHub Actions minutes are exhausted). The workflow is kept current
for when it can; until then the local `make test` + `make lint` is the only gate.

| Job | Runner | Steps |
|---|---|---|
| `core-linux` | `ubuntu-latest` + `swift:6.1-noble` container | builds SQLite with snapshot + FTS5, `swift build` + `swift test` for GulpKit, `arch-check.sh`, `rules-check.sh`, every `Scripts/*-dod.sh`, `jsc-host-typecheck.sh`, then build + test Beacon |
| `macos` | `macos-15` | `brew install xcodegen`, then `make lint`, `make generate`, `make test-core`, `Scripts/m4b-browser.sh`, `make build`, `make test`. It still selects `Xcode_16`, which ships Swift 6.0; it needs Xcode 16.3+ (Swift 6.1) before it can pass |
| `release` (on tag `v*`) | `macos-15` | placeholder step; `make release` with signing secrets is not wired yet |

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
- `defaults delete com.gulp.app` resets user settings during development.
- To test the TLS path without touching the system trust store, use the Gulp Browser (F16). It
  trusts the Gulp CA through the `--ignore-certificate-errors-spki-list` flag.
