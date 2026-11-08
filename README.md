# Gulp

**Gulp** is a native macOS application for web application security testing: an intercepting
HTTP(S)/WebSocket proxy plus a full toolkit (Repeater, Fuzzer, Scanner, Crawler, OAST "Beacon",
Decoder and JWT Workbench, Comparer, gRPC/protobuf, session handling, extensions, automation and an
optional AI assistant).

Its feature set matches a commercial-grade web security suite (Burp Suite Professional is the
reference point) and adds features that suit a modern, native macOS tool.

> ⚠️ Gulp is for **authorized** security testing only. Testing systems without permission is illegal
> in most jurisdictions. Gulp enforces target scope by default (see `docs/00-vision.md` §6).

## Status

This repository currently holds the **specification and build plan**. The code is written milestone
by milestone, following `docs/03-roadmap.md`. Progress is tracked in `docs/PROGRESS.md`.

## Where to start

| You are… | Read |
|---|---|
| Claude (or any engineer) building Gulp | [`CLAUDE.md`](CLAUDE.md), then [`docs/README.md`](docs/README.md) |
| Someone who wants the big picture | [`docs/00-vision.md`](docs/00-vision.md) |
| Someone setting up a dev machine | [`docs/02-build-and-dev-setup.md`](docs/02-build-and-dev-setup.md) |

## Tech stack (summary)

- **Swift 6** (strict concurrency), **SwiftUI + AppKit** UI, macOS 14 Sonoma or later
- **SwiftNIO** (+ NIO SSL / HTTP2 / Extras) for the proxy and the raw HTTP engine
- **swift-certificates / swift-crypto** for the on-the-fly MITM certificate authority
- **SQLite via GRDB** for project files (`*.gulp`)
- **JavaScriptCore** for in-app scripting; JSON-RPC over stdio for out-of-process extensions
- **XcodeGen** for the app project; all logic lives in a SwiftPM package (`Packages/GulpKit`)

The reasoning behind each choice is in [`docs/07-decisions.md`](docs/07-decisions.md).

## License

Gulp is released under the [MIT License](LICENSE).

> Reminder: Gulp is for **authorized** security testing only. The MIT license grants broad reuse
> rights but does not authorize testing systems you don't have permission to test.
