# Gulp

An intercepting proxy and web security workbench for macOS, written in Swift. (Not related to the
gulp.js build tool.)

<p>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/hero-dark.svg">
    <img src="docs/assets/hero-light.svg" width="880" alt="Gulp holds a request in Intercept, the user changes &quot;role&quot; from user to admin, forwards it, and the response comes back with a mass-assignment finding.">
  </picture>
</p>

> **Pre-release.** The engines and CLI are tested on macOS and Linux. The macOS app runs, but there
> is no signed build yet ([status](#status)).

Repeater, Fuzzer, Scanner, Crawler, out-of-band testing, and a set of specialist tools that other
suites leave to plugins, all around one proxy.

Here it is checking an OAuth authorization server:

```console
$ gulp-cli sso probe --target http://127.0.0.1:8088 \
    --authorize "http://127.0.0.1:8088/authorize?response_type=code&client_id=app"\
"&redirect_uri=http://127.0.0.1:8088/callback&state=s"\
"&code_challenge=abc&code_challenge_method=S256"

sso probe: redirect_uri variants
  [registered] http://127.0.0.1:8088/callback → accepted
  [path-suffix] http://127.0.0.1:8088/callback/../evil → ACCEPTED
  [path-traversal] http://127.0.0.1:8088/callback/%2e%2e/evil → ACCEPTED
  [subdomain] http://evil.example.127.0.0.1:8088/callback → rejected
  [sibling-host] http://127.0.0.1:8088.evil.example/callback → rejected
  [@-confusion] http://127.0.0.1:8088@evil.example/callback → rejected
  [open-redirect-chain] http://127.0.0.1:8088/callback?next=https://evil.example/ → ACCEPTED
redirect_uri: OVER-ACCEPTS 3 variant(s) — path-suffix, path-traversal, open-redirect-chain
sso probe: PKCE enforcement
  method=plain → ACCEPTED
  no PKCE → ACCEPTED
pkce: DOWNGRADEABLE (plain or none accepted)
```

Point the same command at the fixed version of that server (`/safe/authorize`) and every line
comes back `rejected`. That pairing is how Gulp is tested.

## Every bug has a twin

Gulp ships with **VulnLab**, a deliberately broken local web app. Every vulnerable route in it has a
twin under `/safe/` with the same shape and the bug fixed: `/sqli/error` and `/safe/sqli/error`,
`/cache/poison` and `/safe/cache/poison`, `/graphql` and `/safe/graphql`.

Each check has to find the bug on one and stay quiet on the other. Catching the bug proves the check
works. Staying quiet on the fixed twin proves it isn't just flagging every response.

The test suite is built around it: 640 unit tests and 41 end-to-end scripts that start VulnLab,
drive the real CLI against it, and fail if a finding lands on a `/safe/` route.

## What's in it

If you've used Burp Suite you already know the layout. The names differ in a few places
([full map](docs/00-vision.md#4-naming-map-reference-suite--gulp)).

| Tool | What it does |
|---|---|
| **Proxy** | HTTP/1.1, HTTP/2 and WebSockets, with TLS interception from a local CA. Intercept, match & replace, streaming responses and SSE. |
| **Repeater** | Sends the bytes you wrote, exactly. Raw HTTP/2, pipelining, and race-condition groups (single-packet, parallel, sequential). |
| **Fuzzer** | Sniper / battering ram / pitchfork / cluster bomb, payload processing, grep and extract, rate caps, content discovery. |
| **Scanner** | Passive and active checks: SQLi (error, boolean, time), XSS, SSTI, command injection, XXE, SSRF, path traversal, NoSQL, LDAP, XPath, prototype pollution, file upload, CORS, host header, JWT. |
| **Check Recipes** | Write your own passive checks in JSON, no code needed. |
| **Crawler** | Static crawl, crawl-and-audit, OpenAPI import. |
| **Beacon** | Out-of-band (OAST) detection, compatible with interactsh, plus a local dev server for tests (a deployable server is planned). |
| **GulpQL** | A query language over your traffic: `resp.status >= 500 and req.host ~ "api"`. Tested on a million-row project. |
| **Sessions** | Cookie jar, identities, login macros, and request signing (AWS SigV4, DPoP, RFC 9421). |
| **Decoder / Comparer / Sequencer** | Transform chains and inline transform tags, byte and word diffs, token randomness analysis. |

### Workbenches you'd normally install as plugins

- **Authz Matrix**: replays each request as each user and shows you who can see what.
- **JWT Workbench**: decode, re-sign, `alg` confusion, a secret-cracking wordlist.
- **GraphQL Workbench**: introspection, schema view, object-level authorization probe.
- **gRPC / protobuf**: decodes gRPC, gRPC-Web and Connect traffic, with or without `.proto` files; schemas by reflection; fuzz individual protobuf fields.
- **Smuggling Probe**: CL.TE / TE.CL timing detection, then a confirmation step.
- **Param Discovery**: finds hidden parameters in batches.
- **JS Recon**: pulls endpoints, secrets and source maps out of bundles, and diffs two deploys of the same bundle.
- **WebSocket tools**: cross-site WebSocket hijacking, message fuzzing, per-message authz, scripted conversations, out-of-band payloads over a socket.
- **SSO Workbench**: OAuth/OIDC and SAML flow reconstruction, redirect_uri and PKCE attacks (above).
- **Cache poisoning & deception**: unkeyed headers, confirmed by a clean follow-up request.
- **LLM testing**: prompt-injection payloads against a chat endpoint; MCP tool-poisoning and missing-auth checks.
- **Retest**: re-runs the request behind an issue and tells you whether it's fixed, still there, or back again.

## Try it

You need Swift 6.1 or later. The engines and CLI build on macOS 14+ and on Linux; the app needs
macOS 14+ and Xcode.

```bash
make bootstrap && make run     # macOS: generate the Xcode project, build Gulp.app, launch it
```

The app listens as a proxy on `127.0.0.1:8080`. Point a browser at it, or use the toolbar's
Open Browser for a preconfigured one. To stay headless, use the CLI:

```bash
make vulnlab          # terminal 1: VulnLab on http://127.0.0.1:8088 (binds localhost only)
```

```bash
# terminal 2: build the CLI
swift build --package-path Packages/GulpKit --product gulp-cli
alias gulp-cli="$PWD/Packages/GulpKit/.build/debug/gulp-cli"
```

Then pick something to break:

```bash
gulp-cli llm inject --target http://127.0.0.1:8088 --path /chat --leak-marker SYS_SECRET_8f3a2
```

```bash
printf 'GET /smuggle HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n' > req.txt
gulp-cli smuggle --raw req.txt --target http://127.0.0.1:8088
```

`gulp-cli --help` lists the rest: around fifty subcommands, from `proxy` and `fuzz` to `scan active`
and `report`. The `Scripts/*-dod.sh` files are worked examples. Each one is a full session against
VulnLab you can read top to bottom.

On Linux, if SwiftPM can't find zlib or sqlite, add
`-Xcc -I/usr/local/include -Xlinker -L/usr/local/lib` to the build.

## Drive it from Claude Code

`gulp-cli mcp` serves a project over MCP. An agent can read your history, scope and site map, and
send requests to in-scope targets only. Every action it takes is written to the project's audit log.

```bash
claude mcp add gulp -- gulp-cli mcp --project ~/engagements/acme.gulp --approval in-scope
```

Leave out `--approval in-scope` and the agent can read but not send.

## Status

Pre-release. **The engines and the CLI are the finished part:** everything above runs headless and
is tested on macOS and Linux.

The macOS app builds, and its UI tests open every tool and send a request from Repeater to VulnLab.
It hasn't had a daily-driver beta yet, there are no signed downloads, and a few screens (Assistant,
Extensions, DOM Probe) are still previews of engines the CLI already drives. Brotli/zstd decoding
and an extension gallery are still on the list. [`docs/PROGRESS.md`](docs/PROGRESS.md) tracks every
milestone as it stands.

## How it's built

- **Raw bytes are the truth.** A request you edit is never parsed and rebuilt through `URLRequest`
  or anything else that "fixes" it. If you send a malformed header, Gulp sends that exact malformed
  header.
- **Scope is enforced, not suggested.** Active tools check scope before every send and refuse
  out-of-scope targets unless you override them for that one action.
- **Swift 6 with strict concurrency.** SwiftNIO for networking, swift-crypto and swift-certificates
  for the CA, SQLite (GRDB) for `.gulp` project files, JavaScriptCore for scripting.
- **The rules are checked by machine.** `make rules` (part of `make lint`) runs the architecture
  and hard-rule checks, like no bare network engine in an active tool, no silent store writes, and
  no randomness in tests without a seed.

The code is one SwiftPM package (`Packages/GulpKit`) split into layered modules. The app is a thin
shell over it. [`docs/01-architecture.md`](docs/01-architecture.md) has the module map, and
[`docs/07-decisions.md`](docs/07-decisions.md) explains why each piece is the way it is.

## Contributing

Bug reports and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers the build, the
gate (`make test` and `make lint`) and how changes are reviewed. If you use a coding agent,
[AGENTS.md](AGENTS.md) is the brief it should read first. Found a vulnerability in Gulp itself? See
[SECURITY.md](SECURITY.md).

## Use it on things you're allowed to test

Gulp is for authorized security testing: your own systems, systems you have written permission to
test, and labs like VulnLab. Pointing it anywhere else is illegal in most places. Scope enforcement
is on by default for that reason.

## License

[MIT](LICENSE). The license lets you reuse the code. It doesn't give you permission to test anyone
else's systems.
