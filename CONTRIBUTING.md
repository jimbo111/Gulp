# Contributing to Gulp

Thanks for taking the time. Bug reports, fixes and new checks are all welcome.

## Build and test

You need Swift 6.1 or later. On macOS you also need Xcode (for the app) and Homebrew.

```bash
make bootstrap     # XcodeGen via Homebrew, resolve packages
make test          # GulpKit tests + the app's UI tests (macOS)
make test-core     # GulpKit tests only (macOS or Linux)
make lint          # swift format --strict, plus the architecture and hard-rule checks
make vulnlab       # the deliberately vulnerable test server on 127.0.0.1:8088
```

`make test` and `make lint` must pass before a change is merged. The `Scripts/*-dod.sh` scripts
are end-to-end checks against VulnLab; run the ones that cover what you changed.

## How changes are made

- **Read the docs first.** `docs/` is the source of truth: `docs/01-architecture.md` for module
  boundaries, `docs/features/Fxx-*.md` for what each feature must do, `docs/07-decisions.md` for why.
  If the code and the docs disagree, fix one of them in the same change.
- **Tests come with the change** and name the requirement they cover, for example
  `test_PRX013_inScope`.
- **Fix causes, not symptoms.** A fix that adds a fallback around a problem instead of removing it
  will be sent back.
- **Respect the hard rules** in [AGENTS.md](AGENTS.md) §4: raw bytes are sent exactly as written,
  the main thread never waits on the network or the database, active tools check scope before
  every send, and no secrets go into the repo. `make rules` checks most of them mechanically.
- **New scanner checks** need a VulnLab route with the bug and a `/safe/` twin without it. The
  check must find the first and stay quiet on the second.

## Commits and pull requests

One logical change per pull request. Commit messages are short and say what changed, for example
`Return 409 on duplicate device_id instead of 500`. Reference requirement IDs where they apply.

## Testing other people's systems

Gulp is for authorized testing only. Don't open issues or pull requests that target systems you
don't have permission to test, and don't include real targets or captured traffic in reports.
