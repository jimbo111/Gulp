# Lessons

Rules learned the hard way on this repo. Read at session start.

- **Gate commits on lint with `&&`.** `make lint | tail -1; git commit …` committed unformatted code
  twice: the pipe and the `;` both drop lint's exit code. Write `make lint >/dev/null 2>&1 && git
  commit …`.
- **Identifiers that name stored data are not branding.** Renaming the Keychain services along with
  the bundle ID orphaned every existing CA key, and a `try?` hid it (no HTTPS interception, no
  message). Before renaming an identifier, ask whether data is filed under it.
- **No `try?` on a failure the user must see.** If an optional result means "feature off", keep the
  error and surface it (`ProjectSession.certificateAuthorityError`).
- **Wall-clock tests need wide margins or relative checks.** A doubling's 3x bound and a cold,
  parallel 300 ms first-paint check both failed on CI runners. Compare scaling over a wide span
  (16x input vs 64x bound), warm one-time startup costs up first, and serialize timing suites.
- **A test stub that checks then records under two locks races.** Concurrent callers both see
  "empty". Do the check and the record in one locked step.
- **Coalesced writes hand out ids before the row exists.** Anything that stores an exchange id
  (Repeater history, Fuzzer results, OAST links) flushes the writer first.
- **macOS UI tests on this Mac**: unlocked screen, display awake (`caffeinate -d`), and no ⌘A in a
  text field (the Korean input method takes it).
- **`gh` hangs on this network.** Read CI with `curl -H "Authorization: Bearer $(gh auth token)"`
  against api.github.com, and push with `git -c credential.helper= -c
  credential.helper='!gh auth git-credential' push` (the keychain credential lacks `workflow`).
- **Starting Colima starts the owner's Supabase containers.** Stop them (and Colima) afterwards.
  Mount work under `$HOME`; Colima does not share `/private/tmp`.
- **Verify agent and reviewer reports against the code.** Three of the last review's findings were
  real bugs the implementer missed (orphaned CA, in-flight Notebook save, OAST flush), and one
  agent's claim of a stale carry-over turned out to hide a real bug.
