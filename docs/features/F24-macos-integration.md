# F24 — macOS integration

> Milestones: M3 (CA install), M20 (the rest) · Modules: `GulpFeatures`, `App/`, small helpers ·
> Depends on: F02, F20

## 1. Purpose

Make Gulp feel native and convenient on macOS: trusting the CA, toggling the system proxy, a menu
bar presence, Shortcuts/Services integration, Quick Look, and the usual Mac niceties.

## 2. Requirements

### 2.1 Certificate install (M3)

| ID | Pri | Requirement |
|---|---|---|
| MAC-001 | P0 | **Install CA in the login keychain**: add the Gulp CA to the user's login keychain and set it trusted for SSL. Prefer a user-approved flow (the system prompts for the password); document that trusting a root requires explicit user consent. Provide clear instructions and a one-click helper that opens the right flow; verify trust afterward (F02). |
| MAC-002 | P0 | **Uninstall/!trust** the CA from the keychain; show current trust status. |
| MAC-003 | P1 | **iOS Simulator install**: detect booted simulators and install the CA into them (`xcrun simctl keychain <udid> add-root-cert`), for testing mobile web/app traffic. |
| MAC-004 | P1 | Clear **manual instructions** for physical iOS/Android devices and other browsers (download from `http://gulp/cert.pem`, trust steps), shown in-app. |

### 2.2 System proxy and networking (M20)

| ID | Pri | Requirement |
|---|---|---|
| MAC-010 | P1 | **System proxy toggle**: set/unset the macOS HTTP/HTTPS proxy to a Gulp listener for a chosen network service (via `networksetup`/SystemConfiguration), with a clear on/off indicator and automatic revert on quit/crash (restore previous settings). Requires admin; explain why. |
| MAC-011 | P2 | Per-app proxying guidance (since macOS lacks per-app proxy natively): document using the Gulp Browser (F16) or environment variables for CLI tools; optionally a helper that launches a chosen app with proxy env vars set. |
| MAC-012 | P2 | Detect and warn about conflicting proxies/VPNs; detect when the system proxy points at a stopped listener. |

### 2.3 App integration (M20)

| ID | Pri | Requirement |
|---|---|---|
| MAC-020 | P1 | **Menu bar extra** (optional): show proxy/intercept status, quick toggles (intercept, listener, open browser), and recent issues count; click to open the app. |
| MAC-021 | P1 | **Dock & notifications**: dock badge for new high-severity issues/intercept queue; macOS user notifications for long task completion and high-severity findings (UI-090). |
| MAC-022 | P1 | **Services / Share**: a Service to "Send URL to Gulp (new Repeater request)" and to open a `.gulp`/HAR; register as a handler for `.gulp` and HAR files. |
| MAC-023 | P1 | **App Intents / Shortcuts**: expose actions (start proxy, run a scan on a URL, export a report) as App Intents so users can script Gulp from Shortcuts/automations. |
| MAC-024 | P2 | **Quick Look** extension for `.gulp`: preview a project (summary: host counts, issue counts, created/modified) without opening the app. |
| MAC-025 | P2 | **Universal Clipboard/Handoff** not required; ensure standard macOS behaviors (full-keyboard-access, window restoration, state restoration per window, dark mode, accent colors) work. |
| MAC-026 | P1 | **Sparkle auto-update** UI (check now, channel, release notes) wired to the signed appcast (doc 02 §8). |
| MAC-027 | P2 | **Gatekeeper-friendly first run**: signed/notarized; on first launch, guide through CA setup and the authorized-testing acknowledgment (F20 PRJ-024). |

## 3. UI

- Settings → TLS hosts the CA install/uninstall/status (MAC-001/002/003/004).
- Settings → Network hosts the system-proxy toggle and conflict warnings (MAC-010/012).
- Settings → General hosts the menu-bar-extra and notification preferences; Settings → Updates hosts
  Sparkle options.
- App Intents/Services registered via Info.plist and the App Intents framework; no dedicated UI.

## 4. Implementation notes

- **CA install**: use the Security framework (`SecCertificate`, trust settings) for the login
  keychain; because trusting a root is sensitive, rely on the system's user-consent prompt rather
  than trying to bypass it. Never silently modify the **System** keychain. Verify with
  `SecTrustEvaluateWithError` on a test leaf (F02).
- **System proxy**: prefer `SCPreferences`/`SCDynamicStore` (SystemConfiguration) or shell out to
  `networksetup`; capture the prior configuration and register a cleanup on terminate and a crash
  guard (a saved snapshot restored on next launch if we exited uncleanly while the proxy was set).
- **Menu bar extra**: `MenuBarExtra` (SwiftUI) gated by a setting; keep it lightweight.
- **App Intents**: define intents in the app target that call into `ProjectSession`/CLI-equivalent
  services; keep them headless-safe.
- **No App Sandbox** (ADR-005) is what makes the system-proxy toggle (MAC-010/011) and browser
  launching (F16) possible; keep Hardened Runtime entitlements minimal and documented.

## 5. Edge cases

- User declines the keychain password prompt → CA not trusted; show status and the manual path
  (download + trust) and the Gulp Browser alternative (no system trust needed).
- System proxy left set after a crash → restore from the saved snapshot on next launch; also offer a
  one-click "reset system proxy".
- Multiple network services (Wi-Fi, Ethernet, VPN) → let the user pick which to proxy; warn about
  VPNs that override proxy settings.
- MDM-managed machines may block keychain/proxy changes → detect failure and explain.

## 6. Acceptance tests

1. "Install CA" results in a trusted root (verified by `SecTrustEvaluateWithError` on a fresh leaf);
   "Uninstall" reverts it; status reflects both.
2. iOS Simulator install makes a booted simulator trust Gulp (manual/CI-assisted check).
3. System-proxy toggle routes a chosen service through Gulp and restores the exact prior settings on
   quit and after a simulated crash.
4. A Shortcuts action "Scan URL with Gulp" runs a scan and returns a result; the `.gulp` Quick Look
   shows a summary; a new high-severity issue posts a notification and badges the dock.
