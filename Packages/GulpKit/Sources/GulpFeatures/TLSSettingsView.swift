// GulpFeatures — Settings → TLS (F02 §3, F24 MAC-001/MAC-002/MAC-004): the CA's identity, export,
// install/remove in the login keychain, the "trusted by this Mac" badge, and instructions for other
// devices. Keychain calls can block on the system's password prompt, so they run off the main thread.

#if canImport(AppKit)
import AppKit
import GulpTLS
import GulpWorkspace
import SwiftUI
import UniformTypeIdentifiers

/// Settings → TLS.
public struct TLSSettingsView: View {
    let environment: WorkspaceEnvironment
    @State private var authority: CertificateAuthority?
    @State private var fingerprint = ""
    @State private var trusted: Bool?
    @State private var busy = false
    @State private var message: String?

    /// The TLS pane for the user's CA in `environment`.
    public init(environment: WorkspaceEnvironment = .standard) {
        self.environment = environment
    }

    /// The screen.
    public var body: some View {
        Form {
            Section("Gulp certificate authority") {
                if let authority {
                    LabeledContent("Subject", value: "\(authority.certificate.subject)")
                    LabeledContent("SHA-256") {
                        Text(fingerprint)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                    }
                    let expiry = authority.certificate.notValidAfter
                    LabeledContent("Valid until", value: expiry.formatted(date: .abbreviated, time: .omitted))
                    LabeledContent("Trusted by this Mac") { trustBadge }
                    HStack {
                        Button("Export…") { export(authority) }
                        Button("Install in Login Keychain…") { change { try KeychainTrust.install($0) } }
                            .help("Adds the CA to your login keychain and trusts it for TLS")
                        Button("Remove Trust") { change { try KeychainTrust.remove($0) } }
                    }
                    .disabled(busy)
                } else {
                    ProgressView()
                }
                if let message { Text(message).foregroundStyle(.secondary) }
            }
            Section("Other devices and browsers") {
                Text(
                    """
                    Download the certificate from http://gulp/cert.pem while using Gulp as the proxy, \
                    or export it here. iOS: install the profile, then enable full trust in Settings → \
                    General → About → Certificate Trust Settings. Android: install it as a user CA \
                    (apps targeting Android 7+ ignore user CAs unless they opt in). Firefox: import it \
                    under Settings → Privacy & Security → Certificates.
                    """
                )
                .font(.callout)
                .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .task { await load() }
    }

    @ViewBuilder private var trustBadge: some View {
        switch trusted {
        case true?: Label("Trusted", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
        case false?: Label("Not trusted", systemImage: "xmark.seal").foregroundStyle(.orange)
        case nil: ProgressView().controlSize(.small)
        }
    }

    private func load() async {
        let environment = self.environment
        let loaded = await Task.detached { () -> (CertificateAuthority, String, Bool)? in
            guard let authority = try? environment.certificateAuthority() else { return nil }
            let fingerprint = (try? authority.sha256Fingerprint()) ?? ""
            return (authority, fingerprint, (try? KeychainTrust.isTrusted(authority)) ?? false)
        }.value
        guard let loaded else {
            message = "The Gulp CA could not be loaded or created."
            return
        }
        authority = loaded.0
        fingerprint = loaded.1
        trusted = loaded.2
    }

    /// Run a Keychain change off the main thread, then refresh the trust badge.
    private func change(_ action: @escaping @Sendable (CertificateAuthority) throws -> Void) {
        guard let authority else { return }
        busy = true
        message = nil
        Task {
            let outcome = await Task.detached { () -> (String?, Bool) in
                var failure: String?
                do {
                    try action(authority)
                } catch {
                    failure = "\(error)"
                }
                return (failure, (try? KeychainTrust.isTrusted(authority)) ?? false)
            }.value
            message = outcome.0
            trusted = outcome.1
            busy = false
        }
    }

    private func export(_ authority: CertificateAuthority) {
        let panel = NSSavePanel()
        panel.title = "Export Gulp CA Certificate"
        panel.nameFieldStringValue = "gulp-ca.pem"
        panel.allowedContentTypes = ["pem", "der"].map { UTType(filenameExtension: $0) ?? .data }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let bytes =
                url.pathExtension.lowercased() == "der"
                ? try authority.certificateDER() : Array(try authority.certificatePEM().utf8)
            try Data(bytes).write(to: url)
            message = "Exported to \(url.lastPathComponent)."
        } catch {
            message = "Export failed: \(error)"
        }
    }
}
#endif
