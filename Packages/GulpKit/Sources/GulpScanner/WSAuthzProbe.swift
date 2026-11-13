// WebSocket per-message authorization (F23 WSX-004). Many servers authenticate a WebSocket only at
// the HTTP handshake and then trust every frame on that connection. The probe replays a *privileged*
// message — one that works for a high-privilege identity — over a connection opened with a stripped or
// lower-privilege identity. If the privileged action still succeeds, the server never re-authorized
// the action per message, so any authenticated (or hijacked) socket can perform it.

/// The outcome of a per-message WebSocket authorization probe.
public enum WSAuthzVerdict: String, Sendable, Equatable {
    /// The privileged action succeeded under the stripped identity — per-message authorization is
    /// missing (the server authorized only at the handshake). This is the finding.
    case missing
    /// The stripped identity was refused — the server re-checks authorization on each message.
    case enforced
    /// The privileged baseline did not itself succeed, so nothing can be concluded (wrong message,
    /// wrong privileged identity, or the socket does not expose the action).
    case inconclusive
}

/// Classifies a per-message WebSocket authorization probe from the two replies to one privileged
/// message: one under a privileged identity, one under a stripped identity.
public enum WSAuthzProbe {
    /// Error-shaped tokens that mark a *denied* privileged reply (so the baseline is not a success).
    static let denialTokens = ["forbidden", "unauthorized", "denied", "\"error\"", "not allowed"]

    /// Decide whether per-message authorization is enforced.
    ///
    /// - Parameters:
    ///   - privilegedReply: the reply to the privileged message under the privileged identity.
    ///   - strippedReply: the reply to the *same* message under the stripped/other identity.
    ///   - successMarker: a substring that identifies a *successful* privileged reply (for example the
    ///     secret value or a success field). When empty, the privileged reply must be non-empty and
    ///     not denial-shaped, and the stripped reply is compared for equality against it.
    /// - Returns: `.missing` if the stripped identity also got the privileged result, `.enforced` if it
    ///   was refused, `.inconclusive` if the privileged baseline was not a success.
    public static func classify(
        privilegedReply: String, strippedReply: String, successMarker: String
    ) -> WSAuthzVerdict {
        let privileged = privilegedReply.lowercased()
        if privilegedReply.isEmpty || denialTokens.contains(where: { privileged.contains($0) }) {
            return .inconclusive
        }
        let marker = successMarker.isEmpty ? privilegedReply : successMarker
        guard privilegedReply.contains(marker) else { return .inconclusive }
        return strippedReply.contains(marker) ? .missing : .enforced
    }
}
