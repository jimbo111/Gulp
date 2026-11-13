// GulpScanner — HTTP request-smuggling / desync probes (F23 ADV-030/031). These rely on Gulp's
// byte-exact engine (CLAUDE.md "raw bytes are the truth"): the probes carry deliberately conflicting
// length framing (Content-Length vs Transfer-Encoding) that a parser-normalizing client could never
// send. A front-end and back-end that disagree on where the body ends make a vulnerable chain wait for
// bytes that never come, so a timing differential against a normal baseline classifies the vector. The
// probe construction and the timing classification are pure and tested; a VulnLab route emulates the
// desync delay for the end-to-end DoD. Confirmation/exploitation is never run automatically.

import Foundation
import GulpCore

/// A request-smuggling vector.
public enum SmugglingVector: String, Sendable, CaseIterable {
    /// Front-end uses Content-Length, back-end uses Transfer-Encoding.
    case clte = "CL.TE"
    /// Front-end uses Transfer-Encoding, back-end uses Content-Length.
    case tecl = "TE.CL"
}

/// Builds smuggling timing probes and classifies the result.
public enum SmugglingProbe {
    /// The request line + Host of `base`, as a POST (smuggling needs a body).
    private static func head(_ base: RawRequest) -> (target: String, host: String) {
        let target = base.bytes[base.parsed.target].string()
        let host = base.headerValue("host")?.string() ?? "localhost"
        return (target.isEmpty ? "/" : target, host)
    }

    /// A timing probe for `vector`: conflicting framing that makes a vulnerable chain hang waiting for
    /// the rest of a body, while a correctly-behaving endpoint answers promptly.
    public static func timingProbe(_ vector: SmugglingVector, base: RawRequest) -> RawRequest {
        let (target, host) = head(base)
        let head = "POST \(target) HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n"
        let body: String
        switch vector {
        case .clte:
            // Front-end (CL=4) forwards `1\r\nA\r\n`; back-end (TE) reads chunk `A` then waits for the
            // next chunk that never arrives.
            body = head + "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\nX"
        case .tecl:
            // Front-end (TE) ends the body at `0\r\n\r\n`; back-end (CL=6) waits for 6 more bytes.
            body = head + "Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX"
        }
        return RawRequest(Bytes(body))
    }

    /// A benign baseline: the same endpoint with clean framing (no conflict), to time against.
    public static func baselineProbe(base: RawRequest) -> RawRequest {
        let (target, host) = head(base)
        return RawRequest(
            Bytes(
                "POST \(target) HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
    }

    /// Classify from timings: the probe is vulnerable when it takes markedly longer than the baseline
    /// (the back-end stalled waiting for bytes), by at least `threshold` seconds.
    public static func isVulnerable(baseline: Double, probe: Double, threshold: Double = 3) -> Bool {
        probe - baseline >= threshold
    }
}
