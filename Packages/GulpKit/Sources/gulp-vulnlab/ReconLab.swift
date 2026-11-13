// gulp-vulnlab — recon fixtures (F27, the secret & JS-endpoint recon DoD). The vulnerable routes leak
// a credential and hard-code endpoints in a JS file; the /safe/ twins serve the same shape with the
// secret removed and only a public, linked endpoint.

import Foundation
import GulpCore

enum ReconLab {
    // A fake but structurally-valid AWS key + a high-entropy token (not a real credential).
    static let awsKey = "AKIAIOSFODNN7EXAMPLE"
    static let apiToken = "sk_live_51H8xR2eZvKYlo2C9bQf3mN7pL4wX1aT6"

    static func respond(_ path: String) -> VulnReply? {
        switch path {
        case "/recipe/leak":
            // A verbose stack header a Check Recipe can flag.
            return VulnReply(
                bytes: VulnLab.response(
                    200, body: Array("ok\n".utf8),
                    headers: ["X-Powered-By: Express/4.17.1", "X-Debug-Token: 9f2c"]))
        case "/safe/recipe/leak":
            return VulnReply(bytes: VulnLab.response(200, body: Array("ok\n".utf8)))
        case "/recon/app.js":
            let js = """
                const API_BASE = "/api/v2";
                const config = { apiKey: "\(apiToken)", url: "/internal/admin/users" };
                fetch("/api/v2/profile").then(r => r.json());
                axios.post("/api/v2/orders", {});
                // legacy: fetch("/admin/debug/dump")
                """
            return VulnReply(
                bytes: VulnLab.response(200, body: Array(js.utf8), type: "application/javascript"))
        case "/recon/config":
            let body = "{\"region\":\"us-east-1\",\"aws_access_key_id\":\"\(awsKey)\",\"ok\":true}"
            return VulnReply(bytes: VulnLab.response(200, body: Array(body.utf8), type: "application/json"))
        case "/safe/recon/app.js":
            // No secret and no hard-coded endpoints (paths come from the server at runtime).
            let js = """
                const base = document.querySelector("meta[name=api]").content;
                fetch(base).then(r => r.json());
                """
            return VulnReply(
                bytes: VulnLab.response(200, body: Array(js.utf8), type: "application/javascript"))
        case "/safe/recon/config":
            return VulnReply(
                bytes: VulnLab.response(
                    200, body: Array("{\"region\":\"us-east-1\",\"ok\":true}".utf8), type: "application/json")
            )
        default:
            return nil
        }
    }
}
