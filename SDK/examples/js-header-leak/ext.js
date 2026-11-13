// A Gulp in-process JS extension (runtime: "js"). It runs inside a JavaScriptCore JSContext; Gulp calls
// `initialize` once, then `passiveCheck` for each exchange. The host API is `host.log(message)` and,
// with the http-send permission, `host.httpSend(params) -> response`.
//
// This mirrors the out-of-process `header-leak` example: it flags responses that leak a debug header,
// which can expose internal routing or framework detail. Returning findings needs the create-issues
// permission (enforced by the host).

// Headers that should never reach a client.
var LEAKY = ["x-debug", "x-powered-by", "x-aspnet-version", "server-timing", "x-backend-server"];

// Register the passive check Gulp will show in the manager.
function initialize(apiVersion) {
  host.log("js-header-leak initialized (API " + apiVersion + ")");
  return {
    passiveChecks: [{ id: "js.header-leak", name: "Debug-header leak (JS)" }],
  };
}

// Inspect one exchange; return any findings.
function passiveCheck(request, response) {
  var findings = [];
  var lower = String(response).toLowerCase();
  for (var i = 0; i < LEAKY.length; i++) {
    var header = LEAKY[i];
    // A header line looks like "\r\nx-debug: ...".
    if (lower.indexOf("\n" + header + ":") !== -1) {
      findings.push({
        typeID: "js.header-leak",
        name: "Debug header leaked: " + header,
        severity: "low",
        detail: "The response includes the debugging header '" + header + "', which can expose "
          + "internal framework or routing detail to clients.",
        marker: header,
      });
    }
  }
  return { findings: findings };
}
