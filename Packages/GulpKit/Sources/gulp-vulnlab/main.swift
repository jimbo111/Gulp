// gulp-vulnlab — intentionally vulnerable local test server (doc 06 §3). Binds 127.0.0.1 ONLY.
//
//   gulp-vulnlab [--port 8088] [--raw-port 8089] [--tls-port 8443]

import Foundation

var appPort = 8088
var rawPort = 8089
var tlsPort = 8443
var arguments = CommandLine.arguments.dropFirst()
while let argument = arguments.popFirst() {
    switch argument {
    case "--port":
        appPort = Int(arguments.popFirst() ?? "") ?? appPort
    case "--raw-port":
        rawPort = Int(arguments.popFirst() ?? "") ?? rawPort
    case "--tls-port":
        tlsPort = Int(arguments.popFirst() ?? "") ?? tlsPort
    case "--help", "-h":
        print("usage: gulp-vulnlab [--port 8088] [--raw-port 8089] [--tls-port 8443]")
        exit(0)
    default:
        FileHandle.standardError.write(Data("unknown argument: \(argument)\n".utf8))
        exit(64)
    }
}

let server = try await VulnLabServer.start(appPort: appPort, rawPort: rawPort, tlsPort: tlsPort)
let banner = """
    gulp-vulnlab \(VulnLab.version): INTENTIONALLY VULNERABLE test server. Do not expose it.
      http://127.0.0.1:\(appPort)  /echo /redirect /chunked /gzip /slow /large /continue /status/N
      tcp://127.0.0.1:\(rawPort)   raw echo: writes back the exact bytes received, then closes
      https://localhost:\(tlsPort) the HTTP fixtures over TLS (untrusted, self-issued certificate)

    """
FileHandle.standardOutput.write(Data(banner.utf8))
try await server.waitUntilClosed()
