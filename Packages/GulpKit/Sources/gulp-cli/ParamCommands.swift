// gulp-cli — Parameter Discovery headless (F23 ADV-020). Brute-force hidden query parameters a request
// doesn't advertise and report which the server processes (reflected or behaviour-changing).

import ArgumentParser
import Foundation
import GulpCore
import GulpHTTP
import GulpScanner

/// `gulp-cli discover-params --raw req.txt --target http://host [--wordlist names.txt]`
struct DiscoverParams: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "discover-params",
        abstract: "Brute-force hidden query parameters and report the ones the server processes.")

    @Option(help: "A raw request file whose query is probed.") var raw: String
    @Option(help: "Where the request goes, e.g. http://127.0.0.1:8088.") var target: String
    @Option(help: "A wordlist of candidate names (one per line); a small built-in list otherwise.")
    var wordlist: String?
    @Option(help: "Candidate names per request.") var batchSize = 24

    /// A tiny built-in candidate list for when no wordlist is given.
    static let builtin = [
        "debug", "trace", "test", "admin", "verbose", "source", "callback", "redirect", "url", "next",
        "id", "user", "role", "format", "json", "xml", "page", "limit", "offset", "sort", "filter",
        "q", "search", "lang", "preview", "draft", "token", "key", "api_key", "access",
    ]

    func run() async throws {
        guard let data = FileManager.default.contents(atPath: raw) else {
            throw ValidationError("Cannot read \(raw)")
        }
        guard let destination = HTTPTarget(url: target) else {
            throw ValidationError("Invalid --target \(target)")
        }
        let names: [String]
        if let wordlist {
            guard let listData = FileManager.default.contents(atPath: wordlist) else {
                throw ValidationError("Cannot read \(wordlist)")
            }
            names = String(decoding: listData, as: UTF8.self).split(whereSeparator: \.isNewline)
                .map(String.init).filter { !$0.isEmpty }
        } else {
            names = Self.builtin
        }
        let base = RawRequest(Bytes([UInt8](data)))
        let engine = NIOHTTPEngine()
        defer { Task { await engine.shutdown() } }
        let options = SendOptions(recordAs: .automation)
        let found = await ParamMiner.discover(base: base, names: names, batchSize: batchSize) { request in
            let result = await engine.send(request, to: destination, options: options)
            return result.exchange.response ?? RawResponse(Bytes("HTTP/1.1 0 \r\n\r\n"))
        }
        print("discover-params: \(found.count) processed of \(names.count) candidates")
        for param in found.sorted(by: { $0.name < $1.name }) {
            print("  \(param.name)\t\(param.evidence)")
        }
    }
}
