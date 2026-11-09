// gulp-cli — Decoder, Comparer and JWT Workbench headless (F12, F13, ADV-010…013): the same GulpCodec
// and GulpDiff code the app's tools show.

import ArgumentParser
import Foundation
import GulpCodec
import GulpDiff

/// Reads the input argument: `@file`, `-` (stdin) or the text itself.
func readInput(_ value: String) throws -> [UInt8] {
    if value == "-" { return [UInt8](FileHandle.standardInput.readDataToEndOfFile()) }
    if value.hasPrefix("@") {
        guard let data = FileManager.default.contents(atPath: String(value.dropFirst())) else {
            throw ValidationError("Cannot read \(value.dropFirst())")
        }
        return [UInt8](data)
    }
    return Array(value.utf8)
}

/// `name` or `name(key=value,key=value)`.
func parseStep(_ text: String) throws -> TransformStep {
    guard let open = text.firstIndex(of: "(") else { return TransformStep(text) }
    guard text.hasSuffix(")") else { throw ValidationError("Bad step \(text)") }
    var arguments: [String: String] = [:]
    for pair in text[text.index(after: open)..<text.index(before: text.endIndex)].split(separator: ",") {
        let parts = pair.split(separator: "=", maxSplits: 1)
        arguments[String(parts[0])] = parts.count > 1 ? String(parts[1]) : "true"
    }
    return TransformStep(String(text[..<open]), arguments)
}

/// Printable form of bytes: the text when it's UTF-8, else hex.
func display(_ bytes: [UInt8]) -> String {
    if let text = String(bytes: bytes, encoding: .utf8), !bytes.contains(0) { return text }
    return "hex:" + bytes.map { String(format: "%02x", $0) }.joined()
}

/// `gulp-cli decode --chain url-decode,base64-decode,gunzip TEXT` / `--smart` (F12).
struct Decode: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Run a Decoder chain or Smart Decode on text, @file or - (stdin).")

    @Option(help: "Steps, comma-separated (args in parentheses: hmac-sha256(key=k)).")
    var chain: String?

    @Flag(help: "Run the chain backwards (each step's inverse, in reverse order).")
    var reverse = false

    @Flag(help: "Detect and decode recursively (Smart Decode) and print the chain found.")
    var smart = false

    @Flag(help: "Print every level, not just the result.")
    var levels = false

    @Option(help: "Check Smart Decode against a fixture file (JSON: [{name, input, chain, output}]).")
    var checkFixtures: String?

    @Flag(help: "List the operations.")
    var list = false

    @Argument(help: "The input: text, @file, or - for stdin.")
    var input: String?

    func run() async throws {
        if list {
            for transform in Transforms.all.values.sorted(by: { $0.name < $1.name }) {
                let inverse = transform.inverse.map { " (inverse: \($0))" } ?? ""
                print("\(transform.name)\t\(transform.kind.rawValue)\t\(transform.summary)\(inverse)")
            }
            return
        }
        if let checkFixtures { return try check(checkFixtures) }
        guard let input else { throw ValidationError("Give an input (text, @file or -).") }
        let bytes = try readInput(input)
        if smart {
            let result = SmartDecode.run(bytes)
            print(
                "chain: \(result.chain.isEmpty ? "(nothing to decode)" : result.chain.joined(separator: " → "))"
            )
            print(display(result.output))
            return
        }
        guard let chain else { throw ValidationError("Give --chain or --smart.") }
        var steps = try chain.split(separator: ",").map { try parseStep(String($0)) }
        if reverse {
            guard let inverted = Transforms.reversed(steps) else {
                throw ValidationError("A step has no inverse (hashes, pretty-printing…).")
            }
            steps = inverted
        }
        do {
            let values = try Transforms.run(bytes, steps)
            if levels {
                for (index, value) in values.enumerated() {
                    let label = index == 0 ? "input" : steps[index - 1].name
                    print("[\(index)] \(label) (\(value.count) bytes): \(display(value))")
                }
            } else {
                FileHandle.standardOutput.write(Data(values.last ?? []))
                if !(values.last ?? []).isEmpty { print() }
            }
        } catch let error as CodecError {
            throw ValidationError(error.message)
        }
    }

    func check(_ path: String) throws {
        guard let data = FileManager.default.contents(atPath: path),
            let cases = try JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else { throw ValidationError("Cannot read fixtures \(path)") }
        var failures = 0
        for item in cases {
            let name = item["name"] as? String ?? "?"
            let result = SmartDecode.run(Array((item["input"] as? String ?? "").utf8))
            let ok =
                result.chain == item["chain"] as? [String]
                && String(decoding: result.output, as: UTF8.self) == item["output"] as? String
            if !ok { failures += 1 }
            print("\(ok ? "ok  " : "FAIL") \(name): \(result.chain.joined(separator: " → "))")
        }
        print("\(cases.count - failures)/\(cases.count) solved")
        if failures > 0 { throw ExitCode(1) }
    }
}

/// `gulp-cli diff a.txt b.txt` (F13).
struct Diff: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "Diff two files (Comparer).")

    @Flag(help: "Byte granularity (default: words).")
    var byte = false

    @Flag(help: "Ignore whitespace differences.")
    var ignoreWhitespace = false

    @Flag(help: "Ignore case.")
    var ignoreCase = false

    @Flag(help: "Pretty-print JSON on both sides first.")
    var prettyJSON = false

    @Option(help: "Print at most this many changes.")
    var show = 20

    @Argument(help: "Left file.")
    var left: String

    @Argument(help: "Right file.")
    var right: String

    func run() async throws {
        guard let a = FileManager.default.contents(atPath: left),
            let b = FileManager.default.contents(atPath: right)
        else {
            throw ValidationError("Cannot read the inputs")
        }
        let options = DiffOptions(
            ignoreWhitespace: ignoreWhitespace, ignoreCase: ignoreCase, prettyJSON: prettyJSON)
        let started = ContinuousClock.now
        let result = Differ.diff([UInt8](a), [UInt8](b), granularity: byte ? .byte : .word, options: options)
        let elapsed = ContinuousClock.now - started
        let ms = Double(elapsed.components.seconds) * 1_000 + Double(elapsed.components.attoseconds) / 1e15
        let summary = result.summary
        print(
            "\(result.identical ? "identical" : "different"): \(summary.modifications) modified, \(summary.added) added, "
                + "\(summary.deleted) deleted (\(a.count) vs \(b.count) bytes, \(String(format: "%.0f", ms)) ms)"
        )
        for change in result.changes.prefix(show) {
            let removed = display(Array(result.a[change.a]))
            let added = display(Array(result.b[change.b]))
            switch change.operation {
            case .delete: print("- @\(change.a.lowerBound): \(removed.debugDescription)")
            case .insert: print("+ @\(change.b.lowerBound): \(added.debugDescription)")
            case .equal: break
            }
        }
        if !result.identical { throw ExitCode(1) }
    }
}

/// `gulp-cli jwt decode|verify|sign|forge|crack` (ADV-010…012).
struct JWTCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "jwt", abstract: "JWT Workbench: decode, verify, sign, forge and crack tokens.",
        subcommands: [DecodeToken.self, Verify.self, Sign.self, Forge.self, Crack.self])

    static func token(_ text: String) throws -> JWT {
        do {
            return try JWT(String(decoding: try readInput(text), as: UTF8.self))
        } catch let error as CodecError {
            throw ValidationError(error.message)
        }
    }

    static func key(secret: String?, keyFile: String?) throws -> JWTKey {
        if let secret { return .secret(Array(secret.utf8)) }
        guard let keyFile, let text = try? String(contentsOfFile: keyFile, encoding: .utf8) else {
            throw ValidationError("Give --secret or --key (a PEM or JWK file).")
        }
        if let pem = JWTKey.pem(text) { return pem }
        if let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] {
            return try JWTKey.jwk(object)
        }
        throw ValidationError("\(keyFile) is not a PEM or JWK key")
    }

    static func claims(_ json: String?) throws -> [String: Any?] {
        guard let json else { return [:] }
        guard let object = try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any] else {
            throw ValidationError("--claims must be a JSON object")
        }
        return object.mapValues { $0 is NSNull ? nil : $0 }
    }

    struct DecodeToken: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "decode", abstract: "Show a token's header and claims.")
        @Argument(help: "The token (text, @file or -).") var token: String
        func run() async throws {
            print(
                String(decoding: try JWT.decodeForDisplay(try JWTCommand.token(token).compact), as: UTF8.self)
            )
        }
    }

    struct Verify: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Verify a token's signature with a secret, key or JWKS.")
        @Option(help: "HMAC secret.") var secret: String?
        @Option(help: "PEM or JWK file.") var key: String?
        @Option(help: "JWKS file (the key with the token's kid, or each key).") var jwks: String?
        @Argument(help: "The token.") var token: String
        func run() async throws {
            let jwt = try JWTCommand.token(token)
            var ok: Bool
            if let jwks {
                guard let data = FileManager.default.contents(atPath: jwks) else {
                    throw ValidationError("Cannot read \(jwks)")
                }
                let kid = jwt.header["kid"] as? String
                ok = try JWTKey.jwks(data).filter { kid == nil || $0.kid == kid }.contains {
                    jwt.verifies(with: $0.key)
                }
            } else {
                ok = jwt.verifies(with: try JWTCommand.key(secret: secret, keyFile: key))
            }
            print(ok ? "valid (\(jwt.algorithm))" : "INVALID (\(jwt.algorithm))")
            if !ok { throw ExitCode(1) }
        }
    }

    struct Sign: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Set claims and (re-)sign a token.")
        @Option(help: "Algorithm (HS256…, RS256…, PS256…, ES256…).") var alg = "HS256"
        @Option(help: "HMAC secret.") var secret: String?
        @Option(help: "Private key file (PEM or JWK).") var key: String?
        @Option(help: "Claims to set, as JSON (null removes).") var claims: String?
        @Argument(help: "A token to start from (or {} for a new one).") var token: String =
            "eyJhbGciOiJub25lIn0.e30."
        func run() async throws {
            let jwt = try JWTCommand.token(token).withClaims(try JWTCommand.claims(claims))
            print(try jwt.signed(alg, key: try JWTCommand.key(secret: secret, keyFile: key)).compact)
        }
    }

    struct Forge: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Attack helpers (each line: label<TAB>token): none, confusion, kid, times.")
        @Option(help: "none | confusion | kid | times") var attack: String
        @Option(help: "The server's public key PEM (confusion).") var pubkey: String?
        @Option(help: "Claims to set first, as JSON.") var claims: String?
        @Argument(help: "The token to start from.") var token: String
        func run() async throws {
            let jwt = try JWTCommand.token(token).withClaims(try JWTCommand.claims(claims))
            let forgeries: [JWTForgery]
            switch attack {
            case "none": forgeries = try JWTAttacks.algNone(jwt)
            case "confusion":
                guard let pubkey, let pem = try? String(contentsOfFile: pubkey, encoding: .utf8) else {
                    throw ValidationError("confusion needs --pubkey (the server's public key PEM)")
                }
                forgeries = try JWTAttacks.keyConfusion(jwt, publicKeyPEM: pem)
            case "kid": forgeries = [try JWTAttacks.kidInjection(jwt)]
            case "times": forgeries = try JWTAttacks.timeClaims(jwt)
            default: throw ValidationError("Unknown attack \(attack)")
            }
            for forgery in forgeries { print("\(forgery.label)\t\(forgery.token)") }
        }
    }

    struct Crack: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Brute-force a weak HMAC secret from a wordlist.")
        @Option(help: "Wordlist file (one secret per line; # comments).") var wordlist: String
        @Argument(help: "The HS256/384/512 token.") var token: String
        func run() async throws {
            guard let text = try? String(contentsOfFile: wordlist, encoding: .utf8) else {
                throw ValidationError("Cannot read \(wordlist)")
            }
            let words = text.split(whereSeparator: \.isNewline).map(String.init).filter {
                !$0.hasPrefix("#") && !$0.isEmpty
            }
            let jwt = try JWTCommand.token(token)
            if let secret = JWTAttacks.crack(jwt, wordlist: words) {
                print("secret: \(secret)")
            } else {
                print("not found in \(words.count) candidates")
                throw ExitCode(1)
            }
        }
    }
}
