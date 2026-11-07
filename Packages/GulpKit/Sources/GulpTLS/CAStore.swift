// GulpTLS — where the CA lives (F02 TLS-002). The certificate is public and is a plain file; the
// private key goes to the macOS Keychain (app) or to a mode-0600 file (Linux, CLI, tests).

import Foundation

#if canImport(Security)
import Security
#endif

/// Persistent storage for the CA.
public protocol CAStore: Sendable {
    /// The stored CA, or nil if none was saved yet.
    func load() throws -> CertificateAuthority?
    /// Save (replace) the CA.
    func save(_ authority: CertificateAuthority) throws
    /// Remove the stored CA.
    func delete() throws
}

extension CertificateAuthority {
    /// Load the CA from `store`, or generate and save a new one (first run, TLS-001).
    public static func loadOrCreate(
        from store: any CAStore, keyType: CAKeyType = .rsa2048
    ) throws -> CertificateAuthority {
        if let existing = try store.load() { return existing }
        let authority = try generate(keyType: keyType)
        try store.save(authority)
        return authority
    }
}

/// CA certificate and key as files in one directory: `ca.pem` and `ca.key` (mode 0600).
public struct FileCAStore: CAStore {
    /// The directory holding the files.
    public let directory: URL

    /// A store in `directory` (created on save with mode 0700).
    public init(directory: URL) {
        self.directory = directory
    }

    /// `~/.config/gulp/ca` (TLS-002, Linux/CLI).
    public static var standard: FileCAStore {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return FileCAStore(directory: home.appendingPathComponent(".config/gulp/ca", isDirectory: true))
    }

    var certificateURL: URL { directory.appendingPathComponent("ca.pem") }
    var keyURL: URL { directory.appendingPathComponent("ca.key") }

    /// Load `ca.pem` + `ca.key`.
    public func load() throws -> CertificateAuthority? {
        guard let certificate = try? String(contentsOf: certificateURL, encoding: .utf8),
            let key = try? String(contentsOf: keyURL, encoding: .utf8)
        else { return nil }
        return try CertificateAuthority(certificatePEM: certificate, privateKeyPEM: key)
    }

    /// Write both files; the key file is created with mode 0600.
    public func save(_ authority: CertificateAuthority) throws {
        try FileSecrets.createPrivateDirectory(directory)
        try FileSecrets.write(Data(authority.certificatePEM().utf8), to: certificateURL, mode: 0o644)
        try FileSecrets.write(Data(authority.key.pem.utf8), to: keyURL, mode: 0o600)
    }

    /// Delete both files.
    public func delete() throws {
        for url in [certificateURL, keyURL] where FileManager.default.fileExists(atPath: url.path) {
            try FileManager.default.removeItem(at: url)
        }
    }
}

enum FileSecrets {
    static func createPrivateDirectory(_ url: URL) throws {
        do {
            try FileManager.default.createDirectory(
                at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        } catch {
            throw TLSError.storage("cannot create \(url.path): \(error)")
        }
    }

    /// Replace the file at `url` with `data`, created with `mode` (never briefly world-readable).
    static func write(_ data: Data, to url: URL, mode: Int) throws {
        let manager = FileManager.default
        if manager.fileExists(atPath: url.path) { try? manager.removeItem(at: url) }
        guard manager.createFile(atPath: url.path, contents: data, attributes: [.posixPermissions: mode])
        else { throw TLSError.storage("cannot write \(url.path)") }
    }
}

#if canImport(Security)
/// macOS app storage (TLS-002): the certificate as a file, the private key as a Keychain generic
/// password item (this device only).
public struct KeychainCAStore: CAStore {
    /// Directory for the (public) certificate file.
    public let directory: URL
    /// Keychain service name.
    public let service: String
    static let account = "ca-private-key"

    /// A store with the certificate in `directory` and the key under `service`.
    public init(directory: URL, service: String = "com.gulp.app.ca") {
        self.directory = directory
        self.service = service
    }

    var certificateURL: URL { directory.appendingPathComponent("ca.pem") }

    /// Load the certificate file and the Keychain key.
    public func load() throws -> CertificateAuthority? {
        guard let certificate = try? String(contentsOf: certificateURL, encoding: .utf8) else { return nil }
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data,
            let pem = String(data: data, encoding: .utf8)
        else { throw TLSError.storage("Keychain read failed (\(status))") }
        return try CertificateAuthority(certificatePEM: certificate, privateKeyPEM: pem)
    }

    /// Save the certificate file and replace the Keychain key.
    public func save(_ authority: CertificateAuthority) throws {
        try FileSecrets.createPrivateDirectory(directory)
        try FileSecrets.write(Data(authority.certificatePEM().utf8), to: certificateURL, mode: 0o644)
        SecItemDelete(baseQuery as CFDictionary)
        var item = baseQuery
        item[kSecValueData as String] = Data(authority.key.pem.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        item[kSecAttrLabel as String] = "Gulp CA private key"
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw TLSError.storage("Keychain write failed (\(status))") }
    }

    /// Delete the certificate file and the Keychain key.
    public func delete() throws {
        SecItemDelete(baseQuery as CFDictionary)
        if FileManager.default.fileExists(atPath: certificateURL.path) {
            try FileManager.default.removeItem(at: certificateURL)
        }
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: Self.account,
        ]
    }
}
#endif
