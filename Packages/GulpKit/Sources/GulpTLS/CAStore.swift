// GulpTLS — where the CA lives (F02 TLS-002). The certificate is public and is a plain file; the
// private key goes to the macOS Keychain (app) or to a mode-0600 file (Linux, CLI, tests).

import Foundation

#if canImport(Security)
import Security
#endif

/// Persistent storage for the CA.
public protocol CAStore: Sendable {
    /// The stored CA, or nil only when nothing was saved yet. A CA that exists but can't be read
    /// (or is half there) throws: `loadOrCreate` must never replace a root the user trusts.
    func load() throws -> CertificateAuthority?
    /// Save (replace) the CA.
    func save(_ authority: CertificateAuthority) throws
    /// Remove the stored CA.
    func delete() throws
}

extension CertificateAuthority {
    /// Load the CA from `store`, or generate and save a new one (first run, TLS-001). A stored CA
    /// that fails to load is an error, never a reason to make a new one.
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

    /// Load `ca.pem` + `ca.key`; nil when neither exists.
    public func load() throws -> CertificateAuthority? {
        let manager = FileManager.default
        let present = [certificateURL, keyURL].filter { manager.fileExists(atPath: $0.path) }
        if present.isEmpty { return nil }
        guard present.count == 2 else {
            throw TLSError.storage("\(directory.path) holds only \(present[0].lastPathComponent)")
        }
        return try CertificateAuthority(
            certificatePEM: FileSecrets.read(certificateURL), privateKeyPEM: FileSecrets.read(keyURL))
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

    static func read(_ url: URL) throws -> String {
        do {
            return try String(contentsOf: url, encoding: .utf8)
        } catch {
            throw TLSError.storage("cannot read \(url.path): \(error)")
        }
    }

    /// Replace the file at `url` with `data`. The bytes go to a new file created with `mode`
    /// (`O_EXCL`, so it is never briefly readable by others), which is then renamed over `url`:
    /// the old file stays whole until the new one is.
    static func write(_ data: Data, to url: URL, mode: Int) throws {
        let temporary = url.path + ".\(UUID().uuidString).tmp"
        let fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL, mode_t(mode))
        guard fd >= 0 else { throw TLSError.storage("cannot create \(temporary) (errno \(errno))") }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            try handle.write(contentsOf: data)
            try handle.close()
        } catch {
            unlink(temporary)
            throw TLSError.storage("cannot write \(temporary): \(error)")
        }
        guard rename(temporary, url.path) == 0 else {
            unlink(temporary)
            throw TLSError.storage("cannot write \(url.path) (errno \(errno))")
        }
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

    /// Load the certificate file and the Keychain key; nil when neither exists.
    public func load() throws -> CertificateAuthority? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        let hasCertificate = FileManager.default.fileExists(atPath: certificateURL.path)
        if status == errSecItemNotFound {
            guard hasCertificate else { return nil }
            throw TLSError.storage("\(certificateURL.path) exists but its Keychain key is missing")
        }
        guard status == errSecSuccess, let data = result as? Data,
            let pem = String(data: data, encoding: .utf8)
        else { throw TLSError.storage("Keychain read failed (\(status))") }
        guard hasCertificate else {
            throw TLSError.storage("the Keychain holds a CA key but \(certificateURL.path) is missing")
        }
        return try CertificateAuthority(certificatePEM: FileSecrets.read(certificateURL), privateKeyPEM: pem)
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
