// GulpStore — one writer per project file (F20 §5). Two processes (or two windows) appending to the
// same project would hand out the same exchange ids from separate in-memory counters, and every
// batch after the first collision would fail. An advisory `flock` on a side file prevents that.
//
// Concept: `flock` locks belong to the open file description and the kernel drops them when the
// process exits or crashes, so a stale lock can never outlive its owner (unlike a "lock file exists"
// check).

import Foundation

#if canImport(Glibc)
import Glibc
#endif

/// An exclusive advisory lock on `<project>.gulplock`, held while the project is open.
final class ProjectLock: Sendable {
    /// The lock file next to a project file.
    static func path(for url: URL) -> String { url.path + ".gulplock" }

    private let descriptor: Int32

    /// Take the lock, or throw `StoreError.alreadyOpen` if another session holds it.
    init(for url: URL) throws {
        let fd = open(Self.path(for: url), O_CREAT | O_RDWR, 0o644)
        guard fd >= 0 else { throw StoreError.alreadyOpen("cannot create the lock file (errno \(errno))") }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
            close(fd)
            throw StoreError.alreadyOpen(url.lastPathComponent)
        }
        descriptor = fd
    }

    /// Release the lock (also happens automatically if the process ends).
    func release() {
        flock(descriptor, LOCK_UN)
        close(descriptor)
    }
}
