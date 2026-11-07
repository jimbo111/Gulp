// GulpStore — the project schema (doc 04 §4) as GRDB migrations. A shipped migration is never
// edited (doc 04 §4 "Notes"): schema changes add a new `vN_description` migration.

import GRDB

/// Schema migrations for a `.gulp` project file.
enum Schema {
    /// Every migration, in order.
    static func migrator() -> DatabaseMigrator {
        var migrator = DatabaseMigrator()
        migrator.registerMigration("v1_initial") { db in
            try db.execute(sql: v1)
        }
        return migrator
    }

    /// The current schema version written to `meta.schema_version`.
    static let version = 1

    /// Schema v1, generated from the SQL block in doc 04 §4 (comments stripped, lines wrapped).
    static let v1 = """
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE blobs (
        id INTEGER PRIMARY KEY,
        sha256 BLOB NOT NULL UNIQUE,
        size INTEGER NOT NULL,
        compression INTEGER NOT NULL DEFAULT 0,
        data BLOB NOT NULL
        );
        CREATE TABLE exchanges (
        id INTEGER PRIMARY KEY,
        source TEXT NOT NULL,
        created_at REAL NOT NULL,
        scheme TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
        ip TEXT, sni TEXT,
        http_version TEXT NOT NULL,
        method TEXT, path TEXT, query TEXT,
        request_blob INTEGER NOT NULL REFERENCES blobs(id),
        response_blob INTEGER REFERENCES blobs(id),
        original_request_blob INTEGER REFERENCES blobs(id),
        original_response_blob INTEGER REFERENCES blobs(id),
        status INTEGER, response_length INTEGER, mime TEXT, title TEXT,
        state TEXT NOT NULL, error TEXT,
        timing_json TEXT, tls_json TEXT,
        connection_id INTEGER, client_address TEXT,
        in_scope INTEGER NOT NULL DEFAULT 0,
        highlight TEXT, comment TEXT,
        param_count INTEGER, has_cookies INTEGER, sets_cookies INTEGER,
        extension TEXT
        );
        CREATE INDEX ix_ex_source_id ON exchanges(source, id);
        CREATE INDEX ix_ex_host ON exchanges(host, port, scheme);
        CREATE INDEX ix_ex_status ON exchanges(status);
        CREATE INDEX ix_ex_scope ON exchanges(in_scope, id);
        CREATE TABLE exchange_tags (exchange_id INTEGER REFERENCES exchanges(id) ON DELETE CASCADE,
        tag TEXT, PRIMARY KEY(exchange_id, tag));
        CREATE TABLE ws_connections (id INTEGER PRIMARY KEY,
        upgrade_exchange_id INTEGER REFERENCES exchanges(id), url TEXT, opened_at REAL, closed_at REAL,
        close_code INTEGER);
        CREATE TABLE ws_messages (
        id INTEGER PRIMARY KEY, connection_id INTEGER REFERENCES ws_connections(id) ON DELETE CASCADE,
        direction INTEGER NOT NULL,
        opcode INTEGER NOT NULL, created_at REAL NOT NULL,
        payload_blob INTEGER REFERENCES blobs(id), original_payload_blob INTEGER REFERENCES blobs(id),
        length INTEGER, highlight TEXT, comment TEXT,
        frames_json TEXT
        );
        CREATE VIRTUAL TABLE fts_exchanges USING fts5(request_text, response_text, content='',
        contentless_delete=1, tokenize='trigram');
        CREATE TABLE scope_rules (id INTEGER PRIMARY KEY,
        kind TEXT CHECK(kind IN ('include','exclude')), enabled INTEGER, protocol TEXT,
        host_regex TEXT, port TEXT, path_regex TEXT, ordinal INTEGER);
        CREATE TABLE issues (
        id INTEGER PRIMARY KEY, type_id TEXT NOT NULL, name TEXT NOT NULL,
        severity TEXT NOT NULL, confidence TEXT NOT NULL,
        host TEXT NOT NULL, path TEXT NOT NULL, insertion_point TEXT,
        dedup_key TEXT NOT NULL UNIQUE,
        detail_md TEXT, background_md TEXT, remediation_md TEXT, references_md TEXT,
        status TEXT NOT NULL DEFAULT 'open',
        source_task_id INTEGER, created_at REAL, updated_at REAL
        );
        CREATE TABLE issue_evidence (id INTEGER PRIMARY KEY,
        issue_id INTEGER REFERENCES issues(id) ON DELETE CASCADE,
        exchange_id INTEGER REFERENCES exchanges(id), request_markers_json TEXT,
        response_markers_json TEXT, oast_interaction_id INTEGER, note TEXT);
        CREATE TABLE tasks (id INTEGER PRIMARY KEY, kind TEXT, name TEXT, config_json TEXT, state TEXT,
        progress_json TEXT, created_at REAL, finished_at REAL);
        CREATE TABLE task_log (id INTEGER PRIMARY KEY,
        task_id INTEGER REFERENCES tasks(id) ON DELETE CASCADE, at REAL, level TEXT, message TEXT);
        CREATE TABLE repeater_tabs (id INTEGER PRIMARY KEY, title TEXT, group_id INTEGER,
        ordinal INTEGER, target_json TEXT, options_json TEXT, draft_blob INTEGER REFERENCES blobs(id));
        CREATE TABLE repeater_groups (id INTEGER PRIMARY KEY, name TEXT, color TEXT, send_mode TEXT);
        CREATE TABLE repeater_history (id INTEGER PRIMARY KEY,
        tab_id INTEGER REFERENCES repeater_tabs(id) ON DELETE CASCADE,
        exchange_id INTEGER REFERENCES exchanges(id), ordinal INTEGER);
        CREATE TABLE fuzzer_attacks (id INTEGER PRIMARY KEY, name TEXT, config_json TEXT,
        base_request_blob INTEGER, state TEXT, created_at REAL);
        CREATE TABLE fuzzer_results (attack_id INTEGER REFERENCES fuzzer_attacks(id) ON DELETE CASCADE,
        seq INTEGER, payloads_json TEXT, exchange_id INTEGER, status INTEGER, length INTEGER,
        time_ms INTEGER, grep_json TEXT, PRIMARY KEY(attack_id, seq));
        CREATE TABLE oast_payloads (id INTEGER PRIMARY KEY, correlation_id TEXT UNIQUE,
        created_at REAL, context_json TEXT);
        CREATE TABLE oast_interactions (id INTEGER PRIMARY KEY,
        payload_id INTEGER REFERENCES oast_payloads(id), protocol TEXT, remote_address TEXT, at REAL,
        raw_blob INTEGER, summary TEXT);
        CREATE TABLE notebook_items (
        id INTEGER PRIMARY KEY, kind TEXT,
        exchange_id INTEGER REFERENCES exchanges(id) ON DELETE SET NULL,
        request_blob INTEGER REFERENCES blobs(id),
        response_blob INTEGER REFERENCES blobs(id),
        target_json TEXT,
        title TEXT, status TEXT, body_md TEXT, tags TEXT, highlight TEXT,
        issue_id INTEGER REFERENCES issues(id) ON DELETE SET NULL,
        created_at REAL, updated_at REAL, ordinal INTEGER
        );
        CREATE TABLE cookie_jar (domain TEXT, path TEXT, name TEXT, value TEXT, expires REAL,
        secure INTEGER, http_only INTEGER, same_site TEXT, identity_id INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(domain, path, name, identity_id));
        CREATE TABLE identities (id INTEGER PRIMARY KEY, name TEXT, color TEXT, config_json TEXT);
        CREATE TABLE macros (id INTEGER PRIMARY KEY, name TEXT, steps_json TEXT);
        CREATE TABLE session_rules (id INTEGER PRIMARY KEY, name TEXT, enabled INTEGER,
        ordinal INTEGER, config_json TEXT);
        CREATE TABLE sequencer_runs (id INTEGER PRIMARY KEY, name TEXT, config_json TEXT,
        tokens_blob INTEGER, results_json TEXT, created_at REAL);
        CREATE TABLE settings (scope TEXT, key TEXT, value_json TEXT, PRIMARY KEY(scope, key));
        CREATE TABLE extension_state (extension_id TEXT, key TEXT, value BLOB,
        PRIMARY KEY(extension_id, key));
        """
}
