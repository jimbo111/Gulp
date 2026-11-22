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
        // F04 TGT-020: a scope rule's host is an exact name or a regex, and rules keep a stable id.
        migrator.registerMigration("v2_scope_rule_identity") { db in
            try db.execute(sql: "ALTER TABLE scope_rules ADD COLUMN uid TEXT")
            try db.execute(sql: "ALTER TABLE scope_rules ADD COLUMN host_is_regex INTEGER NOT NULL DEFAULT 1")
        }
        // F04 TGT-007: per-node annotations and per-host notes on the site map, keyed by the node's
        // URL key (`https://host:443/a/b`; a host node's key is the host key). The tree itself is
        // rebuilt from `exchanges`, so only what the user typed is stored.
        migrator.registerMigration("v3_site_map_notes") { db in
            try db.execute(
                sql: """
                    CREATE TABLE site_map_notes (node_key TEXT PRIMARY KEY, comment TEXT, highlight TEXT,
                    notes TEXT)
                    """)
        }
        // F20 PRJ-012: imports look up duplicates by request blob; F21 AUT-023: the audit log of
        // agent (MCP/automation) actions.
        migrator.registerMigration("v4_import_index_audit_log") { db in
            try db.execute(sql: "CREATE INDEX ix_ex_request_blob ON exchanges(request_blob)")
            try db.execute(
                sql: """
                    CREATE TABLE audit_log (id INTEGER PRIMARY KEY, at REAL NOT NULL, actor TEXT NOT NULL,
                    action TEXT NOT NULL, target TEXT, outcome TEXT NOT NULL, detail TEXT)
                    """)
        }
        // F05 M9: hosts are stored lowercase so GulpQL host equality uses the binary index (DNS names
        // are case-insensitive; the raw bytes keep what was sent); Notebook notes are looked up by
        // exchange (GulpQL `notes`, F14).
        migrator.registerMigration("v5_gulpql") { db in
            try db.execute(sql: "UPDATE exchanges SET host = lower(host) WHERE host != lower(host)")
            try db.execute(sql: "CREATE INDEX ix_nb_exchange ON notebook_items(exchange_id)")
            // F14 §5: a snapshot larger than the cap is stored cut, and says so.
            try db.execute(sql: "ALTER TABLE notebook_items ADD COLUMN truncated INTEGER NOT NULL DEFAULT 0")
        }
        // F08 SCN-004: the user's severity/confidence overrides and notes survive re-findings;
        // evidence is read per issue.
        migrator.registerMigration("v6_issue_triage") { db in
            try db.execute(sql: "ALTER TABLE issues ADD COLUMN severity_user TEXT")
            try db.execute(sql: "ALTER TABLE issues ADD COLUMN confidence_user TEXT")
            try db.execute(sql: "ALTER TABLE issues ADD COLUMN notes_md TEXT")
            try db.execute(sql: "CREATE INDEX ix_evidence_issue ON issue_evidence(issue_id)")
            try db.execute(sql: "CREATE INDEX ix_issues_host ON issues(host, path)")
        }
        // F10 BCN-002: payloads remember the exchange that carried them (no foreign key: deleting an
        // exchange must not fail on, or delete, its OAST record) and their host; an interaction keeps
        // its unique id even when no payload of this project matches it.
        migrator.registerMigration("v7_oast") { db in
            try db.execute(sql: "ALTER TABLE oast_payloads ADD COLUMN exchange_id INTEGER")
            try db.execute(sql: "ALTER TABLE oast_payloads ADD COLUMN host TEXT")
            try db.execute(sql: "ALTER TABLE oast_interactions ADD COLUMN unique_id TEXT")
            try db.execute(sql: "CREATE INDEX ix_oast_payload_exchange ON oast_payloads(exchange_id)")
            try db.execute(sql: "CREATE INDEX ix_oast_interaction_payload ON oast_interactions(payload_id)")
        }
        // PRJ-003 / doc 04 §4: an exchange id is never handed out twice. The next id is derived from
        // `MAX(id)`, which forgets deleted rows, so `meta.exchange_id_high_water` keeps the highest
        // id ever deleted. A file from before v8 starts from the highest id anything still names
        // (Fuzzer results and OAST payloads have no foreign key, the passive scanner keeps a cursor).
        // No table changes, so foreign keys stay on (no whole-database check after it).
        migrator.registerMigration("v8_exchange_id_high_water", foreignKeyChecks: .immediate) { db in
            try db.execute(
                sql: """
                    INSERT OR REPLACE INTO meta (key, value) SELECT '\(exchangeIDHighWater)', COALESCE(MAX(id), 0)
                    FROM (SELECT MAX(id) AS id FROM exchanges
                    UNION ALL SELECT MAX(exchange_id) FROM issue_evidence
                    UNION ALL SELECT MAX(exchange_id) FROM notebook_items
                    UNION ALL SELECT MAX(exchange_id) FROM repeater_history
                    UNION ALL SELECT MAX(upgrade_exchange_id) FROM ws_connections
                    UNION ALL SELECT MAX(exchange_id) FROM fuzzer_results
                    UNION ALL SELECT MAX(exchange_id) FROM oast_payloads
                    UNION ALL SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'passive_scan_last_id')
                    """)
            try db.execute(
                sql: """
                    CREATE TRIGGER exchanges_id_high_water AFTER DELETE ON exchanges BEGIN
                    INSERT INTO meta (key, value) VALUES ('\(exchangeIDHighWater)', OLD.id)
                    ON CONFLICT(key) DO UPDATE SET value = MAX(CAST(value AS INTEGER), OLD.id);
                    END
                    """)
        }
        return migrator
    }

    /// The `meta` key holding a floor for the next exchange id: raised to every deleted id, and seeded
    /// at v8 from the highest id anything referenced (see `v8_exchange_id_high_water`).
    static let exchangeIDHighWater = "exchange_id_high_water"

    /// The current schema version written to `meta.schema_version`.
    static let version = 8

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
