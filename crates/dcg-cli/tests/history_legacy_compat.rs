//! Upgrade coverage for history databases created by the legacy fsqlite backend.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use dcg_cli::history::{CommandEntry, HistoryDb, SqliteValue};
use flate2::read::GzDecoder;
use std::io::Read;
use tempfile::TempDir;

// Gzip-compressed `history.db` produced by released dcg 0.6.7 after one hook
// decision, then checkpointed with stock SQLite. Before dcg repairs the derived
// FTS index, stock SQLite reports:
// `wrong # of entries in index sqlite_autoindex_commands_fts_config_1`.
//
// Uncompressed SHA-256:
// 6c7cbafe529be371ff72116398b417423744e28c6c0610d0c2ae1bf713c15c2a
const LEGACY_FSQLITE_HISTORY_GZIP_BASE64: &str = concat!(
    "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"
);

fn assert_database_corrupt(error: rusqlite::Error) {
    match error {
        rusqlite::Error::SqliteFailure(code, _) => {
            assert_eq!(code.code, rusqlite::ErrorCode::DatabaseCorrupt);
        }
        other => panic!("expected the legacy SQLite corruption signature, got {other:?}"),
    }
}

fn scalar_i64(db: &HistoryDb, sql: &str) -> i64 {
    let row = db.connection().query_row(sql).expect("scalar query");
    match row.values().first() {
        Some(SqliteValue::Integer(value)) => *value,
        other => panic!("expected integer scalar, got {other:?}"),
    }
}

fn fts_matches(db: &HistoryDb, token: &str) -> usize {
    db.connection()
        .query_with_params(
            "SELECT rowid FROM commands_fts WHERE commands_fts MATCH ?1",
            &[SqliteValue::Text(token.to_string())],
        )
        .expect("FTS query")
        .len()
}

fn assert_integrity_ok(db: &HistoryDb) {
    let rows = db
        .connection()
        .query("PRAGMA integrity_check")
        .expect("integrity check");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].values(), &[SqliteValue::Text("ok".to_string())]);
}

#[test]
fn opens_repairs_and_keeps_legacy_fsqlite_history_in_sync() {
    let compressed = STANDARD
        .decode(LEGACY_FSQLITE_HISTORY_GZIP_BASE64)
        .expect("decode fixture");
    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut fixture = Vec::new();
    decoder
        .read_to_end(&mut fixture)
        .expect("decompress fixture");
    assert_eq!(fixture.len(), 147_456, "unexpected fixture provenance");

    let temp_dir = TempDir::new().expect("temporary fixture directory");
    let db_path = temp_dir.path().join("legacy-history.db");
    std::fs::write(&db_path, fixture).expect("write legacy fixture");

    let stock = rusqlite::Connection::open(&db_path).expect("open legacy fixture");
    let commands_before: i64 = stock
        .query_row("SELECT COUNT(*) FROM commands", [], |row| row.get(0))
        .expect("legacy command count");
    assert_eq!(commands_before, 1);
    let integrity_failure: String = stock
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .expect("read the first legacy integrity failure");
    assert!(
        integrity_failure.contains("sqlite_autoindex_commands_fts_config_1"),
        "legacy fixture must reproduce the stock-SQLite defect: {integrity_failure}"
    );
    let probe_error = stock
        .query_row(
            "SELECT v FROM commands_fts_config WHERE k = 'version'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect_err("indexed legacy FTS probe must fail before migration");
    assert_database_corrupt(probe_error);
    let unindexed_version: i64 = stock
        .query_row(
            "SELECT v FROM commands_fts_config NOT INDEXED WHERE k = 'version'",
            [],
            |row| row.get(0),
        )
        .expect("legacy FTS config content remains readable without its corrupt index");
    assert_eq!(unindexed_version, 4);
    drop(stock);

    let db = HistoryDb::open(Some(db_path.clone())).expect("repair legacy history on open");
    assert_integrity_ok(&db);
    assert_eq!(db.count_commands().expect("command count"), 1);
    assert_eq!(scalar_i64(&db, "SELECT COUNT(*) FROM commands_fts"), 1);
    assert_eq!(fts_matches(&db, "git"), 1);

    db.connection()
        .execute("UPDATE commands SET command = 'legacyupdatedtoken'")
        .expect("update command");
    assert_eq!(fts_matches(&db, "git"), 0);
    assert_eq!(fts_matches(&db, "legacyupdatedtoken"), 1);

    db.connection()
        .execute("DELETE FROM commands")
        .expect("delete command");
    assert_eq!(fts_matches(&db, "legacyupdatedtoken"), 0);
    assert_eq!(scalar_i64(&db, "SELECT COUNT(*) FROM commands_fts"), 0);

    db.log_command(&CommandEntry {
        command: "freshinsertprobe".to_string(),
        ..Default::default()
    })
    .expect("insert after repair");
    assert_eq!(fts_matches(&db, "freshinsertprobe"), 1);
    drop(db);

    let reopened = HistoryDb::open(Some(db_path)).expect("idempotent second open");
    assert_integrity_ok(&reopened);
    assert_eq!(reopened.count_commands().expect("reopened count"), 1);
    assert_eq!(fts_matches(&reopened, "freshinsertprobe"), 1);
}
