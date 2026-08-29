use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use edsa_core::{RunConfiguration, RunEvent, RunStatus};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

use crate::{ArtifactError, ArtifactStore};

#[derive(Debug)]
pub struct RunStore {
    root: PathBuf,
    connection: Connection,
    event_stream: File,
    next_sequence: u64,
}

impl RunStore {
    /// Creates a new evidence directory. Existing paths are never reused or overwritten.
    ///
    /// # Errors
    /// Returns an error if the output exists or durable storage cannot be initialized.
    pub fn create(
        output: impl AsRef<Path>,
        configuration: &RunConfiguration,
    ) -> Result<Self, RunStoreError> {
        let output = output.as_ref();
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        match fs::create_dir(output) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(RunStoreError::OutputCollision(output.to_path_buf()));
            }
            Err(error) => return Err(error.into()),
        }

        let result = Self::initialize(output, configuration);
        if result.is_err() {
            let _ = fs::remove_dir_all(output);
        }
        result
    }

    fn initialize(output: &Path, configuration: &RunConfiguration) -> Result<Self, RunStoreError> {
        let root = dunce::canonicalize(output)?;
        let configuration_json = serde_json::to_vec_pretty(configuration)?;
        let mut configuration_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join("run.json"))?;
        configuration_file.write_all(&configuration_json)?;
        configuration_file.write_all(b"\n")?;
        configuration_file.sync_all()?;

        let event_stream = OpenOptions::new()
            .append(true)
            .create_new(true)
            .open(root.join("events.jsonl"))?;
        ArtifactStore::open(root.join("artifacts"))?;

        let connection = Connection::open(root.join("ledger.sqlite3"))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE run_configuration (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 configuration_json TEXT NOT NULL
             );
             CREATE TABLE run_events (
                 sequence INTEGER PRIMARY KEY,
                 status TEXT NOT NULL,
                 event_json TEXT NOT NULL
             );
             CREATE TRIGGER run_configuration_no_update
             BEFORE UPDATE ON run_configuration BEGIN SELECT RAISE(ABORT, 'run configuration is immutable'); END;
             CREATE TRIGGER run_configuration_no_delete
             BEFORE DELETE ON run_configuration BEGIN SELECT RAISE(ABORT, 'run configuration is immutable'); END;
             CREATE TRIGGER run_events_no_update
             BEFORE UPDATE ON run_events BEGIN SELECT RAISE(ABORT, 'run events are append-only'); END;
             CREATE TRIGGER run_events_no_delete
             BEFORE DELETE ON run_events BEGIN SELECT RAISE(ABORT, 'run events are append-only'); END;
             PRAGMA user_version = 1;
             COMMIT;",
        )?;
        connection.execute(
            "INSERT INTO run_configuration(singleton, configuration_json) VALUES (1, ?1)",
            params![String::from_utf8(configuration_json)?],
        )?;

        let mut store = Self {
            root,
            connection,
            event_stream,
            next_sequence: 1,
        };
        store.append_event(RunStatus::Created, "run configuration recorded")?;
        Ok(store)
    }

    /// Appends one status event to SQLite and the portable JSONL stream.
    ///
    /// # Errors
    /// Returns an error if serialization or durable storage fails.
    pub fn append_event(
        &mut self,
        status: RunStatus,
        message: impl Into<String>,
    ) -> Result<RunEvent, RunStoreError> {
        if self.current_status()?.is_some_and(RunStatus::is_terminal) {
            return Err(RunStoreError::AlreadyTerminal);
        }
        self.append_record(status, message, serde_json::Value::Null)
    }

    /// Appends a structured run record to the same SQLite ledger and JSONL stream.
    ///
    /// # Errors
    /// Returns an error if the run is terminal or durable storage fails.
    pub fn append_record(
        &mut self,
        status: RunStatus,
        message: impl Into<String>,
        payload: serde_json::Value,
    ) -> Result<RunEvent, RunStoreError> {
        if self.current_status()?.is_some_and(RunStatus::is_terminal) {
            return Err(RunStoreError::AlreadyTerminal);
        }
        let event = RunEvent::new(self.next_sequence, status, message).with_payload(payload);
        let json = serde_json::to_string(&event)?;
        let sequence =
            i64::try_from(event.sequence).map_err(|_| RunStoreError::SequenceOverflow)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO run_events(sequence, status, event_json) VALUES (?1, ?2, ?3)",
            params![sequence, status_name(status), json],
        )?;
        writeln!(self.event_stream, "{json}")?;
        self.event_stream.sync_data()?;
        transaction.commit()?;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(RunStoreError::SequenceOverflow)?;
        Ok(event)
    }

    /// Returns the latest persisted status.
    ///
    /// # Errors
    /// Returns an error for a malformed or inaccessible ledger.
    pub fn current_status(&self) -> Result<Option<RunStatus>, RunStoreError> {
        let json = self
            .connection
            .query_row(
                "SELECT event_json FROM run_events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        json.map(|value| serde_json::from_str::<RunEvent>(&value).map(|event| event.status))
            .transpose()
            .map_err(Into::into)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn status_name(status: RunStatus) -> &'static str {
    match status {
        RunStatus::Created => "created",
        RunStatus::Ready => "ready",
        RunStatus::Running => "running",
        RunStatus::Completed => "completed",
        RunStatus::Inconclusive => "inconclusive",
        RunStatus::Cancelled => "cancelled",
        RunStatus::TimedOut => "timed_out",
        RunStatus::Failed => "failed",
    }
}

#[derive(Debug, Error)]
pub enum RunStoreError {
    #[error("output directory already exists: {0}")]
    OutputCollision(PathBuf),
    #[error("run already has a terminal status")]
    AlreadyTerminal,
    #[error("run event sequence overflowed")]
    SequenceOverflow,
    #[error("run configuration was not valid UTF-8: {0}")]
    ConfigurationUtf8(#[from] std::string::FromUtf8Error),
    #[error("run store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("run store SQLite failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("run store JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("artifact store failed: {0}")]
    Artifact(#[from] ArtifactError),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use edsa_core::{
        DirtyTreeDecision, ProviderMetadata, RepositorySnapshot, RunApprovals, RunBudget,
        RunConfiguration, RunStatus,
    };
    use tempfile::tempdir;

    use super::{RunStore, RunStoreError};

    fn configuration() -> RunConfiguration {
        RunConfiguration::new(
            RepositorySnapshot::new(".", "abc", "def", false),
            ProviderMetadata {
                provider: "openai-compatible".into(),
                model: "test-model".into(),
            },
            RunBudget {
                maximum_model_tokens: 1,
                maximum_cost_microusd: 1,
                maximum_turns: 1,
                maximum_experiments: 1,
                maximum_wall_time_seconds: 1,
            },
            RunApprovals::default(),
            DirtyTreeDecision::Clean,
            BTreeSet::new(),
            Vec::new(),
        )
    }

    #[test]
    fn creates_complete_store_and_refuses_collision() {
        let temporary = tempdir().expect("temporary directory");
        let output = temporary.path().join("run");
        let mut store = RunStore::create(&output, &configuration()).expect("create run store");
        store
            .append_event(RunStatus::Ready, "provider admitted")
            .expect("append ready event");
        assert!(output.join("run.json").is_file());
        assert!(output.join("ledger.sqlite3").is_file());
        assert!(output.join("events.jsonl").is_file());
        assert!(output.join("artifacts/sha256").is_dir());
        assert_eq!(
            store.current_status().expect("status"),
            Some(RunStatus::Ready)
        );
        assert!(matches!(
            RunStore::create(&output, &configuration()),
            Err(RunStoreError::OutputCollision(_))
        ));
    }

    #[test]
    fn terminal_status_rejects_later_events() {
        let temporary = tempdir().expect("temporary directory");
        let output = temporary.path().join("run");
        let mut store = RunStore::create(output, &configuration()).expect("create run store");
        store
            .append_event(RunStatus::Cancelled, "cancelled")
            .expect("append cancellation");
        assert!(matches!(
            store.append_event(RunStatus::Ready, "invalid"),
            Err(RunStoreError::AlreadyTerminal)
        ));
    }

    #[test]
    fn timeout_is_persisted_as_a_terminal_event() {
        let temporary = tempdir().expect("temporary directory");
        let output = temporary.path().join("run");
        let mut store = RunStore::create(output, &configuration()).expect("create run store");
        store
            .append_event(RunStatus::TimedOut, "wall-time budget exhausted")
            .expect("append timeout");
        assert_eq!(
            store.current_status().expect("status"),
            Some(RunStatus::TimedOut)
        );
        assert!(matches!(
            store.append_event(RunStatus::Ready, "invalid"),
            Err(RunStoreError::AlreadyTerminal)
        ));
    }
}
