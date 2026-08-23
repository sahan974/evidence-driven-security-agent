use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

use edsa_core::{
    ConfirmationPolicy, EvidenceAssessment, ExperimentId, Hypothesis, HypothesisState,
    PatchAttemptId, PatchVerification, SCHEMA_VERSION, TransitionError, Verdict,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum EventKind {
    HypothesisProposed(Hypothesis),
    InvestigationStarted,
    ExperimentRecorded {
        id: ExperimentId,
    },
    EvidenceReady,
    VerdictAssigned {
        policy: ConfirmationPolicy,
        assessment: EvidenceAssessment,
        verdict: Verdict,
    },
    PatchProposed {
        id: PatchAttemptId,
    },
    PatchVerified {
        id: PatchAttemptId,
        verification: PatchVerification,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvestigationEvent {
    pub schema_version: u16,
    pub sequence: u64,
    pub event_id: String,
    pub hypothesis_id: String,
    pub previous_hash: String,
    pub event_hash: String,
    pub kind: EventKind,
}

#[derive(Debug)]
pub struct Ledger {
    connection: Connection,
}

impl Ledger {
    /// Opens a ledger and applies forward-only schema migrations.
    ///
    /// # Errors
    /// Returns an error if SQLite cannot open or migrate the database.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let connection = Connection::open(path)?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS schema_migrations (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
             );
             CREATE TABLE IF NOT EXISTS events (
                 sequence INTEGER PRIMARY KEY,
                 event_id TEXT NOT NULL UNIQUE,
                 hypothesis_id TEXT NOT NULL,
                 previous_hash TEXT NOT NULL,
                 event_hash TEXT NOT NULL UNIQUE,
                 event_json TEXT NOT NULL
             );
             INSERT OR IGNORE INTO schema_migrations(version) VALUES (1);
             PRAGMA user_version = 1;
             COMMIT;",
        )?;
        Ok(Self { connection })
    }

    /// Atomically appends one or more events after validating hashes and state transitions.
    ///
    /// # Errors
    /// Returns an error for an empty batch, duplicates, invalid ordering/hashes, or illegal state.
    pub fn append(&mut self, events: &[InvestigationEvent]) -> Result<(), LedgerError> {
        if events.is_empty() {
            return Err(LedgerError::EmptyBatch);
        }
        let existing = Self::load_from_connection(&self.connection)?;
        let mut combined = existing;
        combined.extend_from_slice(events);
        validate_chain(&combined)?;
        replay(&combined)?;

        let transaction = self.connection.transaction()?;
        for event in events {
            let json = serde_json::to_string(event)?;
            let sequence =
                i64::try_from(event.sequence).map_err(|_| LedgerError::SequenceOverflow)?;
            transaction
                .execute(
                    "INSERT INTO events(sequence, event_id, hypothesis_id, previous_hash, event_hash, event_json)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        sequence,
                        event.event_id,
                        event.hypothesis_id,
                        event.previous_hash,
                        event.event_hash,
                        json
                    ],
                )
                .map_err(map_sqlite_error)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Creates the next correctly chained event without persisting it.
    ///
    /// # Errors
    /// Returns an error if current ledger records cannot be loaded.
    pub fn next_event(
        &self,
        event_id: impl Into<String>,
        hypothesis_id: impl Into<String>,
        kind: EventKind,
    ) -> Result<InvestigationEvent, LedgerError> {
        let last = self
            .connection
            .query_row(
                "SELECT sequence, event_hash FROM events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let (sequence, previous_hash) = match last {
            Some((sequence, hash)) => (
                u64::try_from(sequence)
                    .map_err(|_| LedgerError::SequenceOverflow)?
                    .checked_add(1)
                    .ok_or(LedgerError::SequenceOverflow)?,
                hash,
            ),
            None => (1, GENESIS_HASH.to_owned()),
        };
        InvestigationEvent::new(sequence, event_id, hypothesis_id, previous_hash, kind)
    }

    /// Loads all events in sequence order and verifies the complete hash chain.
    ///
    /// # Errors
    /// Returns an error for database, JSON, ordering, or integrity failures.
    pub fn events(&self) -> Result<Vec<InvestigationEvent>, LedgerError> {
        let events = Self::load_from_connection(&self.connection)?;
        validate_chain(&events)?;
        Ok(events)
    }

    /// Reconstructs current hypothesis state solely from persisted events.
    ///
    /// # Errors
    /// Returns an error if storage is corrupt or any transition is illegal.
    pub fn reconstruct(&self) -> Result<HypothesisState, LedgerError> {
        replay(&self.events()?)
    }

    /// Exports verified events as portable, one-record-per-line JSON.
    ///
    /// # Errors
    /// Returns an error for ledger integrity, serialization, or writer failures.
    pub fn export_jsonl(&self, mut writer: impl Write) -> Result<(), LedgerError> {
        for event in self.events()? {
            serde_json::to_writer(&mut writer, &event)?;
            writer.write_all(b"\n")?;
        }
        Ok(())
    }

    /// Imports a complete JSONL stream transactionally.
    ///
    /// # Errors
    /// Returns an error for malformed input, blank records, duplicates, hash drift, or illegal state.
    pub fn import_jsonl(&mut self, reader: impl Read) -> Result<(), LedgerError> {
        let mut events = Vec::new();
        for (index, line) in BufReader::new(reader).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                return Err(LedgerError::BlankJsonLine(index + 1));
            }
            events.push(serde_json::from_str(&line)?);
        }
        self.append(&events)
    }

    fn load_from_connection(
        connection: &Connection,
    ) -> Result<Vec<InvestigationEvent>, LedgerError> {
        let mut statement = connection.prepare(
            "SELECT sequence, event_id, hypothesis_id, previous_hash, event_hash, event_json
             FROM events ORDER BY sequence",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        let mut events = Vec::new();
        for row in rows {
            let (sequence, event_id, hypothesis_id, previous_hash, event_hash, json) = row?;
            let event: InvestigationEvent = serde_json::from_str(&json)?;
            if u64::try_from(sequence).ok() != Some(event.sequence)
                || event_id != event.event_id
                || hypothesis_id != event.hypothesis_id
                || previous_hash != event.previous_hash
                || event_hash != event.event_hash
            {
                return Err(LedgerError::StorageMetadata(event.sequence));
            }
            events.push(event);
        }
        Ok(events)
    }
}

impl InvestigationEvent {
    /// Constructs an event and computes its canonical chain hash.
    ///
    /// # Errors
    /// Returns an error if the hashable event body cannot be serialized.
    pub fn new(
        sequence: u64,
        event_id: impl Into<String>,
        hypothesis_id: impl Into<String>,
        previous_hash: impl Into<String>,
        kind: EventKind,
    ) -> Result<Self, LedgerError> {
        let mut event = Self {
            schema_version: SCHEMA_VERSION,
            sequence,
            event_id: event_id.into(),
            hypothesis_id: hypothesis_id.into(),
            previous_hash: previous_hash.into(),
            event_hash: String::new(),
            kind,
        };
        event.event_hash = event.compute_hash()?;
        Ok(event)
    }

    fn compute_hash(&self) -> Result<String, LedgerError> {
        #[derive(Serialize)]
        struct HashBody<'a> {
            schema_version: u16,
            sequence: u64,
            event_id: &'a str,
            hypothesis_id: &'a str,
            previous_hash: &'a str,
            kind: &'a EventKind,
        }
        let bytes = serde_json::to_vec(&HashBody {
            schema_version: self.schema_version,
            sequence: self.sequence,
            event_id: &self.event_id,
            hypothesis_id: &self.hypothesis_id,
            previous_hash: &self.previous_hash,
            kind: &self.kind,
        })?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

fn validate_chain(events: &[InvestigationEvent]) -> Result<(), LedgerError> {
    let mut previous = GENESIS_HASH;
    for (index, event) in events.iter().enumerate() {
        let expected_sequence =
            u64::try_from(index + 1).map_err(|_| LedgerError::SequenceOverflow)?;
        if event.schema_version != SCHEMA_VERSION {
            return Err(LedgerError::UnsupportedSchema(event.schema_version));
        }
        if event.sequence != expected_sequence {
            return Err(LedgerError::InvalidSequence {
                expected: expected_sequence,
                actual: event.sequence,
            });
        }
        if event.previous_hash != previous || event.compute_hash()? != event.event_hash {
            return Err(LedgerError::HashChain(event.sequence));
        }
        previous = &event.event_hash;
    }
    Ok(())
}

fn replay(events: &[InvestigationEvent]) -> Result<HypothesisState, LedgerError> {
    let first = events.first().ok_or(LedgerError::NoEvents)?;
    let EventKind::HypothesisProposed(hypothesis) = &first.kind else {
        return Err(LedgerError::FirstEventMustPropose);
    };
    if hypothesis.id.as_str() != first.hypothesis_id {
        return Err(LedgerError::HypothesisMismatch(first.sequence));
    }
    let expected_id = first.hypothesis_id.as_str();
    let mut state = HypothesisState::new(hypothesis.clone());
    for event in &events[1..] {
        if event.hypothesis_id != expected_id {
            return Err(LedgerError::HypothesisMismatch(event.sequence));
        }
        match &event.kind {
            EventKind::HypothesisProposed(_) => return Err(LedgerError::DuplicateProposal),
            EventKind::InvestigationStarted => state.begin_investigation()?,
            EventKind::ExperimentRecorded { id } => state.record_experiment(id.clone())?,
            EventKind::EvidenceReady => state.evidence_ready()?,
            EventKind::VerdictAssigned {
                policy,
                assessment,
                verdict,
            } => {
                let computed = state.decide(policy, assessment)?;
                if computed != *verdict {
                    return Err(LedgerError::VerdictMismatch);
                }
            }
            EventKind::PatchProposed { id } => state.propose_patch(id.clone())?,
            EventKind::PatchVerified { id, verification } => {
                state.verify_patch(id, verification)?;
            }
        }
    }
    Ok(state)
}

fn map_sqlite_error(error: rusqlite::Error) -> LedgerError {
    if matches!(error, rusqlite::Error::SqliteFailure(ref inner, _) if inner.extended_code == 2067)
    {
        LedgerError::DuplicateEvent
    } else {
        LedgerError::Sqlite(error)
    }
}

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("event batch cannot be empty")]
    EmptyBatch,
    #[error("ledger contains no events")]
    NoEvents,
    #[error("event sequence overflowed")]
    SequenceOverflow,
    #[error("unsupported event schema version {0}")]
    UnsupportedSchema(u16),
    #[error("invalid sequence: expected {expected}, found {actual}")]
    InvalidSequence { expected: u64, actual: u64 },
    #[error("hash chain verification failed at sequence {0}")]
    HashChain(u64),
    #[error("SQLite metadata disagrees with event body at sequence {0}")]
    StorageMetadata(u64),
    #[error("the first event must propose a hypothesis")]
    FirstEventMustPropose,
    #[error("event at sequence {0} references a different hypothesis")]
    HypothesisMismatch(u64),
    #[error("a hypothesis can only be proposed once")]
    DuplicateProposal,
    #[error("stored verdict does not match deterministic evidence policy")]
    VerdictMismatch,
    #[error("event ID or hash already exists")]
    DuplicateEvent,
    #[error("JSONL line {0} is blank")]
    BlankJsonLine(usize),
    #[error("state transition failed: {0}")]
    Transition(#[from] TransitionError),
    #[error("SQLite failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
}
