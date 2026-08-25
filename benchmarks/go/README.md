# Go security fixtures

This module provides deterministic targets for the Go vertical slice:

- malformed input that triggers and records a recovered panic marker;
- a filesystem-boundary violation using `../../etc/passwd` with `safe.txt` as its control;
- a native fuzz target and a race-detector target.

The adapter invokes only native `go test`, fuzzing, and `-race` commands through the hardened
sandbox. Corpus and minimized inputs are stored in the evidence artifact store by SHA-256 digest,
and deterministic findings can be replayed from their recorded command without an LLM.
