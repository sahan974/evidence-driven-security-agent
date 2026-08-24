# Python security fixtures

The Python vertical slice exercises two falsifiable vulnerability classes:

- path traversal using a minimized `../../etc/passwd` payload and a safe-file control;
- command injection using a marker-producing shell payload and a metacharacter-free control.

Each generated reproducer is a deterministic `python -c` command. It runs only through the
sandbox backend, requires no LLM to replay, and records the command, exit status, bounded output,
oracle result, and negative-control result. The end-to-end test suite models confirmed, rejected,
and inconclusive outcomes; live Docker execution remains an optional integration boundary.
