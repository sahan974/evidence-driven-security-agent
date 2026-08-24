# TypeScript security fixtures

This fixture contains an intentionally vulnerable path reader and an internal-request helper used
to exercise path-traversal and SSRF investigation. SSRF verification uses only a callback server
bound to `127.0.0.1` inside the network-disabled sandbox. No public destination is contacted.

Generated experiments use deterministic one-run `fast-check` properties, execute an independent
negative control, and can be replayed from the recorded Node command without an LLM.
