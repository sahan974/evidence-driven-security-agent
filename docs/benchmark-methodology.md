# Benchmark methodology

The benchmark contains 18 original micro-applications: six each for Python, TypeScript/JavaScript,
and Go. Cases cover path traversal, command injection, SQL injection, SSRF, broken authorization,
unsafe deserialization, sensitive-data exposure, malformed-input panic, and resource exhaustion.
Each language includes clean negatives, and the hidden answers identify incomplete-patch traps.

## Isolation from answers

`benchmarks/manifest.json` contains only case identifiers, language, mount path, and a generic review
brief. Exact status, weakness, and patch-trap labels live under `benchmarks/ground-truth`. Each agent
or sandbox receives only one `benchmarks/cases/...` directory. The harness rejects absolute paths,
parent traversal, missing directories, or any mount under `ground-truth`.

Live prompts wrap source files in explicit `repository-data` delimiters and state that repository
text is untrusted data rather than instructions. They do not include answer records, exact proof
inputs, or ground-truth paths.

## Compared modes

- `external_analyzer`: alert-oriented output without executable confirmation.
- `llm_only`: model proposals limited to signal, suspected, or inconclusive states.
- `full_system`: evidence-gated investigation, replay, and patch verification.

Deterministic mock profiles make CI reproducible. Live mode is opt-in, requires explicit token and
cost budgets, and emits the same versioned JSON result schema.

## Metrics

Reports contain precision, recall, false-confirmation rate, proof stability, patch success,
regression escape, replay success, total duration, model tokens, and API cost in micro-USD. A
confirmed result is counted only when its state is `confirmed`; signals and suspicions are not
silently promoted. Regression escape is reported separately so superficially successful but
incomplete patches remain visible.
