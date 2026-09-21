# Evidence-Driven Security Agent

Evidence-Driven Security Agent is a Rust-based multi-agent system for examining
Python, TypeScript, and Go repositories. It turns source-level signals into
falsifiable hypotheses, selects a bounded verification harness, executes the
verification in an isolated sandbox, and records the evidence needed to
reproduce its final result.

The system is designed to distinguish a plausible concern from a confirmed
finding. A model can interpret repository context and select from approved
verification options. It cannot execute arbitrary commands, generate a shell
script for the host, or assign a finding verdict by itself.

## What it does

- Maps repository source into security-relevant signals.
- Produces ranked, falsifiable hypotheses from those signals.
- Lets an Experiment Designer select a typed harness and an admitted callable
  target for each hypothesis.
- Runs baseline, attack, negative-control, and independent replay checks in an
  isolated Docker environment.
- Uses an Evidence Critic and Reviewer to assess whether the recorded evidence
  is sufficient for the deterministic decision gates.
- Saves run events, evidence artifacts, replay plans, and a verification
  bundle.

## Agents

| Agent | Role |
| --- | --- |
| Mapper | Examines the admitted repository projection and identifies security-relevant source signals. |
| Hypothesis Planner | Converts signals into ranked hypotheses with explicit claims and falsifiers. |
| Experiment Designer | Selects one approved verification harness and one admitted callable target for the current hypothesis. |
| Evidence Critic | Assesses whether the recorded baseline, attack, control, replay, and source evidence are sufficient for gate evaluation. |
| Reviewer | Examines the evidence and reviewer concerns before the runtime applies its deterministic confirmation or rejection gates. |

## Verification model

The model is responsible for repository interpretation, hypothesis planning,
evidence analysis, and selecting from the tools already available to it. The
runtime remains responsible for execution safety and proof decisions.

For every experiment, the Designer must select:

- A typed harness compatible with the repository language and hypothesis class.
- An exact callable from the admitted target catalog, such as
  `app.py::find_account`.
- A rationale explaining why that harness and target are relevant.

The runtime rejects made-up callables, imported dependencies, fields, methods,
unsafe paths, and tools outside the allowed catalog. It never treats a model
proposal as executable code.

## Supported verification harnesses

The current harness set covers the following classes:

| Language | Verification classes |
| --- | --- |
| Python | Path traversal, command injection, SQL injection, unsafe deserialization, broken authorization, sensitive data exposure |
| TypeScript | Path traversal, SSRF, broken authorization, sensitive data exposure, SQL injection |
| Go | Malformed-input panic, filesystem boundary failure, broken authorization, resource exhaustion |

A confirmed result requires a successful baseline, attack oracle, negative
control, and independent replay. When the available evidence does not justify a
decision, the result remains inconclusive rather than being promoted to a
finding.

## Live investigation view

Pass `--live` to see the investigation as it happens. The terminal output is
organized by case and agent role. It shows:

- Mapper signals with source locations.
- Numbered hypotheses, claims, and falsifiers.
- The prioritized hypothesis, using the same visible hypothesis number.
- Numbered proposed experiments.
- The selected harness, exact target, and selection rationale.
- Model-requested read and search tool calls with their outcomes.
- Baseline, attack, and negative-control results.
- Evidence Critic and Reviewer conclusions.
- The final confirmed, rejected, deferred, or inconclusive state.


## Running a scan

### Prerequisites

- Rust and Cargo.
- Docker Desktop running with Linux containers enabled.
- An API key for an OpenAI-compatible model endpoint.

Check the local tooling:

```powershell
rustc --version
cargo --version
docker info
```

### Configure the model provider

Create a private `.env` file from the supplied template:

```powershell
Copy-Item .env.example .env
```

Set these values in `.env`:

```text
MODEL_PROVIDER=openai-compatible
MODEL_API_KEY=your-api-key
MODEL_API_URL=your-provider-chat-completions-endpoint
MODEL_NAME=your-model-name
MODEL_TIMEOUT_SECONDS=60
MODEL_MAX_RETRIES=2
```

Optional pricing fields let the run ledger estimate model cost:

```text
MODEL_INPUT_COST_PER_MILLION_USD=
MODEL_OUTPUT_COST_PER_MILLION_USD=
```

The live workflow and included benchmark cases were tested with
DeepSeek-V4.1-Flash through a DeepSeek OpenAI-compatible endpoint. DeepSeek
is not required: any provider that supports the same chat-completions contract
can be configured through these variables.

Verify the configured provider before starting a scan. This makes one live
model request and may incur a small API charge.

```powershell
cargo test -p edsa-model-providers --test provider_contract configured_provider_live_smoke_test -- --ignored --exact
```

### Run a live scan

```powershell
cargo run -p edsa-cli -- scan <repository-root> --output <run-directory> --max-tokens 30000 --max-cost-microusd 500000 --max-turns 20 --max-experiments 10 --timeout-seconds 900 --live
```

The output directory contains the event ledger, evidence artifacts, replay
plans, and final report bundle for that run.

Verify a completed run bundle:

```powershell
cargo run -p edsa-cli -- inspect <run-directory>
```

## Running the full benchmark

The included benchmark creates an isolated Git workspace for every case and
runs the complete agent loop against the Python, TypeScript, and Go fixtures.

```powershell
cargo run -p edsa-cli -- benchmark full ".edsa/benchmarks/full-run" 30000 500000 20 10 900 --live
```

To inspect one case without running the whole corpus:

```powershell
cargo run -p edsa-cli -- benchmark case py-case-03 ".edsa/benchmarks/python-preview" 30000 500000 20 10 900 --live
```

## Validation

```powershell
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

## License

Licensed under the MIT License.
