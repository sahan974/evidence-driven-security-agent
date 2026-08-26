# Threat model

## Scope and security objective

The framework analyzes repositories that may be actively malicious. Its objective is to produce
auditable security evidence without granting repository content, model output, imported findings,
or executed code authority over the host, credentials, permissions, verdicts, or patch gates.

## Assets

- Host files, Git credentials, provider API keys, environment variables, and Docker control plane.
- Integrity of the authorized repository, append-only evidence, reports, and benchmark ground truth.
- Availability represented by bounded CPU, memory, processes, time, output, model tokens, and cost.
- Verdict integrity: only deterministic evidence gates may confirm findings or verify patches.

## Trust boundaries

1. The CLI and deterministic state machine are trusted control-plane code.
2. Repository files, filenames, manifests, lockfiles, archives, and dependency metadata are untrusted.
3. Model requests cross a hosted-provider boundary; model responses are untrusted proposals.
4. Imported SARIF and external analyzer output are untrusted signals, never confirmation evidence.
5. Docker is the execution boundary. Target code runs as an unprivileged user with bounded resources.
6. Disposable Git worktrees isolate proposed patches from the authorized checkout.

## Attackers and abuse cases

An attacker may control a scanned repository, dependency, analyzer result, or model-visible text.
Relevant attacks include prompt injection that requests tools or false verdicts; install scripts and
build hooks; symlink and archive traversal; oversized files and output floods; API-key exfiltration;
network callbacks; container escape attempts; poisoned SARIF locations and metadata; malicious or
over-broad diffs; denial of service; and benchmark-answer discovery.

## Enforced controls

- Typed role inputs, outputs, tool requests, and per-role capability allowlists constrain agency.
- Repository-derived JSON is wrapped in explicit untrusted-data delimiters. Text cannot mutate the
  trusted role configuration, budgets, approvals, state transitions, or deterministic gates.
- Secret-like files are excluded at ingestion. Sensitive environment names are denied even when
  allowlisted, provider credentials use redacting types, and model output is scanned before use.
- Paths must remain relative and contained. Symlinks and traversing archive members are rejected.
- Network and dependency installation have distinct typed policy decisions and default to denied.
- Patch application requires a typed approval, occurs only in a disposable worktree, is checked by
  Git before application, and must pass the full verification ladder before becoming verified.
- Sandboxes default to no network, read-only source, no capabilities, no-new-privileges, non-root,
  read-only root filesystem, bounded PID/CPU/memory/time/output, and guaranteed cleanup.
- External findings remain signals. Confirmation and patch verification are machine-gated states.
- Benchmark ground truth is outside all agent-visible case mounts and prompts.

## Residual risks and operating requirements

Docker and the host kernel remain part of the trusted computing base; a container-runtime escape or
kernel vulnerability may defeat isolation. Explicitly approved network or dependency installation
increases supply-chain and exfiltration risk and should use pinned artifacts and a restricted proxy in
production. Pattern-based secret scanning cannot detect every credential and may produce false
positives. Resource limits reduce, but do not eliminate, host exhaustion. Git patch parsing and
language toolchains remain complex attack surfaces. Human approval must therefore describe the exact
repository, operation, budget, and expiry, and published claims must remain limited to stored evidence.

## Security invariants for review

- No provider secret is copied into a `SandboxRequest`, container environment, artifact, or report.
- No repository string is parsed as a policy decision or state transition.
- No model output directly confirms a finding or verifies a patch.
- No patch touches the original checkout before independent verification and human acceptance.
- Every denied, failed, truncated, cancelled, or inconclusive action remains explicit and auditable.
