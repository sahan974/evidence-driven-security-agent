# TypeScript and Go patch verification

The patch command can verify filesystem boundary repairs for the Node and Go
replay formats produced by the adapters. Each candidate runs in a disposable
worktree. Verification checks a normal file read, the original path, and eight
alternate paths including sibling directories, absolute paths, and symlinks.
Unsupported replay formats fail with a reason. These checks do not establish
repair coverage for other finding classes.

Node supports directly importable JavaScript and TypeScript modules with Node 22
type stripping. Projects that require a separate compiler or custom loader need
that environment prepared separately. Go supports the adapter's selected local
test with a `path` argument passed to a function returning content and an error.
The verifier obtains this contract from the original test source. It rejects
ambiguous contracts and source symlinks.

The Node verifier requires the safe read to return the exact generated content.
An ordinary Error can indicate rejection, but filesystem failures and programming
errors fail the check. Go also requires exact safe content and rejects wrapped
filesystem errors. These are bounded behavioral checks, not proof of correctness
for every input or concurrent filesystem change.

## Local checks

Run from the repository directory in Git Bash. These commands do not call a model.
The container tests exercise the real language runtimes against complete repairs,
prefix-only repairs, reject-everything functions, and execution failures.

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p edsa-agent-runtime --test patch_loop
docker build -f crates/cli/tests/Dockerfile.patch-gates -t edsa-patch-gates:local .
MSYS_NO_PATHCONV=1 docker run --rm --network none --mount "type=bind,source=$(pwd),target=/workspace,readonly" edsa-patch-gates:local python crates/cli/tests/test_polyglot_patch_gates.py
```

## Live acceptance

A live run must already contain a confirmed filesystem finding and its replay
plan. Set these variables to the actual run directories and IDs. The tests use
the configured hosted provider and consume API credit.

```bash
export EDSA_PATCH_TYPESCRIPT_RUN="path/to/typescript-run"
export EDSA_PATCH_TYPESCRIPT_FINDING="actual-finding-id"
export EDSA_PATCH_GO_RUN="path/to/go-run"
export EDSA_PATCH_GO_FINDING="actual-finding-id"
```

For Node projects with dependencies, prepare an image using the target repository
as build context. Its package lock must agree with its package manifest. A stale
lock must be corrected before building. The image installs dependencies during
preparation. Verification itself runs without network access and copies the
project to temporary storage so test tools can write their caches.

```bash
docker build -f crates/cli/tests/Dockerfile.node-patch -t edsa-node-patch:local path/to/typescript-target
export EDSA_PATCH_TYPESCRIPT_IMAGE=edsa-node-patch:local
cargo test -p edsa-cli --test live_patch_workflow live_typescript_patch_passes_every_gate -- --ignored --exact --nocapture
cargo test -p edsa-cli --test live_patch_workflow live_go_patch_passes_every_gate -- --ignored --exact --nocapture
```

Go uses the image and resource settings recorded in its replay plan. Projects
with external modules need an image containing those modules. Optional image
overrides are `EDSA_PATCH_PYTHON_IMAGE`, `EDSA_PATCH_TYPESCRIPT_IMAGE`, and
`EDSA_PATCH_GO_IMAGE`. Each takes precedence over `EDSA_PATCH_IMAGE`.

Accept the implementation only after the relevant live test passes. A passing
container harness test alone does not demonstrate model-generated repair.
