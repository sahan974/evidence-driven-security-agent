# Disposable patch-loop fixtures

The integration tests create temporary Git repositories from a one-line vulnerable file and apply
a unified diff only inside detached disposable worktrees. The fixture scenarios cover successful
verification, regression failure, incomplete variant rejection, cancellation, and patch-application
failure. Every scenario compares the original working-tree status and content before and after the
attempt.
