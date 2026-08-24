# Repository ingestion fixtures

Task 6 uses temporary Git repositories created by its integration tests rather
than committed vulnerable applications. The fixtures cover clean and dirty trees,
mixed Python/TypeScript/JavaScript/Go detection, auditable exclusions, path
traversal, non-root repository paths, and symbolic links without executing any
repository code.
