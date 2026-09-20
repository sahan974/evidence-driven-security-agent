# Benchmark fixtures

The benchmark has eighteen small repositories: six each for Python, TypeScript, and Go. Each repository exposes the same public entry point used by the language adapter, but the work is split across an application boundary, a service where appropriate, and a storage, network, process, or codec boundary.

The cases are intentionally compact enough to run repeatedly in an isolated container. They are not intended to resemble full production applications. Their purpose is to test whether a scan can follow a realistic call path, distinguish clean controls from vulnerable cases, create a proof, and replay that proof without calling the model again.

`ground-truth/answers.json` is the evaluation key. It is used only after a run completes to calculate benchmark metrics. The model receives the public brief and the repository source, not the answer key.

Every benchmark run records a manifest digest. Changing fixture source or a public brief therefore creates a new corpus revision. Results from an earlier output directory remain valid for the repository snapshot captured in that directory, but must not be presented as results for a newer fixture revision.
