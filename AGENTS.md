# AGENTS.md

Single source of truth for AI coding agents working on this project. Read this before making any changes.

`CLAUDE.md` intentionally delegates here — update this file, not the pointer.

The Snyk SBOM CLI Extension: a Go module (built on the Snyk go-application-framework) that adds the `sbom` command group to the Snyk CLI. It generates an SBOM (Software Bill of Materials) for a local project (`sbom`), and tests and monitors SBOMs (`sbom test`, the experimental `sbom monitor`). It gathers the project's dependency graphs, calls the Snyk API to convert them, and renders the result.

**Scope:** These rules cover the Go source under `pkg/` and `internal/`.

> **Caution:** This repository is intended for internal (Snyk) contributions only at this time.

## Architecture

The extension registers the `sbom` command group on the GAF engine. `pkg/sbom.Init(engine)` calls each command package's `RegisterWorkflows(engine)`. Each `internal/commands/<cmd>/` package — `sbomcreate`, `sbomtest`, `sbommonitor` — exposes a `WorkflowID`, a `RegisterWorkflows(e workflow.Engine) error` that builds its flag set (`internal/flags`) and registers the workflow, and a `<Cmd>Workflow(ictx workflow.InvocationContext, input []workflow.Data)` handler that reads all inputs from the InvocationContext. `internal/service` converts dep-graphs into SBOM documents and maps HTTP status to errors; `internal/snykclient` is the Snyk API client; `internal/view` renders human-readable test/monitor output; `internal/errors` centralises customer-facing errors.

### Hard rules

Every item is a blocking gate — a PR that violates any of these must not merge.

- **The SBOM path uses the raw (unpruned) dependency graph by default.** Request the effective (pruned) graph only when the user passes `--prune-repeated-subdependencies` *and* the `internal_snyk_sbom_prune_effective_graph_enabled` feature flag is on (then set `effective-graph` / `effective-graph-with-errors`); without the flag, `-p` is a no-op. Never feed a pruned graph into an SBOM outside that gate — pruned graphs produce incorrect SBOMs. Reference: [`internal/commands/sbomcreate/depgraph.go`](internal/commands/sbomcreate/depgraph.go)
- **Require the user to set the SBOM output format explicitly** — `--format` has no default; validate it with `service.ValidateSBOMFormat` (supported: `cyclonedx1.4/1.5/1.6+json|xml`, `spdx2.3+json`). Reference: [`internal/service/service.go`](internal/service/service.go)
- **Render user-facing errors through the Snyk error-catalog** (`error-catalog-golang-public`) so the correct `SNYK-…` code shows, and propagate the underlying GAF error (e.g. from `GetStringWithError`) instead of substituting one that renders a generic `SNYK-CLI-0000`. The local `ErrorFactory` / `SBOMExtensionError` is an interim layer being migrated to the catalog — new error paths use the catalog. Reference: [`internal/errors/errors.go`](internal/errors/errors.go)
- **Preserve backwards compatibility for existing CLI customers.** Keep `--experimental` as a deprecated, ignored no-op on `sbom` create/test (it is still required to enable the experimental `sbom monitor` command), and do not add validation that breaks current usage. Reference: [`internal/flags/flags.go`](internal/flags/flags.go)

### Conventions

- Command workflows read their dependencies (config, logger, network client, analytics) from `workflow.InvocationContext`; lower-level types take plain constructor params (`NewSnykClient(client, apiBaseURL, orgID)`). No DI container, no globals.
- Read configuration through the GAF config (`config.GetBool` / `GetString`, `SNYK_`-prefixed env vars), not `os.Getenv` directly.
- Build API URLs with `net/url` (`url.JoinPath`, returning `*url.URL`), not string concatenation or `Sprintf` — manual joining produces backslashes on Windows.
- Decode HTTP response bodies with `json.NewDecoder(resp.Body).Decode`, not by reading the whole body into memory.
- Take result totals and summary values from the server response (e.g. `res.Summary.TotalIssues`); never recompute them locally.
- Name interfaces by the action they perform and don't bind them to one implementation (e.g. `RemoteRepoURLGetter`, not a git-specific name).
- Include the Snyk request ID in surfaced error responses so failures are traceable.
- Register experimental or network-hitting flags as hidden and decoupled from unrelated feature flags — an explicit per-invocation opt-in (e.g. `--gradle-refresh-dependencies`).
- New or higher-risk behaviour is typically rolled out behind a feature flag (decided per change, not required for every change) for staged per-org/group rollout; flags are checked via `config.GetBool(constants.FeatureFlag…)` and named in `internal/constants`. Reference: [`internal/constants/constants.go`](internal/constants/constants.go)

### Directory layout

| Directory | Purpose |
|-----------|---------|
| `pkg/sbom` | Extension entrypoint: `Init(engine)` registers the three subcommand workflows |
| `internal/commands/sbomcreate` | `sbom` create command: workflow, dep-graph gathering, SBOM generation |
| `internal/commands/sbomtest` | `sbom test` command: test workflow, presenter, summary |
| `internal/commands/sbommonitor` | `sbom monitor` command (experimental): monitor workflow, file parse |
| `internal/snykclient` | HTTP client to the Snyk API (sbom convert, sbom test, monitor deps, JSON:API types) |
| `internal/service` | Converts dep-graphs into SBOM documents; HTTP status → error mapping |
| `internal/view` | Human-readable rendering of test/monitor results |
| `internal/errors` | Customer-facing errors via `ErrorFactory` / `SBOMExtensionError` |
| `internal/flags` | CLI flag definitions and per-command flag sets |
| `internal/constants` | Feature-flag names and shared constants |

## Code conventions

### Style and formatting

Formatting and linting are enforced by tooling — run `goimports -local github.com/snyk/cli-extension-sbom` and `golangci-lint run -v ./...` (golangci-lint v2; CI pins v2.9.0) instead of reasoning about style; they are authoritative. There is no Makefile; invoke the Go and golangci-lint commands directly.

### Patterns

- Exported constructors are `New`-prefixed (`NewErrorFactory`, `NewSnykClient`); flag names are `flagXxx` / `FlagXxx` constants.
- Package and source-file basenames are concatenated-lowercase single words (`sbomcreate`, `snykclient.go`); `cmd_exec` is the lone snake_case exception.
- `ireturn` restricts functions to returning concrete types — only `error` and `workflow.Data` may be returned as interfaces.

### Best practices for new code

Apply these principles when writing **new** code. Do not refactor existing code to comply unless explicitly asked.

When you touch a file that has existing violations:
1. Write your new code correctly.
2. Leave the surrounding violation untouched.
3. Emit: "⚠️ Legacy debt: [file:line] — [which principle], left alone to avoid scope creep."

- **Single Responsibility Principle (SRP)**
- **Avoid Hasty Abstractions (AHA)**

## Generated code

Never hand-edit these — they are auto-generated:

| Path | Generator | Regenerate with |
|------|-----------|-----------------|
| `internal/mocks/mock_codescanner.go` | GoMock (`mockgen`) for `code-client-go` `CodeScanner` | `mockgen -package=mocks -destination=internal/mocks/mock_codescanner.go github.com/snyk/code-client-go CodeScanner` |

## Testing

> **Note:** No automated coverage enforcement found in CI or config. The unit-test job runs with `-race` and atomic covermode but does not fail on a coverage threshold — coverage is reported, not gated. Consider adding a threshold.

| Command | What it runs |
|---------|--------------|
| `go test -race ./...` | Unit tests |

There is no Makefile — run Go commands directly. The golangci config declares an `integration` build tag, but no integration-tagged tests currently exist.

### AI agent testing protocol

**1. Test-first: fail before pass.**

Before writing implementation, write a test that exercises the new behavior. Run it — it **must
fail** first. A test that passes before the change is testing the wrong thing; discard it and write
another. Implement, then run again. This cycle counts as one attempt; you have **3 attempts** total.
If fail-then-pass cannot be achieved, stop and warn: "Warning: could not achieve
fail-before/pass-after for [test name] — [reason]."

If writing a test before implementation is genuinely not feasible (e.g., the change is in test
scaffolding itself), document the reason explicitly.

**2. Do not add tests for pre-existing untested code you touch.**

When modifying existing code that has no tests, report it: "Warning: [file/function] has no
existing test coverage. This change is unverified." Do **not** add tests for it — that is out of
scope and may introduce incorrect assumptions about existing behavior. Do write tests for any
**new** behavior you add, even if it lives in an existing file.

## Local development

- Requires the Go toolchain; the version is pinned in `go.mod` — consult it rather than assuming.
- Install `golangci-lint` separately — there is no Makefile or bundled install target.
- A local dev harness lives at `cmd/develop/main.go` for running the extension outside the CLI.

## Commits and PRs

**Commit format:** Conventional Commits (`<type>(scope): <description>`) — used throughout git history, though no commitlint config enforces it.
Types observed: feat, fix, chore, refactor, docs.
Example: `feat: allow sbom test --report/--monitor via registry-based group opt-in [OSF-466]`
Branch naming: `<type>/<TICKET>-<description>` (e.g. `feat/osf-466/registry-based-sbom-monitor-ff`).

## When in doubt

If you're unsure about a decision that would affect SBOM output correctness, the error contract, feature-flag gating, or the Snyk API interaction, ask @snyk/engines_sca-scanners (the CODEOWNERS team) before proceeding.

## Before you finish

Before presenting any change, verify each item below. Do not report work as complete until every applicable item passes.

- [ ] `go test -race ./...` passes
- [ ] `golangci-lint run -v ./...` passes
- [ ] `goimports -local github.com/snyk/cli-extension-sbom` run and output committed
- [ ] Mocks regenerated with `mockgen` if the mocked interface changed
- [ ] New code has test coverage (or the "unverified" warning is documented)
- [ ] New/changed behaviour is feature-flag gated where appropriate
- [ ] Commit / PR title follows Conventional Commits
