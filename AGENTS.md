# AGENTS.md

Single source of truth for AI coding agents working on this project. Read this before making any changes.

`CLAUDE.md` intentionally delegates here — update this file, not the pointer.

The Snyk SBOM CLI Extension: a Go module (built on the Snyk go-application-framework) that generates an SBOM (Software Bill of Materials) for a local software project. It registers a CLI-extension workflow that takes the project's dependency graphs, calls the Snyk API to convert them, and returns an SBOM document in a user-specified format.

**Scope:** These rules cover the Go source under `pkg/` and `internal/`.

> **Caution:** This repository is intended for internal (Snyk) contributions only at this time.

## Architecture

The extension is a single go-application-framework (GAF) workflow. `pkg/sbom` registers it via `Init(e workflow.Engine)` and defines its flags; the workflow (`SBOMWorkflow`) reads all inputs — config, logger, network client, dep-graphs — from the `workflow.InvocationContext` rather than constructing dependencies itself. `internal/service` calls the Snyk API to convert dep-graphs into an SBOM document, and `internal/errors` centralises customer-facing errors through an `ErrorFactory`.

### Hard rules

Every item is a blocking gate — a PR that violates any of these must not merge.

- **Require the user to explicitly set the SBOM output format** — never fall back to a default format such as CycloneDX JSON (see #17).
- **Build SBOMs only from the full (non-pruned) dependency graph** — never feed a pruned/"effective" graph (or the effective-graph flags) into SBOM generation; pruned graphs produce incorrect SBOMs (see #177).
- **Set the correct content type on SBOM results** (see #15).
- **Propagate the underlying GAF error** (e.g. from `GetStringWithError`) so the framework renders the correct error-catalog code (e.g. `SNYK-0005`) instead of a generic `SNYK-CLI-0000` (see #174, #114).
- **Keep accepting — and ignoring — the `--experimental` flag; do not remove it before GA.** Removing it broke usage and had to be reverted (see #27, #28).
- **Do not Snyk-monitor the code test in CI** — dependencies are already monitored, so monitoring the project twice is wrong (see #30).

### Conventions

- Dependencies are passed explicitly (read from `workflow.InvocationContext`); no DI container and no globals. Reference: [`pkg/sbom/sbom.go`](pkg/sbom/sbom.go)
- Construct customer-facing errors through the `ErrorFactory` (`internal/errors`, built with `errors.NewErrorFactory(logger)`), which logs the internal cause and produces an `SBOMExtensionError`; wrap the internal cause with `%w` and pass it into a factory method (see #26). Reference: [`internal/errors/errors.go`](internal/errors/errors.go)
- Read configuration through the GAF config (`config.GetBool`, `SNYK_`-prefixed env vars), not `os.Getenv` directly (see #155, #138).
- Build API URLs with `net/url` (`url.JoinPath`), not string concatenation or `Sprintf` — manual joining produces backslashes on Windows (see #110).
- Decode HTTP response bodies with `json.NewDecoder(resp.Body).Decode`, not by reading the whole body into memory (see #110, #92).
- Name functions and variables for their specific purpose (not package-wide-sounding names); name interfaces by the action they perform (e.g. `RemoteRepoURLGetter`) (see #123, #129, #161).
- Use `snake_case` for API query-parameter names per the Snyk API design rules (e.g. `go_module_level`, not `goModuleLevel`) (see #163).
- Gate logging so irrelevant ecosystems don't log on every SBOM run — keep logs quiet unless the value is relevant/set (see #178).

### Directory layout

| Directory | Purpose |
|-----------|---------|
| `pkg/sbom` | Workflow definition, flag registration, and the `Init` entrypoint for the CLI extension |
| `internal/service` | HTTP client logic converting dep-graphs to SBOM documents via the Snyk API |
| `internal/errors` | `ErrorFactory` producing customer-facing `SBOMExtensionError` values |
| `internal/mocks` | Hand-written HTTP test server/response mocks (excluded from linting) |

### Danger zone

Treat these areas as high-risk:

- **Error handling and user-facing error messages** (`internal/errors`, `internal/service`): the most-fixed area in the repo — org-ID inference, dep-graph failures, payload and response-body handling, API responses (see #18, #20, #24 and others).
- **The `--experimental` flag** in `pkg/sbom`: removing it before GA broke usage and had to be reverted — change its handling with care (see #27, #28).

For these, prefer the smallest possible change, add tests before modifying, and ask a human reviewer before landing.

## Code conventions

### Style and formatting

Formatting and linting are enforced by tooling — run `goimports -local github.com/snyk/cli-extension-sbom` and `golangci-lint run -v ./...` instead of reasoning about style; they are authoritative. There is no Makefile; invoke the Go and golangci-lint commands directly.

### Patterns

- Exported constructors are `New`-prefixed (`NewErrorFactory`, `NewInternalError`); flag names are `flagXxx` constants.
- Directories and source-file basenames are concatenated-lowercase single words (`errors.go`, `service.go`, `sbom.go`).

### Best practices for new code

Apply these principles when writing **new** code. Do not refactor existing code to comply unless explicitly asked.

When you touch a file that has existing violations:
1. Write your new code correctly.
2. Leave the surrounding violation untouched.
3. Emit: "⚠️ Legacy debt: [file:line] — [which principle], left alone to avoid scope creep."

- **Single Responsibility Principle (SRP)**
- **Avoid Hasty Abstractions (AHA)**

## Testing

> **Note:** No automated coverage enforcement found in CI or config. The unit-test job runs with `-race` and atomic covermode but does not fail on a coverage threshold — coverage is reported, not gated. Consider adding a threshold.

| Command | What it runs |
|---------|--------------|
| `go test -race ./...` | Unit tests |
| `go test -tags=integration ./...` | Integration tests |

Integration tests are guarded by the `integration` build tag (`//go:build integration`); the tag is declared in the golangci config so lint sees them too.

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

- Requires the Go toolchain pinned in `go.mod` (Go 1.19).
- Install `golangci-lint` separately — there is no Makefile or bundled install target.

## Commits and PRs

**Commit format:** Conventional Commits (`<type>(scope): <description>`) — used throughout git history, though no commitlint config enforces it.
Types observed: feat, fix, chore, refactor.
Example: `feat: introduce error factory which logs error details`
Branch naming: `<type>/<TICKET>-<description>` (e.g. `fix/LINK-213-body-error`).

## When in doubt

If you're unsure about a decision that would affect SBOM output correctness, the error contract, or the Snyk API interaction, ask @snyk/link (the CODEOWNERS team) before proceeding.

## Before you finish

Before presenting any change, verify each item below. Do not report work as complete until every applicable item passes.

- [ ] `go test -race ./...` passes
- [ ] `golangci-lint run -v ./...` passes
- [ ] `goimports -local github.com/snyk/cli-extension-sbom` run and output committed
- [ ] Integration tests (`go test -tags=integration ./...`) pass when touching the service or workflow
- [ ] New code has test coverage (or the "unverified" warning is documented)
- [ ] Snyk scan is clean (CI runs open-source + code tests at the high severity threshold)
- [ ] Commit / PR title follows Conventional Commits

---

## Human review checklist

This file was generated by `/create-agents-md:create-agents-md` in auto mode as a starting point. Complete these items to finish it:

- [ ] Review test coverage and consider adding a CI coverage threshold (currently reported, not enforced).
- [ ] Confirm the max subject-line length and whether commit types beyond feat/fix/chore/refactor are allowed.
- [ ] Remove this section once all items above are resolved.
