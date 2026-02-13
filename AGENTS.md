# Repository Guidelines

## Project Scope
This repository is a **fork of openmls/openmls**. The primary development focus is `torln-openmls-wasm/`, but the entire workspace is subject to fork management rules. Keep feature changes scoped to `torln-openmls-wasm/` or new crates (e.g., `openmls_torln_*`) unless a dependency change in the workspace is required.

**Critical**: openmls is a security/cryptography library (MLS protocol). Never modify core protocol or cryptographic logic casually. Any change to encryption, key management, or state machine code requires prior design review and team approval.

## Fork Management Principles
1. **Respect upstream design** — The original openmls design, security model, and protocol logic must be preserved. Do not alter core logic unnecessarily.
2. **Upstream compatibility** — The fork must remain mergeable with upstream (openmls/openmls) to receive security patches and bug fixes. Keep our custom code clearly separated from upstream code.
3. **Traceable changes** — Every change must go through a PR with clear purpose and impact scope. No direct commits to `main`.

## Code Change Scope Rules (Priority Order)
When adding functionality, prefer these approaches in order:
1. **Best**: Create a new crate, module, or adapter layer (e.g., `openmls_torln_*`).
2. **Acceptable**: Add a new file/module within an existing crate to isolate logic.
3. **Last resort**: Modify existing upstream core logic (protocol/crypto). Requires team discussion first.

## ALG Comment Tagging
When modifying upstream-managed code, mark the change with an `ALG:` tag comment:
```rust
// ALG: <summary of change intent> (author: <name or initials>)
// Example:
// ALG: add application-specific group context (author: TK)
```
- `ALG:` is the fixed search prefix for locating all our modifications to upstream code.
- If the change evolves, update the description but keep the tag.

## Git Remotes & Branch Structure

### Remotes
- `origin` — our fork (torlnapp/openmls)
- `upstream` — original repo (openmls/openmls). **Never push to upstream.**

### Branches
| Branch | Purpose | Rules |
|--------|---------|-------|
| `upstream-main` | Tracks `upstream/main` exactly | No direct commits. Update only via `git reset --hard upstream/main`. |
| `main` | Our project's base branch | No direct commits or force-push. All changes via PR only. |
| `feature/*` | Feature development | Branch from `main`. |
| `fix/*` | Bug fixes | Branch from `main`. |
| `chore/upstream-sync-*` | Upstream sync operations | Created from `upstream-main`. See sync procedure below. |

### Upstream Sync Procedure
1. Update `upstream-main`: `git checkout upstream-main && git fetch upstream && git reset --hard upstream/main`
2. Create sync branch: `git checkout -b chore/upstream-sync-YYYY-MM-DD upstream-main`
3. Merge our main: `git merge main` → resolve conflicts → run `cargo fmt` / `cargo test` / `cargo clippy`
4. PR `chore/upstream-sync-*` → `main` (requires review). Verify: ALG-tagged code preserved, no test regressions, API changes addressed.

## Project Structure & Module Organization
- `torln-openmls-wasm/src/` — Rust source for the wasm bindings.
- `torln-openmls-wasm/static/` — static assets copied into the output package.
- `torln-openmls-wasm/pkg/` — wasm-pack build output (generated).
- `torln-openmls-wasm/build.sh` — builds the wasm package and copies `static/index.html`.
- `torln-openmls-wasm/check-size.sh` — size budget check for the packaged output.

## Build, Test, and Development Commands
- `cargo build -p torln-openmls-wasm` — compile the crate in the workspace.
- `cargo test -p torln-openmls-wasm` — run Rust unit tests for this crate.
- `./torln-openmls-wasm/build.sh` — build the wasm package (requires `wasm-pack`).
- `./torln-openmls-wasm/check-size.sh` — build and enforce bundle size budgets.
- `cargo fmt` — format codebase with the workspace `rustfmt` settings.
- `cargo clippy --all-targets --all-features` — lint check (run before PR).

## Coding Style & Naming Conventions
- Formatting: always run `rustfmt`; CI enforces formatting.
- Rust 2021 edition (see `rustfmt.toml`).
- Naming: `snake_case` for modules/functions, `CamelCase` for types/traits, `SCREAMING_SNAKE_CASE` for constants.
- Documentation: add rustdoc comments on public APIs; keep wasm-exposed APIs well documented.

## Testing Guidelines
- Prefer unit tests in `torln-openmls-wasm/src/` near the code under test.
- Run `cargo test -p torln-openmls-wasm` before submitting changes.
- For changes touching upstream code, also run the full workspace tests to check for regressions.

## Commit & Pull Request Guidelines
- **Commit messages**: Use conventional commit format with scope. Present tense, imperative mood, first line ≤ 80 chars.
  - `feat(torln-adapter): add custom storage backend`
  - `fix(torln-crypto): handle key rotation edge cases`
  - `chore(openmls): sync with upstream v0.7.1`
- **PRs**: One logical change per PR. PR description must include:
  - Change summary
  - Reason / background
  - Impact scope (which crates/modules affected)
  - Test results (manual/automated)
- Keep each PR ≤ 1000 lines. Ensure status checks pass before review.
- **Review checklist**: Does it affect protocol/crypto? Does it increase upstream merge conflict risk? Are fmt/clippy/test passing?

## Dependency Management (Service Repos)
- Service repos consume this fork as a git dependency:
  ```toml
  [dependencies]
  openmls = { git = "https://github.com/torlnapp/openmls.git", branch = "main", package = "openmls" }
  ```
- Pin to `main` or a specific tag (e.g., `torln-v0.7.2+torln1`) for production.
- Local `path` dependency overrides are for personal dev only — never commit them to shared configs.
- When changes land on `main`, verify downstream service repos still build and pass tests.

## Size & Output Tips
- `check-size.sh` enforces size thresholds; keep wasm exports minimal and avoid pulling in large dependencies.
- Generated output in `torln-openmls-wasm/pkg/` should not be hand-edited.
