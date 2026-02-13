# Repository Guidelines

## Project Scope
This repository is a multi-crate workspace, but this project focuses on `torln-openmls-wasm/` only. Keep changes scoped to that crate unless a dependency change in the workspace is required.

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

## Coding Style & Naming Conventions
- Formatting: always run `rustfmt`; CI enforces formatting.
- Rust 2021 edition (see `rustfmt.toml`).
- Naming: `snake_case` for modules/functions, `CamelCase` for types/traits, `SCREAMING_SNAKE_CASE` for constants.
- Documentation: add rustdoc comments on public APIs; keep wasm-exposed APIs well documented.

## Testing Guidelines
- Prefer unit tests in `torln-openmls-wasm/src/` near the code under test.
- Run `cargo test -p torln-openmls-wasm` before submitting changes.

## Commit & Pull Request Guidelines
- Commit messages: present tense, imperative mood, first line ≤ 80 chars; reference issues/PRs after the first line; call out key review comments for nontrivial patches.
- PRs: link and assign an issue, keep each PR ≤ 1000 lines, and follow the PR template. Describe design, alternatives, side-effects, and verification steps. Ensure status checks pass before review.

## Size & Output Tips
- `check-size.sh` enforces size thresholds; keep wasm exports minimal and avoid pulling in large dependencies.
- Generated output in `torln-openmls-wasm/pkg/` should not be hand-edited.
