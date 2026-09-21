<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Contributing

Thank you for helping. lint-http holds every change to a small set of gates
that run locally in a couple of minutes, and a change that passes them locally
passes CI. This page is the process; [docs/development.md](../docs/development.md)
is the technical guide, including how a rule is written and cited.

## Set up once

- Rust 1.94 or newer through [rustup](https://rustup.rs), and
  [`just`](https://just.systems) (`cargo install just`).
- The citation toolchain, Python-based and dev-only: `just install-citations`
  builds a `.venv` from the pinned versions in `specs/requirements.txt`.
- `just install-hooks` enables the pre-commit hook, which checks formatting and
  citation currency before each commit.
- For the slow gates (`just check-all`): `cargo install cargo-deny cargo-machete
  cargo-tarpaulin` and `pipx install reuse`.

## Make a change

1. Fork the repository and branch from `main`.
2. Write the code and its tests. A rule needs a positive and a negative case;
   the development guide says where each thing goes.
3. Run `just check` as you go. It is the fast tier: formatting, citations,
   clippy, rustdoc, tests, and the quote check that opens every cited document.
4. If you changed a rule's or a defect's metadata, regenerate what is derived
   from it: `just gendocs` for `docs/rules/` and `docs/violations/`,
   `just genconfig` for `config_example.toml`. Editing those by hand fails a
   test.
5. Run `just check-all` before pushing. It adds the MSRV build, the supply-chain
   gates, a release build and coverage.
6. Make every commit build green on its own, not only the branch tip. A
   selective `git add` has produced a broken commit here more than once.
7. Open a pull request. The template lists what a reviewer looks for.

## What surprises newcomers

- **A quote is copied from the document, never recalled.** Every `// cite(…)`
  comment is verified against the published text by `just quotes`. A remembered
  quote compiles, formats and passes clippy; only that gate catches it.
- **`cargo fmt` does not reach the rule modules.** They enter the crate through
  a generated `#[path]` include. `just fmt` formats them; `just fmt-check` is
  what CI runs.
- **Rule ids and violation ids are breaking changes.** A configuration names
  them, and the catalogue does not alias. Renaming one is a decision, not a
  tidy-up.
- **Every file carries an SPDX header.** `reuse lint` gates it, including
  Markdown and TOML.
- **Nothing is registered by hand.** Creating a file under
  `lint-http-rules/src/rules/` is the registration.
- **Do not edit source while `just coverage` runs.** It reads the tree as it
  goes and takes about fifteen minutes.

## Reporting

Bugs, findings you believe are wrong, and feature ideas each have an issue
template. A suspected vulnerability goes through [SECURITY.md](SECURITY.md)
instead of a public issue.
