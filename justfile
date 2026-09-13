# SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
#
# SPDX-License-Identifier: ISC

# Local mirror of the CI gates. `just check` runs everything CI rejects a PR for;
# `just fmt` fixes the formatting that `cargo fmt` alone cannot reach. Run bare
# `just` to list recipes. Enable the commit-time guard once with
# `just install-hooks`.

# rustfmt does not follow the build.rs `#[path]` include into the rule modules,
# so `cargo fmt` never formats them. They are formatted directly here, exactly as
# the CI fmt job does — this is the drift the guard exists to stop.
rule-modules := "lint-http-rules/src/rules/*.rs"

# List available recipes.
default:
    @just --list

# Format the whole workspace, including the rule modules cargo fmt cannot reach.
fmt:
    cargo fmt --all
    rustfmt --edition 2021 {{rule-modules}}

# Check formatting exactly as the CI fmt job does (workspace + rule modules).
fmt-check:
    cargo fmt --all -- --check
    rustfmt --edition 2021 --check {{rule-modules}}

# Clippy across the workspace, warnings as errors (the `cargo lint` alias).
lint:
    cargo lint

# The docs build with no warnings — dead intra-doc links included. The comments
# here are the design record, so this checks the artifact they render into.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

# Workspace tests with all features.
test:
    cargo test --workspace --all-features

# Build .venv from the pinned citation toolchain. The pin lives in
# specs/requirements.txt because the bytes of specs/specs_generated.yaml depend
# on it; a .venv built by hand is how a local `extract` and CI's disagree about a
# file neither of them edited.
install-citations:
    python3 -m venv .venv
    .venv/bin/pip install --quiet --upgrade pip
    .venv/bin/pip install --quiet -r specs/requirements.txt
    @.venv/bin/apycite --help >/dev/null && echo "✓ citation toolchain installed from specs/requirements.txt"

# Citations file is current and the ratchet holds — offline, from the .venv.
#
# This says nothing about whether a quote is *in* its document: `extract` reads
# the tree and `ratchet` counts files. The recipe that opens the documents is
# `quotes` below, and the two are separate because only one of them needs the
# network.
citations:
    #!/usr/bin/env bash
    set -euo pipefail
    apy=.venv/bin/apycite; [ -x "$apy" ] || apy=apycite
    "$apy" extract --frozen
    "$apy" ratchet

# Every quote still says what the code claims it says.
#
# **This is the gate that catches a sentence nobody read.** A cite comment is
# ordinary source text: a quote recalled from memory rather than copied out of
# the document compiles, formats, passes clippy, passes `citations` above, and
# fails only here — which is exactly what happened to an RFC 9651 § 4.2 quote
# that turned two answers into one. Nothing cheaper can find it, because
# everything cheaper is reading the same wrong string this file is.
#
# Slower than the rest of `check` put together (~80s) and the only recipe in it
# that touches the network. It reads through the HTTP cache in `data/cache/`,
# where CI runs `apycite verify --refresh --strict-redirects` and re-fetches
# every source — so a green run here means the quotes match the documents *as
# this machine last saw them*, and CI is what says they still match the
# documents as published. That difference is why the flag is not copied here:
# re-fetching forty documents on every local check would buy an answer the
# push already gets.
#
# Document supersession is a WARN and stays one: six of the RFCs this catalogue
# quotes have successors that deleted the thing being linted, which the CI job's
# own comment explains at length.
#
# Reads the documents: the gate that catches a quote nobody read.
quotes:
    #!/usr/bin/env bash
    set -euo pipefail
    apy=.venv/bin/apycite; [ -x "$apy" ] || apy=apycite
    "$apy" verify

# Regenerate docs/rules/ and docs/rules.md from rule metadata — the fixer for the
# `docs_match_generated` and `docs_have_no_orphans` gates. Not part of `check`:
# it writes into the tree, and deletes the pages no rule claims any more.
gendocs:
    cargo xtask gendocs

# Regenerate config_example.toml from rule metadata — the fixer for the
# `config_example_matches_generated` gate. Not part of `check` for the same
# reason as `gendocs`: it writes into the tree.
genconfig:
    cargo xtask genconfig

# Third-party licensing + advisories (needs `reuse` and `cargo-deny` installed).
supply-chain:
    reuse lint
    cargo deny check advisories licenses

# Everything CI rejects a PR for, cheapest checks first so failures surface early
# — which puts `quotes` last, since it is the only one that reads the sources.
check: fmt-check citations lint doc test quotes

# Enable the versioned pre-commit hook (points core.hooksPath at .githooks).
install-hooks:
    git config core.hooksPath .githooks
    @echo "✓ pre-commit hook enabled — formatting + citations checked on every commit."
