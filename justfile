# SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
#
# SPDX-License-Identifier: ISC

# Local mirror of the CI gates, in two tiers. `just check` is the fast one, run
# constantly; `just check-all` adds the four slow gates it leaves out, and is
# what to run before pushing. Each recipe's own comment says which CI job it
# mirrors and where it stops short. `just fmt` fixes the formatting that
# `cargo fmt` alone cannot reach. Run bare `just` to list recipes. Enable the
# commit-time guard once with `just install-hooks`.
#
# **Two CI answers no local recipe can give**, and naming them is the point of
# saying "mirror" at all: the `build` job compiles on macOS and Windows as well
# as Linux, and the nightly `verify` job re-fetches every cited document from
# the network. One machine has one OS, and `quotes` reads the cache on purpose
# — see its comment. Everything else CI rejects a PR for is reachable from here.

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
#
# Rustdoc builds clean, warnings as errors.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

# Workspace tests with all features.
test:
    cargo test --workspace --all-features

# Build .venv from the pinned citation toolchain. The pin lives in
# specs/requirements.txt because the bytes of specs/specs_generated.yaml depend
# on it; a .venv built by hand is how a local `extract` and CI's disagree about a
# file neither of them edited.
#
# One-time setup: build .venv from specs/requirements.txt.
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
#
# Offline: the citations file is current and the ratchet holds.
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
#
# Writes the tree: regenerate docs/rules/ and docs/rules.md.
gendocs:
    cargo xtask gendocs

# Regenerate config_example.toml from rule metadata — the fixer for the
# `config_example_matches_generated` gate. Not part of `check` for the same
# reason as `gendocs`: it writes into the tree.
#
# Writes the tree: regenerate config_example.toml.
genconfig:
    cargo xtask genconfig

# The workspace still builds on the oldest Rust it claims to support.
#
# The version is read out of the workspace manifest rather than written here,
# because a floor spelled in two places is a floor that drifts — which is the
# same argument `rust-version`'s own comment makes for having the job at all.
# The CI job pins `dtolnay/rust-toolchain@1.94` literally and is the one copy
# left; if this recipe and that job ever disagree, the manifest is right.
#
# `cargo check`, not `cargo build`: this asks whether the code *compiles* on
# that floor, and the stable jobs already own whether it links and runs.
#
# Slow gate: the workspace compiles on the Rust the manifest declares.
msrv:
    #!/usr/bin/env bash
    set -euo pipefail
    v=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml | head -1)
    [ -n "$v" ] || { echo "could not read rust-version from Cargo.toml" >&2; exit 1; }
    # Probe by *resolving* the toolchain, not by string-matching the installed
    # list: `rustup toolchain list` prints whatever spelling it was installed
    # under, so a tree declaring 1.94 against an installed `1.94.0` reads as
    # missing when it is right there. `rustup run` resolves the name the same
    # way `cargo +$v` is about to, which makes this probe agree with the
    # command it is guarding by construction.
    rustup run "$v" rustc --version >/dev/null 2>&1 || {
        echo "toolchain $v is not usable — run: rustup toolchain install $v" >&2
        exit 1
    }
    echo "checking against the declared minimum: $v"
    cargo "+$v" check --workspace --all-targets --all-features

# First- and third-party supply chain, exactly as the CI job runs it.
#
# Three questions, not two, and the third was missing here long enough to be
# worth naming: `reuse` asks whether our own files carry their SPDX metadata,
# `cargo deny` asks about the licences and advisories of the tree we pull, and
# `cargo machete` asks whether we *declared* what we pull — a manifest may only
# name what the code reads.
#
# Needs three tools CI installs for itself. To match it locally:
#   pipx install reuse && cargo install cargo-deny cargo-machete
#
# Slow gate: SPDX metadata, dependency licences and advisories, unused deps.
supply-chain:
    reuse lint
    cargo deny check advisories licenses
    cargo machete

# Coverage under the 95% floor in `.cargo/config.toml` (the `cargo coverage`
# alias). Kept out of `check` and slow enough (~15 min) to plan around.
#
# **Do not edit source while this runs.** Tarpaulin reads the tree as it goes,
# so a save mid-run produces a report of a tree that never existed.
#
# Slow gate (~15 min): coverage against the 95% floor. Do not edit while it runs.
coverage:
    cargo coverage

# Release build, this platform only.
#
# The CI job runs the same command across ubuntu, macOS and windows; one machine
# can answer for one of them, and this is that one. It is also the only gate
# that compiles in release mode — `test` and `lint` are debug — so it is where a
# `debug_assert`-shaped assumption or an optimisation-only warning surfaces.
#
# Slow gate: release build for this platform (CI also does macOS and Windows).
build:
    cargo build --workspace --release

# Everything CI rejects a PR for that this machine can answer, cheapest checks
# first so failures surface early — which puts `quotes` last, since it is the
# only one that reads the sources.
#
# **This is the fast tier, and it is not all of CI.** It omits `msrv`,
# `supply-chain`, `coverage` and `build` — the four slow ones — each of which is
# its own recipe above and all of which `check-all` runs. That omission is a
# choice about how often this is run, not a claim that the four do not matter:
# this one is cheap enough to sit behind every commit, and a fifteen-minute
# coverage run is not.
#
# The fast tier: run this constantly. `check-all` is the one to run before pushing.
check: fmt-check citations lint doc test quotes

# Every gate `check` skips, after `check` itself. Run this before pushing.
#
# Ordered by cost again, so the four extra failures also surface cheapest-first.
# What is still left over after this is only what one machine cannot do: the
# macOS and Windows legs of `build`, and the nightly `verify` refresh. Both are
# named at the top of this file.
#
# The full tier: `check` plus the four slow gates. Run before pushing.
check-all: check msrv supply-chain build coverage

# Enable the versioned pre-commit hook (points core.hooksPath at .githooks).
install-hooks:
    git config core.hooksPath .githooks
    @echo "✓ pre-commit hook enabled — formatting + citations checked on every commit."
