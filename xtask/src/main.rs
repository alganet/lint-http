// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Repository maintenance tasks, kept out of the delivered `lint-http` binary.
//!
//! `gendocs` regenerates `docs/rules/<id>.md` and the `docs/rules.md` index from
//! rule metadata, and deletes the pages no rule claims any more (reported on
//! stderr, since deleting quietly is how a file goes missing without a reader
//! ever knowing). `genconfig` regenerates `config_example.toml` from the same
//! metadata. Both are repo tools and not user tools: they write into the
//! working tree, resolved from the workspace root that this crate's manifest
//! dir points at. An installed binary has no such tree, which is why this lives
//! here and not in the CLI.
//!
//! Run them as `cargo xtask gendocs` / `cargo xtask genconfig` (the alias is in
//! `.cargo/config.toml`) or `just gendocs` / `just genconfig`.

use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

mod genconfig;
mod gendocs;

/// The workspace root, derived from this crate's manifest dir. `config_example.toml`
/// and the `docs/` tree live there, so reads and writes are anchored here rather
/// than to the process CWD (which varies between `cargo run` at the root and
/// `cargo test -p`).
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate manifest dir has a parent (the workspace root)")
        .to_path_buf()
}

#[derive(Parser, Debug)]
#[command(name = "xtask", about = "Repository maintenance tasks for lint-http")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Regenerate the rule documentation under the --out directory from rule metadata.
    Gendocs(GendocsArgs),
    /// Regenerate the example configuration file from rule metadata.
    Genconfig(GenconfigArgs),
}

#[derive(clap::Args, Debug)]
struct GendocsArgs {
    /// Output directory; `rules.md` and `rules/<id>.md` are written under it.
    /// Defaults to `docs/` at the workspace root.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
struct GenconfigArgs {
    /// Output file. Defaults to `config_example.toml` at the workspace root.
    #[arg(long)]
    out: Option<PathBuf>,
}

/// Where the docs go when `--out` is not given: the workspace root's `docs/`,
/// not `./docs`.
///
/// The alias passes `--package`, so `cargo xtask gendocs` runs from any
/// subdirectory — and the drift gate's failure message tells people to run
/// exactly that. A relative default would let the suggested fix write 194 files
/// into `lint-http-rules/docs/` and leave the gate red, which is a bad way to
/// find out what your working directory was. The inputs are already anchored to
/// the repo root; the output now agrees with them.
fn resolve_out(out: Option<PathBuf>) -> PathBuf {
    out.unwrap_or_else(|| repo_root().join("docs"))
}

/// Where the example config goes when `--out` is not given, for the same reason
/// [`resolve_out`] gives: the gate reads the workspace root's copy, so the fix
/// it suggests has to write there from wherever it is run.
fn resolve_config_out(out: Option<PathBuf>) -> PathBuf {
    out.unwrap_or_else(|| repo_root().join("config_example.toml"))
}

/// The whole tool, minus argument parsing, so the work is reachable from a test
/// and `main` stays a line the coverage gate does not have to care about.
fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Gendocs(args) => {
            let out = resolve_out(args.out);
            for path in gendocs::write_all(&out)? {
                eprintln!("Removed {} — no rule claims it", path.display());
            }
            eprintln!("Wrote rule docs to {}", out.display());
            Ok(())
        }
        Command::Genconfig(args) => {
            let out = resolve_config_out(args.out);
            genconfig::write(&out)?;
            eprintln!("Wrote example config to {}", out.display());
            Ok(())
        }
    }
}

fn main() -> anyhow::Result<()> {
    run(Cli::parse())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lint_http_rules::rules::{
        PROTOCOL_RULES, REGISTERED_PROTOCOL_RULES, REGISTERED_RULES, RULES,
    };

    /// Cross-crate linkme guard, in this binary's link configuration.
    ///
    /// The rule catalogue self-registers into `linkme` distributed slices over in
    /// `lint-http-rules`; here it arrives across an rlib boundary, where dead-code
    /// elimination or a missing reference could leave the slices empty. That
    /// matters more than it looks: every documentation gate iterates `RULES`, so
    /// an empty catalogue would make them all pass over nothing at all rather
    /// than fail. This test is what stands between that and a green build. The
    /// shipped binary has the same guard in
    /// `lint-http-proxy/tests/linkme_catalogue.rs`.
    #[test]
    fn catalogue_collected_in_xtask_link_config() {
        assert!(
            !REGISTERED_RULES.is_empty(),
            "no transaction rules were collected by linkme in the xtask link config",
        );
        assert!(
            !REGISTERED_PROTOCOL_RULES.is_empty(),
            "no protocol rules were collected by linkme in the xtask link config",
        );

        // Sorted views must agree with the raw registrations.
        assert_eq!(RULES.len(), REGISTERED_RULES.len());
        assert_eq!(PROTOCOL_RULES.len(), REGISTERED_PROTOCOL_RULES.len());

        // Spot-check a known transaction rule and a known protocol rule.
        assert!(RULES.iter().any(|r| r.id() == "host_header"));
        assert!(PROTOCOL_RULES
            .iter()
            .any(|r| r.id() == "quic_transport_parameters_valid"));
    }

    /// One arm per subcommand, so a new one has to be given a place here rather
    /// than silently falling into another's `_ =>`.
    fn gendocs_args(argv: &[&str]) -> Option<PathBuf> {
        match Cli::parse_from(argv).command {
            Command::Gendocs(args) => args.out,
            Command::Genconfig(_) => panic!("expected gendocs"),
        }
    }

    fn genconfig_args(argv: &[&str]) -> Option<PathBuf> {
        match Cli::parse_from(argv).command {
            Command::Genconfig(args) => args.out,
            Command::Gendocs(_) => panic!("expected genconfig"),
        }
    }

    /// The default is absolute, and it is the tree the drift gate reads — not
    /// `./docs`, which is only the same thing when you happen to be standing at
    /// the workspace root.
    #[test]
    fn out_defaults_to_the_workspace_docs_tree() {
        let out = resolve_out(gendocs_args(&["xtask", "gendocs"]));
        assert!(out.is_absolute());
        assert_eq!(out, repo_root().join("docs"));
    }

    #[test]
    fn cli_gendocs_parses_out() {
        assert_eq!(
            resolve_out(gendocs_args(&[
                "xtask",
                "gendocs",
                "--out",
                "/tmp/docs-out"
            ])),
            PathBuf::from("/tmp/docs-out")
        );
    }

    /// Same anchoring argument as the docs tree, and the same failure if it is
    /// wrong: the fixer writes a `config_example.toml` the gate never reads.
    #[test]
    fn config_out_defaults_to_the_workspace_file() {
        let out = resolve_config_out(genconfig_args(&["xtask", "genconfig"]));
        assert!(out.is_absolute());
        assert_eq!(out, repo_root().join("config_example.toml"));
    }

    #[test]
    fn cli_genconfig_parses_out() {
        assert_eq!(
            resolve_config_out(genconfig_args(&[
                "xtask",
                "genconfig",
                "--out",
                "/tmp/config-out.toml"
            ])),
            PathBuf::from("/tmp/config-out.toml")
        );
    }

    /// The CLI end of `genconfig`: the render reaches a file, and that file is
    /// the one the gate would accept.
    #[test]
    fn run_genconfig_writes_the_example_config() {
        let path =
            std::env::temp_dir().join(format!("xtask_genconfig_{}.toml", uuid::Uuid::new_v4()));
        run(Cli::parse_from([
            "xtask",
            "genconfig",
            "--out",
            path.to_str().expect("temp path is utf-8"),
        ]))
        .expect("genconfig should succeed");

        let written = std::fs::read_to_string(&path).expect("read generated config");
        assert_eq!(written, genconfig::render());
        std::fs::remove_file(&path).ok();
    }

    /// The pruning itself is `gendocs`'s to test; what this covers is the CLI
    /// end of it — that the deletion reaches the tree through `run`, and is said
    /// out loud rather than done quietly behind the "Wrote rule docs" line.
    #[test]
    fn run_gendocs_writes_the_index_and_prunes_an_orphan() {
        let dir = std::env::temp_dir().join(format!("xtask_gendocs_{}", uuid::Uuid::new_v4()));
        let gendocs_here = || {
            run(Cli::parse_from([
                "xtask",
                "gendocs",
                "--out",
                dir.to_str().expect("temp path is utf-8"),
            ]))
            .expect("gendocs should succeed");
        };
        gendocs_here();

        assert!(dir.join("rules.md").is_file());
        let first = RULES.first().expect("catalogue is non-empty");
        assert!(dir
            .join("rules")
            .join(format!("{}.md", first.id()))
            .is_file());

        let orphan = dir.join("rules").join("rule_that_was_renamed.md");
        std::fs::write(&orphan, "stale").expect("write orphan");
        gendocs_here();
        assert!(!orphan.exists(), "the orphan should be gone");

        std::fs::remove_dir_all(&dir).ok();
    }
}
