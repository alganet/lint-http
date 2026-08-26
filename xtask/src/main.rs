// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Repository maintenance tasks, kept out of the delivered `lint-http` binary.
//!
//! `gendocs` regenerates `docs/rules/<id>.md` and the `docs/rules.md` index from
//! rule metadata. It is a repo tool and not a user tool: it reads
//! `config_example.toml` and writes into the working tree, both resolved from
//! the workspace root that this crate's manifest dir points at. An installed
//! binary has no such tree, which is why this lives here and not in the CLI.
//!
//! Run it as `cargo xtask gendocs` (the alias is in `.cargo/config.toml`) or
//! `just gendocs`.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "xtask", about = "Repository maintenance tasks for lint-http")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Regenerate the rule documentation under <out>/ from rule metadata.
    Gendocs(GendocsArgs),
}

#[derive(clap::Args, Debug)]
struct GendocsArgs {
    /// Output directory; `rules.md` and `rules/<id>.md` are written under it.
    #[arg(long, default_value = "docs")]
    out: PathBuf,
}

/// The whole tool, minus argument parsing, so the work is reachable from a test
/// and `main` stays a line the coverage gate does not have to care about.
fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Gendocs(args) => {
            lint_http_rules::gendocs::write_all(&args.out)?;
            eprintln!("Wrote rule docs to {}", args.out.display());
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

    #[test]
    fn cli_gendocs_defaults_out_to_docs() {
        let cli = Cli::parse_from(["xtask", "gendocs"]);
        let Command::Gendocs(args) = cli.command;
        assert_eq!(args.out, PathBuf::from("docs"));
    }

    #[test]
    fn cli_gendocs_parses_out() {
        let cli = Cli::parse_from(["xtask", "gendocs", "--out", "/tmp/docs-out"]);
        let Command::Gendocs(args) = cli.command;
        assert_eq!(args.out, PathBuf::from("/tmp/docs-out"));
    }

    #[test]
    fn run_gendocs_writes_the_index_and_a_rule_page() {
        let dir = std::env::temp_dir().join(format!("xtask_gendocs_{}", uuid::Uuid::new_v4()));
        run(Cli::parse_from([
            "xtask",
            "gendocs",
            "--out",
            dir.to_str().expect("temp path is utf-8"),
        ]))
        .expect("gendocs should succeed");

        assert!(dir.join("rules.md").is_file());
        let first = RULES.first().expect("catalogue is non-empty");
        assert!(dir
            .join("rules")
            .join(format!("{}.md", first.id()))
            .is_file());

        std::fs::remove_dir_all(&dir).ok();
    }
}
