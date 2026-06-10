// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! `gendocs` regenerates the per-rule documentation under `docs/rules/` and the
//! `docs/rules.md` index from rule metadata. See [`lint_http::gendocs`].

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "gendocs",
    about = "Generate rule documentation from rule metadata"
)]
struct Args {
    /// Output directory; `rules.md` and `rules/<id>.md` are written under it.
    #[arg(long, default_value = "docs")]
    out: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    lint_http::gendocs::write_all(&args.out)?;
    eprintln!("Wrote rule docs to {}", args.out.display());
    Ok(())
}
