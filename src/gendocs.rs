// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Documentation generator: renders `docs/rules/<id>.md` and the
//! `docs/rules.md` index from rule metadata
//! ([`Rule::description`](crate::rules::Rule::description),
//! [`rfc_references`](crate::rules::Rule::rfc_references),
//! [`examples`](crate::rules::Rule::examples),
//! [`title`](crate::rules::Rule::title)) plus the per-rule `[rules.<id>]`
//! section pulled from `config_example.toml`.
//!
//! The render functions are pure and deterministic so the #11d CI gate
//! (`docs_match_generated` test) can diff regenerated output against the
//! checked-in docs.

use crate::rules::{Compliance, Example, ProtocolRule, Rule};
use std::path::Path;

/// Fixed license header prepended to every generated markdown file. Held
/// constant (rather than stamped with the current date) so regenerated output
/// is byte-for-byte stable.
const SPDX_HEADER: &str = "<!--\nSPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas \
<alganet@gmail.com>\n\nSPDX-License-Identifier: ISC\n-->\n";

/// Index sections, in render order, paired with the id prefix that selects a
/// transaction rule into them. Protocol rules get their own trailing section;
/// anything matching no prefix falls into "Other Rules".
const TX_SECTIONS: &[(&str, &str)] = &[
    ("connection_", "Connection Rules"),
    ("client_", "Client Rules"),
    ("server_", "Server Rules"),
    ("message_", "Message Rules"),
    ("semantic_", "Semantic Rules"),
    ("stateful_", "Stateful Rules"),
];

/// Derive a human-readable title from a snake_case rule id, e.g.
/// `client_user_agent_present` → `"Client User Agent Present"`. A deterministic
/// approximation: it does not reproduce hand-written hyphenation/acronyms
/// (`User-Agent`), which is acceptable for generated scaffolding.
pub fn title_from_id(id: &str) -> String {
    id.split('_')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect::<String>(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render a single per-rule markdown document from its metadata. Sections that
/// have no content (Specifications when `rfc_references` is empty, Examples when
/// `examples` is empty, Configuration when `config_block` is `None`) are omitted
/// entirely. `title` overrides the id-derived heading when `Some`.
pub fn render_doc(
    id: &str,
    title: Option<&str>,
    description: &str,
    rfc_references: &[&str],
    examples: &[Example],
    config_block: Option<&str>,
) -> String {
    let mut out = String::new();
    out.push_str(SPDX_HEADER);
    let title = title
        .map(str::to_string)
        .unwrap_or_else(|| title_from_id(id));
    out.push_str(&format!("\n# {}\n\n", title));

    out.push_str("## Description\n\n");
    if description.trim().is_empty() {
        out.push_str("_No description provided yet._\n");
    } else {
        out.push_str(description.trim_end());
        out.push('\n');
    }

    if !rfc_references.is_empty() {
        out.push_str("\n## Specifications\n\n");
        for reference in rfc_references {
            out.push_str(&format!("- {}\n", reference));
        }
    }

    if let Some(block) = config_block {
        out.push_str(&format!(
            "\n## Configuration\n\n```toml\n{}\n```\n",
            block.trim_end_matches('\n')
        ));
    }

    if !examples.is_empty() {
        out.push_str("\n## Examples\n");
        render_examples(&mut out, examples);
    }

    out
}

/// Append the Examples subsections. Consecutive examples sharing the same
/// compliance *and* label are grouped under one `### ✅ Good` / `### ❌ Bad`
/// heading (with the optional label suffix appended), each snippet its own
/// fenced `http` block — so a heading documenting several related snippets
/// (e.g. two rejected forms) renders as one heading with multiple blocks.
fn render_examples(out: &mut String, examples: &[Example]) {
    let mut prev: Option<(Compliance, Option<&str>)> = None;
    for example in examples {
        let key = (example.compliance, example.label);
        if prev != Some(key) {
            let kind = match example.compliance {
                Compliance::Compliant => "✅ Good",
                Compliance::NonCompliant => "❌ Bad",
            };
            match example.label {
                Some(label) => out.push_str(&format!("\n### {} {}\n", kind, label)),
                None => out.push_str(&format!("\n### {}\n", kind)),
            }
            prev = Some(key);
        }
        out.push_str(&format!(
            "\n```http\n{}\n```\n",
            example.snippet.trim_end_matches('\n')
        ));
    }
}

/// Render the `docs/rules.md` index: transaction rules grouped into
/// fixed-order sections by id prefix, then a Protocol Rules section. Rules keep
/// the catalogue's (id-sorted) order within each section.
pub fn render_index(rules: &[&dyn Rule], protocol_rules: &[&dyn ProtocolRule]) -> String {
    let mut out = String::new();
    out.push_str(SPDX_HEADER);
    out.push_str(
        "\n# Lint Rules\n\nGenerated index of every rule in the catalogue. Each entry links to \
the per-rule documentation under `rules/`. Rules are disabled by default and \
enabled via configuration.\n",
    );

    let mut covered = vec![false; rules.len()];

    for (prefix, title) in TX_SECTIONS {
        let mut section = String::new();
        for (idx, rule) in rules.iter().enumerate() {
            if !covered[idx] && rule.id().starts_with(prefix) {
                covered[idx] = true;
                section.push_str(&index_entry(rule.id(), rule.description()));
            }
        }
        if !section.is_empty() {
            out.push_str(&format!("\n## {}\n\n", title));
            out.push_str(&section);
        }
    }

    // Transaction rules whose id matched no known prefix.
    let mut other = String::new();
    for (idx, rule) in rules.iter().enumerate() {
        if !covered[idx] {
            other.push_str(&index_entry(rule.id(), rule.description()));
        }
    }
    if !other.is_empty() {
        out.push_str("\n## Other Rules\n\n");
        out.push_str(&other);
    }

    if !protocol_rules.is_empty() {
        out.push_str("\n## Protocol Rules\n\n");
        for rule in protocol_rules {
            out.push_str(&index_entry(rule.id(), rule.description()));
        }
    }

    out
}

/// One index bullet: `- [id](rules/id.md) — <summary>`. The summary is the
/// first non-empty line of the description, falling back to the derived title.
fn index_entry(id: &str, description: &str) -> String {
    let summary = description
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| title_from_id(id));
    format!("- [{0}](rules/{0}.md) — {1}\n", id, summary)
}

/// Extract the `[rules.<id>]` TOML block from `config_example.toml` contents:
/// the section header line and every following line up to (excluding) the next
/// `[` section header or end of file, with trailing blank lines trimmed.
/// Returns `None` if the section is absent. `config_example.toml` is the single
/// source of truth for the generated `## Configuration` section, so a rule's
/// configurable keys are documented in exactly one place.
pub fn config_block_for(id: &str, config_toml: &str) -> Option<String> {
    let header = format!("[rules.{}]", id);
    let mut lines = config_toml.lines();
    lines.by_ref().find(|line| line.trim() == header)?;

    let mut block = header;
    for line in lines {
        if line.trim_start().starts_with('[') {
            break;
        }
        block.push('\n');
        block.push_str(line);
    }
    Some(block.trim_end().to_string())
}

/// Render every rule to disk under `out_dir`: `<out_dir>/rules/<id>.md` per
/// rule plus `<out_dir>/rules.md`. Configuration sections are sourced from
/// `config_example.toml` (read from the current working directory — the repo
/// root). Creates directories as needed.
pub fn write_all(out_dir: &Path) -> anyhow::Result<()> {
    let rules_dir = out_dir.join("rules");
    std::fs::create_dir_all(&rules_dir)?;

    let config_toml = std::fs::read_to_string("config_example.toml")?;

    for rule in crate::rules::RULES.iter() {
        let doc = render_doc(
            rule.id(),
            rule.title(),
            rule.description(),
            rule.rfc_references(),
            rule.examples(),
            config_block_for(rule.id(), &config_toml).as_deref(),
        );
        std::fs::write(rules_dir.join(format!("{}.md", rule.id())), doc)?;
    }
    for rule in crate::rules::PROTOCOL_RULES.iter() {
        let doc = render_doc(
            rule.id(),
            rule.title(),
            rule.description(),
            rule.rfc_references(),
            rule.examples(),
            config_block_for(rule.id(), &config_toml).as_deref(),
        );
        std::fs::write(rules_dir.join(format!("{}.md", rule.id())), doc)?;
    }

    let index = render_index(&crate::rules::RULES, &crate::rules::PROTOCOL_RULES);
    std::fs::write(out_dir.join("rules.md"), index)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn title_from_id_capitalizes_each_word() {
        assert_eq!(
            title_from_id("client_user_agent_present"),
            "Client User Agent Present"
        );
        assert_eq!(title_from_id("connection_id"), "Connection Id");
        assert_eq!(title_from_id("single"), "Single");
    }

    #[test]
    fn render_doc_includes_all_sections_when_metadata_present() {
        let examples = [
            Example {
                compliance: Compliance::Compliant,
                label: Some("Request"),
                snippet: "GET / HTTP/1.1\nHost: example.com\nUser-Agent: x/1.0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                label: None,
                snippet: "GET / HTTP/1.1\nHost: example.com",
            },
        ];
        let doc = render_doc(
            "client_user_agent_present",
            Some("Client User-Agent Present"),
            "Requests should carry a User-Agent header.",
            &["RFC 9110 §10.1.5", "RFC 9110 §5.5"],
            &examples,
            Some("[rules.client_user_agent_present]\nenabled = true\nseverity = \"warn\""),
        );

        assert!(doc.starts_with("<!--\nSPDX-FileCopyrightText"));
        // `title` override preserves header casing the id can't reproduce.
        assert!(doc.contains("# Client User-Agent Present"));
        assert!(doc.contains("## Description\n\nRequests should carry a User-Agent header."));
        assert!(doc.contains("## Specifications\n\n- RFC 9110 §10.1.5\n- RFC 9110 §5.5\n"));
        assert!(doc.contains(
            "## Configuration\n\n```toml\n[rules.client_user_agent_present]\nenabled = true\n\
             severity = \"warn\"\n```"
        ));
        assert!(doc.contains("### ✅ Good Request"));
        assert!(doc.contains("### ❌ Bad\n"));
        assert!(doc.contains("```http\nGET / HTTP/1.1\nHost: example.com\nUser-Agent: x/1.0\n```"));
    }

    #[test]
    fn render_doc_derives_title_and_omits_empty_sections() {
        // No title override → derived from id; no rfc/config/examples → those
        // sections are omitted.
        let doc = render_doc("server_some_rule", None, "", &[], &[], None);

        assert!(doc.contains("# Server Some Rule"));
        assert!(doc.contains("## Description\n\n_No description provided yet._"));
        assert!(!doc.contains("## Specifications"));
        assert!(!doc.contains("## Configuration"));
        assert!(!doc.contains("## Examples"));
    }

    #[test]
    fn render_doc_for_whole_catalogue_is_nonempty_and_well_formed() {
        // Render every rule in-memory; must not touch the real docs/ tree.
        let config_toml =
            std::fs::read_to_string("config_example.toml").expect("config_example.toml");
        let render = |id: &str, title, desc, refs: &[&str], ex: &[Example]| {
            render_doc(
                id,
                title,
                desc,
                refs,
                ex,
                config_block_for(id, &config_toml).as_deref(),
            )
        };
        for rule in crate::rules::RULES.iter() {
            let doc = render(
                rule.id(),
                rule.title(),
                rule.description(),
                rule.rfc_references(),
                rule.examples(),
            );
            assert!(
                doc.starts_with(SPDX_HEADER),
                "{} missing SPDX header",
                rule.id()
            );
            assert!(
                doc.contains("## Description"),
                "{} missing Description",
                rule.id()
            );
        }
        for rule in crate::rules::PROTOCOL_RULES.iter() {
            let doc = render(
                rule.id(),
                rule.title(),
                rule.description(),
                rule.rfc_references(),
                rule.examples(),
            );
            assert!(
                doc.starts_with(SPDX_HEADER),
                "{} missing SPDX header",
                rule.id()
            );
        }
    }

    #[test]
    fn config_block_for_extracts_section_and_stops_at_next() {
        let toml = "[rules.a]\nenabled = true\nseverity = \"warn\"\nallowed = [\"x\"]\n\n\
                    [rules.b]\nenabled = false\n";
        assert_eq!(
            config_block_for("a", toml).as_deref(),
            Some("[rules.a]\nenabled = true\nseverity = \"warn\"\nallowed = [\"x\"]")
        );
        assert_eq!(
            config_block_for("b", toml).as_deref(),
            Some("[rules.b]\nenabled = false")
        );
        assert_eq!(config_block_for("missing", toml), None);
    }

    #[test]
    fn render_index_mentions_every_rule() {
        let index = render_index(&crate::rules::RULES, &crate::rules::PROTOCOL_RULES);
        assert!(index.contains("# Lint Rules"));
        for rule in crate::rules::RULES.iter() {
            assert!(
                index.contains(&format!("[{0}](rules/{0}.md)", rule.id())),
                "index missing {}",
                rule.id()
            );
        }
        for rule in crate::rules::PROTOCOL_RULES.iter() {
            assert!(
                index.contains(&format!("[{0}](rules/{0}.md)", rule.id())),
                "index missing protocol rule {}",
                rule.id()
            );
        }
    }

    #[test]
    fn write_all_creates_files_in_temp_dir() {
        let dir = std::env::temp_dir().join(format!("gendocs_test_{}", uuid::Uuid::new_v4()));
        write_all(&dir).expect("write_all should succeed");

        assert!(dir.join("rules.md").is_file());
        let first = crate::rules::RULES.first().expect("catalogue is non-empty");
        assert!(dir
            .join("rules")
            .join(format!("{}.md", first.id()))
            .is_file());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// #11d drift gate: the committed `docs/rules/` files must equal what
    /// `gendocs` regenerates from rule metadata. This makes the docs a verified
    /// generated artifact — editing a rule (or `config_example.toml`) without
    /// regenerating fails CI. Run `cargo run --bin gendocs` to fix drift.
    #[test]
    fn docs_match_generated() {
        let config_toml =
            std::fs::read_to_string("config_example.toml").expect("config_example.toml");
        let check = |id: &str, expected: String| {
            let path = format!("docs/rules/{}.md", id);
            let on_disk = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {}", path, e));
            assert!(
                on_disk == expected,
                "docs/rules/{}.md is out of date — run `cargo run --bin gendocs`",
                id
            );
        };
        for rule in crate::rules::RULES.iter() {
            check(
                rule.id(),
                render_doc(
                    rule.id(),
                    rule.title(),
                    rule.description(),
                    rule.rfc_references(),
                    rule.examples(),
                    config_block_for(rule.id(), &config_toml).as_deref(),
                ),
            );
        }
        for rule in crate::rules::PROTOCOL_RULES.iter() {
            check(
                rule.id(),
                render_doc(
                    rule.id(),
                    rule.title(),
                    rule.description(),
                    rule.rfc_references(),
                    rule.examples(),
                    config_block_for(rule.id(), &config_toml).as_deref(),
                ),
            );
        }
        let index = render_index(&crate::rules::RULES, &crate::rules::PROTOCOL_RULES);
        let on_disk = std::fs::read_to_string("docs/rules.md").expect("docs/rules.md");
        assert!(
            on_disk == index,
            "docs/rules.md is out of date — run `cargo run --bin gendocs`"
        );
    }
}
