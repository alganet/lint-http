// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Documentation generator: renders `docs/rules/<id>.md` and the
//! `docs/rules.md` index from rule metadata
//! ([`Rule::description`](crate::rules::Rule::description),
//! [`rfc_reference`](crate::rules::Rule::rfc_reference),
//! [`examples`](crate::rules::Rule::examples)).
//!
//! The render functions are pure and deterministic so a future CI gate (#11d)
//! can diff regenerated output against the checked-in docs. While rules still
//! use the empty metadata defaults the output is intentionally sparse; #11c
//! fills the metadata in.

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
/// have no content (Specifications when `rfc_reference` is `None`, Examples
/// when `examples` is empty) are omitted entirely.
pub fn render_doc(
    id: &str,
    description: &str,
    rfc_reference: Option<&str>,
    examples: &[Example],
) -> String {
    let mut out = String::new();
    out.push_str(SPDX_HEADER);
    out.push_str(&format!("\n# {}\n\n", title_from_id(id)));

    out.push_str("## Description\n\n");
    if description.trim().is_empty() {
        out.push_str("_No description provided yet._\n");
    } else {
        out.push_str(description.trim_end());
        out.push('\n');
    }

    if let Some(reference) = rfc_reference {
        out.push_str(&format!("\n## Specifications\n\n- {}\n", reference));
    }

    if !examples.is_empty() {
        out.push_str("\n## Examples\n");
        render_examples(&mut out, examples, Compliance::Compliant, "### ✅ Good");
        render_examples(&mut out, examples, Compliance::NonCompliant, "### ❌ Bad");
    }

    out
}

/// Append the subsection for one compliance class, if any matching examples
/// exist. Each snippet becomes its own fenced `http` block.
fn render_examples(out: &mut String, examples: &[Example], want: Compliance, heading: &str) {
    let matching = examples.iter().filter(|e| e.compliance == want);
    let mut any = false;
    for example in matching {
        if !any {
            out.push_str(&format!("\n{}\n", heading));
            any = true;
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

/// Render every rule to disk under `out_dir`: `<out_dir>/rules/<id>.md` per
/// rule plus `<out_dir>/rules.md`. Creates directories as needed.
pub fn write_all(out_dir: &Path) -> anyhow::Result<()> {
    let rules_dir = out_dir.join("rules");
    std::fs::create_dir_all(&rules_dir)?;

    for rule in crate::rules::RULES.iter() {
        let doc = render_doc(
            rule.id(),
            rule.description(),
            rule.rfc_reference(),
            rule.examples(),
        );
        std::fs::write(rules_dir.join(format!("{}.md", rule.id())), doc)?;
    }
    for rule in crate::rules::PROTOCOL_RULES.iter() {
        let doc = render_doc(
            rule.id(),
            rule.description(),
            rule.rfc_reference(),
            rule.examples(),
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
                snippet: "GET / HTTP/1.1\nHost: example.com\nUser-Agent: x/1.0",
            },
            Example {
                compliance: Compliance::NonCompliant,
                snippet: "GET / HTTP/1.1\nHost: example.com",
            },
        ];
        let doc = render_doc(
            "client_user_agent_present",
            "Requests should carry a User-Agent header.",
            Some("RFC 9110 §10.1.5"),
            &examples,
        );

        assert!(doc.starts_with("<!--\nSPDX-FileCopyrightText"));
        assert!(doc.contains("# Client User Agent Present"));
        assert!(doc.contains("## Description\n\nRequests should carry a User-Agent header."));
        assert!(doc.contains("## Specifications\n\n- RFC 9110 §10.1.5"));
        assert!(doc.contains("### ✅ Good"));
        assert!(doc.contains("### ❌ Bad"));
        assert!(doc.contains("```http\nGET / HTTP/1.1\nHost: example.com\nUser-Agent: x/1.0\n```"));
    }

    #[test]
    fn render_doc_omits_empty_sections_for_default_metadata() {
        // Mirrors the current near-empty state: empty description, no rfc, no
        // examples (the #11a defaults).
        let doc = render_doc("server_some_rule", "", None, &[]);

        assert!(doc.contains("# Server Some Rule"));
        assert!(doc.contains("## Description\n\n_No description provided yet._"));
        assert!(!doc.contains("## Specifications"));
        assert!(!doc.contains("## Examples"));
    }

    #[test]
    fn render_doc_for_whole_catalogue_is_nonempty_and_well_formed() {
        // Render every rule in-memory; must not touch the real docs/ tree.
        for rule in crate::rules::RULES.iter() {
            let doc = render_doc(
                rule.id(),
                rule.description(),
                rule.rfc_reference(),
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
            let doc = render_doc(
                rule.id(),
                rule.description(),
                rule.rfc_reference(),
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
}
