// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Documentation generator: renders `docs/rules/<id>.md` and the
//! `docs/rules.md` index from rule metadata
//! ([`Rule::description`](lint_http_rules::rules::Rule::description),
//! [`specifications`](lint_http_rules::rules::Rule::specifications),
//! [`examples`](lint_http_rules::rules::Rule::examples),
//! [`title`](lint_http_rules::rules::Rule::title)) plus the per-rule
//! `[rules.<id>]` section pulled from `config_example.toml`.
//!
//! The render functions are pure and deterministic so the #11d CI gate
//! (`docs_match_generated` test) can diff regenerated output against the
//! checked-in docs.

use lint_http_rules::rules::{
    Compliance, Example, ProtocolRule, Rule, RuleScope, SpecRef, PROTOCOL_RULES, RULES,
};
use std::path::{Path, PathBuf};

/// The workspace root, derived from this crate's manifest dir. `config_example.toml`
/// and the `docs/` tree live there, so reads are anchored here rather than to the
/// process CWD (which varies between `cargo run` at the root and `cargo test -p`).
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate manifest dir has a parent (the workspace root)")
        .to_path_buf()
}

/// Fixed license header prepended to every generated markdown file. Held
/// constant (rather than stamped with the current date) so regenerated output
/// is byte-for-byte stable.
///
/// The literal embeds an SPDX tag for the *generated* files; the
/// `REUSE-IgnoreStart`/`REUSE-IgnoreEnd` markers stop `reuse lint` from reading
/// it as a (malformed) license tag for this source file, whose own header is
/// the ISC tag at the top.
// REUSE-IgnoreStart
const SPDX_HEADER: &str = "<!--\nSPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas \
<alganet@gmail.com>\n\nSPDX-License-Identifier: ISC\n-->\n";
// REUSE-IgnoreEnd

/// The transaction-rule sections of the index, in render order. Protocol rules
/// have no scope and get their own trailing section.
///
/// Selection used to be `id().starts_with("client_")` and friends, which made
/// the id string load-bearing for one generated file and was the last reason the
/// category prefixes existed. Scope is metadata the rule already declares and
/// the engine already partitions by, so the index now groups rules the way they
/// are dispatched. Titles come from [`section_title`], whose match the compiler
/// checks; that a scope is not merely titled but actually *listed* here is what
/// `render_index_mentions_every_rule` checks, since omitting one would silently
/// drop its rules from the index.
const TX_SECTION_ORDER: &[RuleScope] = &[RuleScope::Client, RuleScope::Server, RuleScope::Both];

/// Heading for a transaction-rule section. Exhaustive over [`RuleScope`], so a
/// new variant fails to compile until it is given a heading here and a place in
/// [`TX_SECTION_ORDER`].
fn section_title(scope: RuleScope) -> &'static str {
    match scope {
        RuleScope::Client => "Client Rules",
        RuleScope::Server => "Server Rules",
        RuleScope::Both => "Client and Server Rules",
    }
}

/// Derive a human-readable title from a snake_case rule id, e.g.
/// `user_agent_present` → `"User Agent Present"`. A deterministic
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
/// have no content (Specifications when `specifications` is empty, Examples when
/// `examples` is empty, Configuration when `config_block` is `None`) are omitted
/// entirely. `title` overrides the id-derived heading when `Some`.
pub fn render_doc(
    id: &str,
    title: Option<&str>,
    description: &str,
    specifications: &[SpecRef],
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

    if !specifications.is_empty() {
        out.push_str("\n## Specifications\n\n");
        for spec in specifications {
            out.push_str(&format!("- {}\n", spec));
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
/// fixed-order sections by [`Rule::scope`], then a Protocol Rules section. Rules
/// keep the catalogue's (id-sorted) order within each section.
pub fn render_index(rules: &[&dyn Rule], protocol_rules: &[&dyn ProtocolRule]) -> String {
    let mut out = String::new();
    out.push_str(SPDX_HEADER);
    out.push_str(
        "\n# Lint Rules\n\nGenerated index of every rule in the catalogue. Each entry links to \
the per-rule documentation under `rules/`. Rules are disabled by default and \
enabled via configuration.\n",
    );

    for scope in TX_SECTION_ORDER {
        let mut section = String::new();
        for rule in rules.iter() {
            if rule.scope() == *scope {
                section.push_str(&index_entry(rule.id(), rule.description()));
            }
        }
        if !section.is_empty() {
            out.push_str(&format!("\n## {}\n\n", section_title(*scope)));
            out.push_str(&section);
        }
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
/// [`repo_root`]`/config_example.toml`, never from the working directory.
/// Creates directories as needed.
pub fn write_all(out_dir: &Path) -> anyhow::Result<()> {
    let rules_dir = out_dir.join("rules");
    std::fs::create_dir_all(&rules_dir)?;

    let config_toml = std::fs::read_to_string(repo_root().join("config_example.toml"))?;

    for rule in RULES.iter() {
        let doc = render_doc(
            rule.id(),
            rule.title(),
            rule.description(),
            rule.specifications(),
            rule.examples(),
            config_block_for(rule.id(), &config_toml).as_deref(),
        );
        std::fs::write(rules_dir.join(format!("{}.md", rule.id())), doc)?;
    }
    for rule in PROTOCOL_RULES.iter() {
        let doc = render_doc(
            rule.id(),
            rule.title(),
            rule.description(),
            rule.specifications(),
            rule.examples(),
            config_block_for(rule.id(), &config_toml).as_deref(),
        );
        std::fs::write(rules_dir.join(format!("{}.md", rule.id())), doc)?;
    }

    let index = render_index(&RULES, &PROTOCOL_RULES);
    std::fs::write(out_dir.join("rules.md"), index)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lint_http_rules::rules::REGISTERED_RULES;

    #[test]
    fn title_from_id_capitalizes_each_word() {
        assert_eq!(title_from_id("user_agent_present"), "User Agent Present");
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
            "user_agent_present",
            Some("User-Agent Present"),
            "Requests should carry a User-Agent header.",
            &[
                SpecRef {
                    spec: "RFC 9110",
                    section: Some("10.1.5"),
                    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5",
                    note: "User-Agent",
                },
                SpecRef {
                    spec: "RFC 9110",
                    section: Some("5.5"),
                    url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5",
                    note: "",
                },
            ],
            &examples,
            Some("[rules.user_agent_present]\nenabled = true\nseverity = \"warn\""),
        );

        assert!(doc.starts_with("<!--\nSPDX-FileCopyrightText"));
        // `title` override preserves header casing the id can't reproduce.
        assert!(doc.contains("# User-Agent Present"));
        assert!(doc.contains("## Description\n\nRequests should carry a User-Agent header."));
        // The bullet is *derived* from the fields now, not stored as prose — which
        // is what ended the five spellings. Both arms of `Display` are pinned here:
        // a note renders after a colon, and an empty note renders no colon at all.
        assert!(doc.contains(
            "## Specifications\n\n\
             - [RFC 9110 §10.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5): User-Agent\n\
             - [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5)\n"
        ));
        assert!(doc.contains(
            "## Configuration\n\n```toml\n[rules.user_agent_present]\nenabled = true\n\
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
        let config_toml = std::fs::read_to_string(repo_root().join("config_example.toml"))
            .expect("config_example.toml");
        let render = |id: &str, title, desc, refs: &[SpecRef], ex: &[Example]| {
            render_doc(
                id,
                title,
                desc,
                refs,
                ex,
                config_block_for(id, &config_toml).as_deref(),
            )
        };
        for rule in RULES.iter() {
            let doc = render(
                rule.id(),
                rule.title(),
                rule.description(),
                rule.specifications(),
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
        for rule in PROTOCOL_RULES.iter() {
            let doc = render(
                rule.id(),
                rule.title(),
                rule.description(),
                rule.specifications(),
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

    /// Also the guard on `TX_SECTION_ORDER`: sections are selected by scope, so a
    /// scope left out of that list would drop its rules from the index entirely,
    /// and one listed twice would print them twice. Counting the links catches
    /// both, which a `contains` check on its own would not.
    #[test]
    fn render_index_mentions_every_rule() {
        let index = render_index(&RULES, &PROTOCOL_RULES);
        assert!(index.contains("# Lint Rules"));
        for rule in RULES.iter() {
            assert_eq!(
                index
                    .matches(&format!("[{0}](rules/{0}.md)", rule.id()))
                    .count(),
                1,
                "index should link {} exactly once",
                rule.id()
            );
        }
        for rule in PROTOCOL_RULES.iter() {
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
        let first = RULES.first().expect("catalogue is non-empty");
        assert!(dir
            .join("rules")
            .join(format!("{}.md", first.id()))
            .is_file());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Every `SpecRef` must name a document `specs/sources.yaml` knows, at the
    /// URL that file calls canonical. Without this, the two halves of a reference
    /// drift apart silently: a rule can point at a host the registry retired, and
    /// nothing notices, because `apycite` only ever fetches what a `// cite`
    /// quotes — never the reference list.
    ///
    /// RFCs are absent from the registry by design: apysource ships a repository
    /// that claims rfc-editor and declares the `RFC NNNN` name family, so they are
    /// checked against that repository's canonical URL instead. Until apysource
    /// 0.9.0 this assertion was a convention with nothing behind it — the docs
    /// linked `.html` while every quote was verified against `.txt`. It is now the
    /// claim that the URL a reader clicks is the URL the verifier read.
    ///
    /// This deliberately does *not* read `specs/specs_generated.yaml`, which
    /// carries the exact URL apysource minted for every cited document and would
    /// kill the literal below. Twenty-four declared `SpecRef`s are never `// cite`d
    /// — including RFC 2978 and RFC 7034 — so they have no block in that file, and
    /// a lookup would need a silent skip for them. A silent skip is how the drift
    /// gets back in.
    #[test]
    fn spec_refs_use_the_source_registry() {
        let registry = std::fs::read_to_string(repo_root().join("specs/sources.yaml"))
            .expect("specs/sources.yaml");
        // A two-line scan, not a YAML parse: the registry is a flat list of
        // `- label:` / `url:` pairs, and a dependency to read two keys would cost
        // more than it explains.
        let mut canonical: Vec<(&str, &str)> = Vec::new();
        let mut lines = registry.lines().peekable();
        while let Some(line) = lines.next() {
            if let Some(label) = line.trim().strip_prefix("- label: ") {
                let url = lines
                    .peek()
                    .and_then(|l| l.trim().strip_prefix("url: "))
                    .unwrap_or_else(|| {
                        panic!(
                            "registry entry {} has no url on the line immediately after \
                             it. This is a line scan, not a YAML parse: keep `url:` \
                             directly under `- label:`, comments above the entry",
                            label
                        )
                    });
                canonical.push((label, url));
            }
        }
        assert!(
            !canonical.is_empty(),
            "read no entries from specs/sources.yaml"
        );

        fn base(url: &str) -> &str {
            url.split('#').next().unwrap_or(url).trim_end_matches('/')
        }
        let check = |id: &str, specs: &[SpecRef]| {
            for s in specs {
                assert!(!s.url.is_empty(), "{}: {} has no url", id, s.spec);
                match s.spec.strip_prefix("RFC ") {
                    // What keeps rfc-editor / datatracker from splitting one RFC
                    // across two hosts again — and, since 0.9.0, what keeps the
                    // link and the verified document from being two documents.
                    Some(number) => {
                        let expected = format!("https://www.rfc-editor.org/rfc/rfc{}.html", number);
                        assert_eq!(
                            base(s.url),
                            expected,
                            "{}: {} must cite {} (canonical), not {}",
                            id,
                            s.spec,
                            expected,
                            s.url
                        );
                    }
                    None => {
                        let entry = canonical.iter().find(|(label, _)| *label == s.spec);
                        let (_, url) = entry.unwrap_or_else(|| {
                            panic!(
                                "{}: {:?} is not a label in specs/sources.yaml — add it there, \
                                 or spell it the way the registry does",
                                id, s.spec
                            )
                        });
                        assert_eq!(
                            base(s.url),
                            base(url),
                            "{}: {} points at {}, but the registry calls {} canonical",
                            id,
                            s.spec,
                            s.url,
                            url
                        );
                    }
                }
            }
        };
        for rule in RULES.iter() {
            check(rule.id(), rule.specifications());
        }
        for rule in PROTOCOL_RULES.iter() {
            check(rule.id(), rule.specifications());
        }
    }

    /// No reference points at a rendition nobody reads.
    ///
    /// `.txt` was the whole story here until apysource 0.9.0: every quote was
    /// verified against rfc-editor's text rendition while every link in the docs
    /// pointed at the HTML. Nothing is fetched as `.txt` any more, and a URL that
    /// reappears with that extension is a reference that has quietly gone back to
    /// naming a document the verifier never opens.
    #[test]
    fn no_spec_ref_names_a_text_rendition() {
        let check = |id: &str, specs: &[SpecRef]| {
            for s in specs {
                assert!(
                    !s.url.split('#').next().unwrap_or(s.url).ends_with(".txt"),
                    "{}: {} points at {} — the verified document is the HTML rendition",
                    id,
                    s.spec,
                    s.url
                );
            }
        };
        for rule in RULES.iter() {
            check(rule.id(), rule.specifications());
        }
        for rule in PROTOCOL_RULES.iter() {
            check(rule.id(), rule.specifications());
        }
    }

    /// #11d drift gate: the committed `docs/rules/` files must equal what
    /// `gendocs` regenerates from rule metadata. This makes the docs a verified
    /// generated artifact — editing a rule (or `config_example.toml`) without
    /// regenerating fails CI. Run `cargo xtask gendocs` to fix drift.
    ///
    /// The gate is a loop over `RULES`, so an empty catalogue would satisfy it
    /// over nothing at all — and the catalogue reaches this crate across an rlib
    /// boundary, which is exactly where linkme can come up empty. The floor
    /// assertion is what keeps a link failure from reading as 194 files in
    /// agreement; `catalogue_collected_in_xtask_link_config` in `main.rs` says
    /// the same thing where a reader will look for it.
    #[test]
    fn docs_match_generated() {
        assert_eq!(RULES.len(), REGISTERED_RULES.len());
        assert!(
            !RULES.is_empty(),
            "catalogue did not collect in the xtask link config — this gate would pass vacuously",
        );

        let root = repo_root();
        let config_toml =
            std::fs::read_to_string(root.join("config_example.toml")).expect("config_example.toml");
        let check = |id: &str, expected: String| {
            let path = root.join(format!("docs/rules/{}.md", id));
            let on_disk = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e));
            assert!(
                on_disk == expected,
                "docs/rules/{}.md is out of date — run `cargo xtask gendocs`",
                id
            );
        };
        for rule in RULES.iter() {
            check(
                rule.id(),
                render_doc(
                    rule.id(),
                    rule.title(),
                    rule.description(),
                    rule.specifications(),
                    rule.examples(),
                    config_block_for(rule.id(), &config_toml).as_deref(),
                ),
            );
        }
        for rule in PROTOCOL_RULES.iter() {
            check(
                rule.id(),
                render_doc(
                    rule.id(),
                    rule.title(),
                    rule.description(),
                    rule.specifications(),
                    rule.examples(),
                    config_block_for(rule.id(), &config_toml).as_deref(),
                ),
            );
        }
        let index = render_index(&RULES, &PROTOCOL_RULES);
        let on_disk = std::fs::read_to_string(root.join("docs/rules.md")).expect("docs/rules.md");
        assert!(
            on_disk == index,
            "docs/rules.md is out of date — run `cargo xtask gendocs`"
        );
    }
}
