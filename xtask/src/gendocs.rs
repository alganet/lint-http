// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Documentation generator: renders two trees of generated markdown and an
//! index over each.
//!
//! `docs/rules/<id>.md` and the `docs/rules.md` index come from rule metadata
//! ([`description`](lint_http_rules::rules::RuleMeta::description),
//! [`specifications`](lint_http_rules::rules::RuleMeta::specifications),
//! [`examples`](lint_http_rules::rules::RuleMeta::examples),
//! [`title`](lint_http_rules::rules::RuleMeta::title),
//! [`config_example`](lint_http_rules::rules::RuleMeta::config_example)).
//!
//! `docs/violations/<id>.md` and the `docs/violations.md` index come from the
//! defect catalogue ([`ViolationDef`]). A rule is the unit of analysis and a
//! violation the unit of report, and they are two trees for the same reason
//! they are two configuration tables: one defect may be reported by several
//! rules, so its page cannot live inside any one of them. The rule pages link
//! down into the defect pages and the defect pages link back — which is the
//! only place in this file that assumes the two directories are siblings.
//!
//! The Configuration block used to be scraped back out of `config_example.toml`,
//! which was the source of truth for it. That file is now generated from the
//! same metadata (see [`crate::genconfig`]), so scraping it would put one
//! generator downstream of another's output — a rule's example would reach its
//! doc page only after `genconfig` had run, and two passes would be needed to
//! land one edit. Both generators read the rule.
//!
//! The render functions are pure and deterministic so the #11d CI gate
//! (`docs_match_generated` test) can diff regenerated output against the
//! checked-in docs.

use lint_http_rules::lint::{Party, Strength};
use lint_http_rules::rules::{
    all_rules, Compliance, Example, ProtocolRule, Rule, RuleMeta, RuleParty, SpecRef,
    PROTOCOL_RULES, RULES,
};
use lint_http_rules::violations::{ViolationDef, VIOLATIONS};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

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
/// are a different kind of rule rather than a fourth party, and keep their own
/// trailing section.
///
/// Selection used to be `id().starts_with("client_")` and friends, which made
/// the id string load-bearing for one generated file and was the last reason the
/// category prefixes existed. It then grouped by the rule's scope, which read
/// as a claim about *whose* rule this is and was not one: scope said which half
/// must be present for the rule to run, and 19 `Server`-scoped rules read the
/// request. What a reader looking for "the rules about my server" wants is the
/// party, so that is what the index groups by.
///
/// Titles come from [`section_title`], whose match the compiler checks; that a
/// party is not merely titled but actually *listed* here is what
/// `render_index_mentions_every_rule` checks, since omitting one would silently
/// drop its rules from the index.
const TX_SECTION_ORDER: &[RuleParty] = &[
    RuleParty::Presumed(Party::Client),
    RuleParty::Presumed(Party::Server),
    RuleParty::PerSite,
    RuleParty::Presumed(Party::Neither),
];

/// Heading for a transaction-rule section. Exhaustive over [`RuleParty`], so a
/// new variant fails to compile until it is given a heading here and a place in
/// [`TX_SECTION_ORDER`].
fn section_title(party: RuleParty) -> &'static str {
    match party {
        RuleParty::Presumed(Party::Client) => "Client Rules",
        RuleParty::Presumed(Party::Server) => "Server Rules",
        RuleParty::Presumed(Party::Neither) => "Rules Neither Peer Answers For",
        RuleParty::PerSite => "Rules Whose Findings Name Their Own Peer",
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
/// have no content (Violations when `violations` is empty, Specifications when
/// `specifications` is empty, Examples when `examples` is empty, Configuration
/// when `config_block` is `None`) are omitted entirely. `title` overrides the
/// id-derived heading when `Some`.
///
/// Parameter order is render order, which is the one property that makes six
/// loose `&str`-ish arguments readable, and it is why `violations` arrives as a
/// seventh parameter rather than as a params struct. Seven is the last one that
/// can: `too_many_arguments` keeps its default threshold of 7 and fires above
/// it, and this crate builds under `-D warnings`. **The eighth field is the one
/// that has to become a struct, because clippy will say so.**
pub fn render_doc(
    id: &str,
    title: Option<&str>,
    description: &str,
    violations: &[&'static ViolationDef],
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

    if !violations.is_empty() {
        render_violations(&mut out, violations);
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

/// Append the `## Violations` section: one bullet per declared defect, linking
/// to the page that documents it.
///
/// It sits between Description and Specifications because `violations()` is the
/// only one of a rule's metadata members with **no default** — a rule must
/// declare what it reports, while a description, a citation list, examples and a
/// config block are each optional. So this is the rule's own output and belongs
/// with the description; everything below it is reference material the rule may
/// or may not carry.
///
/// A bullet, not the defect's detail. The 190 rules declare 1025 entries over
/// 537 distinct defects, so writing each defect's title, severity and citations
/// onto every page that reports it would write 488 of them twice or more —
/// `token_character_forbidden` 42 times. The detail lives on the defect's own
/// page and this is the way to it.
///
/// Sorted here rather than by the caller: a rule's declared array is written in
/// whatever order its author reached for the defs, and a generated page may not
/// inherit that.
///
/// The link is relative from `docs/rules/`, which is where every caller writes
/// this page, and [`render_violation_doc`] makes the same assumption in the
/// other direction.
fn render_violations(out: &mut String, violations: &[&'static ViolationDef]) {
    let mut defs: Vec<&&'static ViolationDef> = violations.iter().collect();
    defs.sort_by_key(|def| def.id);

    out.push_str("\n## Violations\n\n");
    for def in defs {
        out.push_str(&format!(
            "- [{0}](../violations/{0}.md) — {1}\n",
            def.id, def.title
        ));
    }
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
/// fixed-order sections by the party they hold answerable, then a Protocol
/// Rules section. Rules keep the catalogue's (id-sorted) order within each
/// section.
pub fn render_index(rules: &[&dyn Rule], protocol_rules: &[&dyn ProtocolRule]) -> String {
    let mut out = String::new();
    out.push_str(SPDX_HEADER);
    out.push_str(
        "\n# Lint Rules\n\nGenerated index of every rule in the catalogue. Each entry links to \
the per-rule documentation under `rules/`. Rules are disabled by default and \
enabled via configuration.\n\nThe sections group rules by **who is answerable for what they \
report** — the peer that wrote the message the evidence was found in — and not by which half \
of a transaction the rule reads. A rule that reports defects in both halves answers one \
finding at a time and is listed under *Rules Whose Findings Name Their Own Peer*; `lint-http \
--about client|server|any` narrows a report the same way.\n",
    );

    for party in TX_SECTION_ORDER {
        let mut section = String::new();
        for rule in rules.iter() {
            if rule.party() == *party {
                section.push_str(&index_entry(rule.id(), rule.description()));
            }
        }
        if !section.is_empty() {
            out.push_str(&format!("\n## {}\n\n", section_title(*party)));
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

/// One rule's `[rules.<id>]` section: the header rendered from its id, then the
/// body it declares. The same two pieces `genconfig` joins, so the block in a
/// rule's doc page and the block in `config_example.toml` are the same text by
/// construction rather than by a gate comparing them.
pub fn config_section(rule: &dyn RuleMeta) -> String {
    format!("[rules.{}]\n{}", rule.id(), rule.config_example())
}

/// Stand-in for the `## Message` section of a defect whose message is written
/// where it is reported.
///
/// 503 of the 537 entries carry an empty `message`, and that is a design
/// statement rather than a gap: a message naming the value that caused it can
/// only be assembled where the value is, so the format string stays at the
/// site. The line says that in words a reader will not mistake for a TODO.
const PARAMETERISED_MESSAGE: &str = "_Written where it is reported: this defect's message names \
the value that caused it, so it is not fixed text._";

/// What the entry says its sentence obliges, in the words a reader of one page
/// needs — including, for the majority answer, why saying nothing is an answer.
///
/// The severity each of these names is [`Strength::default_severity`]'s, not a
/// second copy of the mapping: the gate that holds the catalogue to it is
/// `a_stated_strength_sets_the_default_severity`, and
/// `the_obligation_line_names_the_level_the_mapping_implies` keeps this prose
/// from drifting away from what that gate enforces.
fn obligation(def: &ViolationDef) -> &'static str {
    match def.strength {
        Strength::Must => {
            "A **`MUST`** binding the sender of the message, so a finding here \
reports at `error` by default."
        }
        Strength::Should => {
            "A **`SHOULD`** binding the sender of the message — advice the \
specification gives in its own voice and the sender declined — so a finding here reports at \
`warn` by default."
        }
        Strength::May => {
            "A **`MAY`**: a permission the sender did not take up, or a component \
its own definition marks `OPTIONAL`. Nothing is broken, so a finding here reports at `info` by \
default."
        }
        Strength::Grammar => {
            "**A value that does not derive from the ABNF production it cites.** \
The production states no keyword; what obliges it is RFC 9110 §2.2 — \"A sender MUST NOT generate \
protocol elements that do not match the grammar defined by the corresponding ABNF rules\" — which \
binds the sender, so a finding here reports at `error` by default."
        }
        Strength::Unstated => {
            "**No sentence obliges the sender of this message.** Either nothing \
states a requirement about this defect, or the keyword in the text it cites binds the *recipient* \
and so says nothing about the peer being reported. The severity below is a judgement, argued in \
the catalogue entry."
        }
    }
}

/// Render one defect's markdown page from its catalogue entry.
///
/// Takes the `&ViolationDef` whole where [`render_doc`] takes six loose
/// parameters, because a def is plain data with public fields rather than a
/// `&dyn` behind which every field is a method call —
/// [`crate::genconfig::violation_section`] already reads one this way.
///
/// The Configuration block is derived here rather than passed in. A parameter
/// would let a caller hand this function a block that configures some *other*
/// defect, which is the failure [`config_section`]'s own doc comment exists to
/// prevent; calling `violation_section` means the block on this page and the
/// block in `config_example.toml` are the same bytes by construction.
///
/// `reported_by` is the one thing a def does not know about itself. A defect
/// names no rule on purpose — 103 of them are reported by more than one, and
/// `token_character_forbidden` by 42 — so the back-link exists only as the
/// inverse of the catalogue's forward lists, which is what [`declarers`]
/// builds.
///
/// The heading is the **id**, not the title. A rule page heads with a title
/// because [`title_from_id`] makes that title the id in prose, so the identity
/// the reader clicked survives it; a defect's title is a sentence with no
/// derivable relation to its id, and heading the page with it would lose the
/// name in the finding, the name in `[violations.<id>]` and the name in the
/// link. The title becomes the lead paragraph, verbatim and unpunctuated — a
/// generator that adds a full stop is one that can disagree with the field.
pub fn render_violation_doc(def: &ViolationDef, reported_by: &[&str]) -> String {
    let mut out = String::new();
    out.push_str(SPDX_HEADER);
    out.push_str(&format!("\n# {}\n\n", def.id));
    out.push_str(def.title);
    out.push('\n');

    // Message renders on every page, following `## Description`'s precedent in
    // `render_doc`; Specifications is omitted when empty, following its own.
    // The asymmetry is deliberate: each section keeps the behaviour its
    // counterpart on a rule page already has. A placeholder under
    // Specifications would restate `every_violation_declares_a_spec`'s four
    // permitted reasons in 33 copies, which is drift waiting to happen — the
    // index preamble says it once instead.
    out.push_str("\n## Message\n\n");
    if def.message.is_empty() {
        out.push_str(PARAMETERISED_MESSAGE);
    } else {
        out.push_str(def.message.trim_end());
    }
    out.push('\n');

    out.push_str("\n## Obligation\n\n");
    out.push_str(obligation(def));
    out.push('\n');
    if let Some(why) = def.departure {
        out.push_str(&format!("\n**It departs from that level.** {why}\n"));
    }

    if !def.spec.is_empty() {
        out.push_str("\n## Specifications\n\n");
        for spec in def.spec {
            out.push_str(&format!("- {}\n", spec));
        }
    }

    out.push_str(&format!(
        "\n## Configuration\n\n```toml\n{}\n```\n",
        crate::genconfig::violation_section(def).trim_end_matches('\n')
    ));

    out.push_str("\n## Reported By\n\n");
    if reported_by.is_empty() {
        out.push_str("_No rule reports this defect._\n");
    } else {
        for rule in reported_by {
            out.push_str(&format!("- [{0}](../rules/{0}.md)\n", rule));
        }
    }

    out
}

/// Render the `docs/violations.md` index: one bullet per defect, in catalogue
/// order, flat.
///
/// No sections, unlike [`render_index`]. A defect has no scope to group by; its
/// `default_severity` is a preference an operator overrides and would scatter
/// related entries across three lists; and the subject it belongs to is source
/// layout (`src/violations/<subject>.rs`), not metadata this can read. What is
/// left is the id order [`VIOLATIONS`] is already sorted into — and because
/// every id opens with its subject, that order *is* the subject grouping.
pub fn render_violation_index(defs: &[&'static ViolationDef]) -> String {
    let mut out = String::new();
    out.push_str(SPDX_HEADER);
    out.push_str(
        "\n# Violations\n\nGenerated index of every defect the rules report. Each entry links \
to the per-defect documentation under `violations/`. A rule is the unit of analysis; a violation \
is the unit of report — the name a finding carries, the name `[violations.<id>]` tunes, and the \
name `enabled = false` switches off. One defect may be reported by several rules, and its page \
names them all.\n\nEntries are in id order, which groups them by subject: an id reads \
`<subject>[_<part>]_<defect>`. A page names the specification sentences its defect enforces where \
there are any — some defects have none, because the value is refused by this implementation \
rather than by a document, or the bound was configured by a deployment, and an absent sentence is \
carried rather than guessed.\n\n",
    );

    for def in defs {
        out.push_str(&format!(
            "- [{0}](violations/{0}.md) — {1}\n",
            def.id, def.title
        ));
    }

    out
}

/// Which rules report each defect: the catalogue's `violations()` lists,
/// inverted.
///
/// It lives here and not in `lint-http-rules` because nothing on the lint path
/// asks this question. `RuleContext::report` resolves a def against *one*
/// rule's declared list by `ptr::eq`, which is the forward direction; the
/// inverse is a documentation shape with one consumer. `rules/mod.rs` builds
/// the same map inside `no_violation_is_emitted_by_two_rules`, and two six-line
/// inversions across a crate boundary are cheaper than a public API with its
/// own doc comment and its own gate. Promote it if a third caller appears —
/// `rules list` emitting a `reported_by` field would be the one.
///
/// `BTreeMap` keys hold the whole map in the id order [`VIOLATIONS`] is in; the
/// values keep [`all_rules`] order — transaction rules by id, then protocol
/// rules by id — which is the order `genconfig` renders sections in.
fn declarers() -> BTreeMap<&'static str, Vec<&'static str>> {
    let mut map: BTreeMap<&'static str, Vec<&'static str>> = BTreeMap::new();
    for rule in all_rules() {
        for def in rule.violations() {
            map.entry(def.id).or_default().push(rule.id());
        }
    }
    map
}

/// Pages under `dir` that no catalogue entry claims, sorted so a failure
/// message reads the same twice.
///
/// The drift gate iterates the catalogue, so it can only ever look at files that
/// *should* exist: a page whose rule was renamed or deleted stays on disk and
/// keeps passing, because nothing looks the other way. This is that other look —
/// the directory listing minus the catalogue.
///
/// `claimed` is the set of file names the generator writes into `dir`. Which
/// catalogue supplies that set is the only difference between the two page
/// directories, so it is a parameter rather than a second copy of this
/// function; [`page_dirs`] is where the pairing is written down.
///
/// Only `.md` is considered. The generator writes nothing else, so anything else
/// under a page directory was put there by someone and is not this tool's to
/// delete.
pub fn orphan_docs(dir: &Path, claimed: &HashSet<String>) -> anyhow::Result<Vec<PathBuf>> {
    let mut orphans = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let kept = match path.file_name().and_then(std::ffi::OsStr::to_str) {
            Some(name) => !name.ends_with(".md") || claimed.contains(name),
            // A name that is not UTF-8 cannot be a catalogue id, and the ids are
            // what this tool wrote — leave it alone rather than guess.
            None => true,
        };
        if !kept {
            orphans.push(path);
        }
    }
    orphans.sort();
    Ok(orphans)
}

/// Every directory this generator writes pages into, paired with the file names
/// its catalogue claims there.
///
/// One list, read by the writer, by the pruner, and by the gate that says the
/// tree has no orphans. A third generated directory is covered by all three the
/// moment it is added here, rather than by three places remembering — which is
/// what the second directory nearly cost, since the drift gate can only ever
/// look at files that should exist.
///
/// A fixed-size array rather than a `Vec`: how many page directories there are
/// is a fact the compiler can hold.
fn page_dirs(out_dir: &Path) -> [(PathBuf, HashSet<String>); 2] {
    [
        (
            out_dir.join("rules"),
            all_rules().map(|r| format!("{}.md", r.id())).collect(),
        ),
        (
            out_dir.join("violations"),
            VIOLATIONS.iter().map(|d| format!("{}.md", d.id)).collect(),
        ),
    ]
}

/// Write `<out_dir>/rules/<id>.md` per rule plus the `<out_dir>/rules.md`
/// index. Creates the directory as needed.
fn write_rule_pages(out_dir: &Path) -> anyhow::Result<()> {
    let rules_dir = out_dir.join("rules");
    std::fs::create_dir_all(&rules_dir)?;

    for rule in all_rules() {
        let doc = render_doc(
            rule.id(),
            rule.title(),
            rule.description(),
            rule.violations(),
            rule.specifications(),
            rule.examples(),
            Some(&config_section(rule)),
        );
        std::fs::write(rules_dir.join(format!("{}.md", rule.id())), doc)?;
    }

    std::fs::write(
        out_dir.join("rules.md"),
        render_index(&RULES, &PROTOCOL_RULES),
    )?;
    Ok(())
}

/// Write `<out_dir>/violations/<id>.md` per defect plus the
/// `<out_dir>/violations.md` index. Creates the directory as needed.
///
/// [`declarers`] is built once and read 537 times, rather than per page: it is
/// a walk of every rule's declared list, and doing it inside the loop would
/// make writing the catalogue quadratic in it.
fn write_violation_pages(out_dir: &Path) -> anyhow::Result<()> {
    let violations_dir = out_dir.join("violations");
    std::fs::create_dir_all(&violations_dir)?;

    let declarers = declarers();
    for def in VIOLATIONS.iter() {
        let reported_by = declarers.get(def.id).map_or(&[][..], Vec::as_slice);
        let doc = render_violation_doc(def, reported_by);
        std::fs::write(violations_dir.join(format!("{}.md", def.id)), doc)?;
    }

    std::fs::write(
        out_dir.join("violations.md"),
        render_violation_index(&VIOLATIONS),
    )?;
    Ok(())
}

/// Render both page trees to disk under `out_dir`, then delete the orphans and
/// return what was deleted, so the tree is the catalogue rather than the
/// catalogue plus whatever it used to be.
///
/// Reporting is the caller's: a generator that prints is one that cannot be
/// called twice in a test without noise.
///
/// The pruning pass reads [`page_dirs`] rather than naming the two directories
/// again, so it cannot fall behind the writing passes above it.
pub fn write_all(out_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    write_rule_pages(out_dir)?;
    write_violation_pages(out_dir)?;

    let mut orphans = Vec::new();
    for (dir, claimed) in page_dirs(out_dir) {
        orphans.extend(orphan_docs(&dir, &claimed)?);
    }
    for path in &orphans {
        std::fs::remove_file(path)?;
    }
    Ok(orphans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo_root;
    use lint_http_rules::lint::Severity;
    use lint_http_rules::rules::REGISTERED_RULES;
    use lint_http_rules::violations::user_agent::USER_AGENT_MISSING;
    use lint_http_rules::violations::REGISTERED_VIOLATIONS;

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
        let declared: &[&ViolationDef] = &[&USER_AGENT_MISSING];
        let doc = render_doc(
            "user_agent_present",
            Some("User-Agent Present"),
            "Requests should carry a User-Agent header.",
            declared,
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
            Some("[rules.user_agent_present]\nenabled = true"),
        );

        assert!(doc.starts_with("<!--\nSPDX-FileCopyrightText"));
        assert!(doc.contains("- [user_agent_missing](../violations/user_agent_missing.md) — "));
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
            "## Configuration\n\n```toml\n[rules.user_agent_present]\nenabled = true\n```"
        ));
        assert!(doc.contains("### ✅ Good Request"));
        assert!(doc.contains("### ❌ Bad\n"));
        assert!(doc.contains("```http\nGET / HTTP/1.1\nHost: example.com\nUser-Agent: x/1.0\n```"));
    }

    #[test]
    fn render_doc_derives_title_and_omits_empty_sections() {
        // No title override → derived from id; no rfc/config/examples → those
        // sections are omitted.
        let doc = render_doc("server_some_rule", None, "", &[], &[], &[], None);

        assert!(doc.contains("# Server Some Rule"));
        assert!(doc.contains("## Description\n\n_No description provided yet._"));
        assert!(!doc.contains("## Violations"));
        assert!(!doc.contains("## Specifications"));
        assert!(!doc.contains("## Configuration"));
        assert!(!doc.contains("## Examples"));
    }

    #[test]
    fn render_doc_for_whole_catalogue_is_nonempty_and_well_formed() {
        // Render every rule in-memory; must not touch the real docs/ tree.
        for rule in all_rules() {
            let doc = render_doc(
                rule.id(),
                rule.title(),
                rule.description(),
                rule.violations(),
                rule.specifications(),
                rule.examples(),
                Some(&config_section(rule)),
            );
            assert!(
                doc.starts_with(SPDX_HEADER),
                "{} missing SPDX header",
                rule.id()
            );
            assert!(
                doc.contains("\n## Violations\n"),
                "{} does not list what it reports",
                rule.id()
            );
            assert!(
                doc.contains("## Description"),
                "{} missing Description",
                rule.id()
            );
            assert!(
                doc.contains(&format!("```toml\n[rules.{}]\n", rule.id())),
                "{} missing its Configuration block",
                rule.id()
            );
        }
    }

    /// The header is the rule's id and the body is the rule's own, so a page
    /// cannot document a section that configures some other rule.
    #[test]
    fn config_section_heads_the_rules_own_body() {
        let rule = all_rules()
            .find(|r| r.id() == "keep_alive_header_valid")
            .expect("keep_alive_header_valid registered");
        let section = config_section(rule);
        assert!(section.starts_with("[rules.keep_alive_header_valid]\n"));
        assert!(section.ends_with(rule.config_example()));
        assert!(section.contains("max_timeout_seconds"));
    }

    /// Also the guard on `TX_SECTION_ORDER`: sections are selected by scope, so a
    /// scope left out of that list would drop its rules from the index entirely,
    /// and one listed twice would print them twice. Counting the links catches
    /// both, which a `contains` check on its own would not.
    #[test]
    fn render_index_mentions_every_rule() {
        let index = render_index(&RULES, &PROTOCOL_RULES);
        assert!(index.contains("# Lint Rules"));
        for rule in all_rules() {
            assert_eq!(
                index
                    .matches(&format!("[{0}](rules/{0}.md)", rule.id()))
                    .count(),
                1,
                "index should link {} exactly once",
                rule.id()
            );
        }
    }

    #[test]
    fn write_all_creates_files_in_temp_dir() {
        let dir = std::env::temp_dir().join(format!("gendocs_test_{}", uuid::Uuid::new_v4()));
        let pruned = write_all(&dir).expect("write_all should succeed");
        assert!(pruned.is_empty(), "a fresh directory has nothing to prune");

        assert!(dir.join("rules.md").is_file());
        let first = RULES.first().expect("catalogue is non-empty");
        assert!(dir
            .join("rules")
            .join(format!("{}.md", first.id()))
            .is_file());

        assert!(dir.join("violations.md").is_file());
        let defect = VIOLATIONS.first().expect("catalogue is non-empty");
        assert!(dir
            .join("violations")
            .join(format!("{}.md", defect.id))
            .is_file());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A second run deletes the page no catalogue entry claims, and only that
    /// page — in **both** trees. The `.txt` in each is the guard on the
    /// extension filter: pruning is scoped to what this tool writes, so an
    /// unrelated file survives regeneration.
    ///
    /// One test over both directories rather than two tests over one each,
    /// because there is one property here and `orphan_docs` was generalized
    /// precisely so there would not be two of it.
    #[test]
    fn write_all_prunes_pages_no_catalogue_entry_claims() {
        let dir = std::env::temp_dir().join(format!("gendocs_prune_{}", uuid::Uuid::new_v4()));
        write_all(&dir).expect("write_all should succeed");

        let rules_dir = dir.join("rules");
        let violations_dir = dir.join("violations");
        let stale_rule = rules_dir.join("rule_that_was_renamed.md");
        let stale_defect = violations_dir.join("defect_that_was_merged_away.md");
        let rule_bystander = rules_dir.join("notes.txt");
        let defect_bystander = violations_dir.join("notes.txt");
        for (path, body) in [
            (&stale_rule, "stale"),
            (&stale_defect, "stale"),
            (&rule_bystander, "mine"),
            (&defect_bystander, "mine"),
        ] {
            std::fs::write(path, body).expect("write fixture");
        }

        for (dir, expected) in page_dirs(&dir).iter().zip([&stale_rule, &stale_defect]) {
            assert_eq!(
                orphan_docs(&dir.0, &dir.1).expect("scan"),
                vec![expected.clone()],
                "only the unclaimed .md is an orphan"
            );
        }

        let pruned = write_all(&dir).expect("write_all should succeed");
        assert_eq!(pruned, vec![stale_rule.clone(), stale_defect.clone()]);
        assert!(!stale_rule.exists(), "the orphan rule page should be gone");
        assert!(
            !stale_defect.exists(),
            "the orphan defect page should be gone"
        );
        assert!(
            rule_bystander.is_file() && defect_bystander.is_file(),
            "a non-generated file should survive in either tree"
        );

        let first = RULES.first().expect("catalogue is non-empty");
        assert!(rules_dir.join(format!("{}.md", first.id())).is_file());
        let defect = VIOLATIONS.first().expect("catalogue is non-empty");
        assert!(violations_dir.join(format!("{}.md", defect.id)).is_file());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The other half of `docs_match_generated`: that gate reads the catalogue
    /// and looks for the file, so it cannot see a page whose rule no longer
    /// exists. Retiring or renaming a rule leaves its page behind, and every
    /// gate stays green while the docs describe a rule nobody can enable.
    #[test]
    fn docs_have_no_orphans() {
        assert!(
            !RULES.is_empty() && !VIOLATIONS.is_empty(),
            "a catalogue did not collect in the xtask link config — every page in its tree would read as an orphan",
        );
        for (dir, claimed) in page_dirs(&repo_root().join("docs")) {
            let orphans = orphan_docs(&dir, &claimed)
                .unwrap_or_else(|e| panic!("read {}: {}", dir.display(), e));
            assert!(
                orphans.is_empty(),
                "nothing in the catalogue claims these pages — run `cargo xtask gendocs`: {:?}",
                orphans
            );
        }
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
        for rule in all_rules() {
            check(rule.id(), rule.specifications());
        }
        // A def's own references reach `docs/violations/<id>.md` directly, so
        // this reads them directly. They were covered only transitively before,
        // by `every_violation_spec_is_declared_by_its_rule` in another crate —
        // and a gate that holds because some other gate holds is one nobody
        // will think to re-check when that one changes.
        for def in VIOLATIONS.iter() {
            check(def.id, def.spec);
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
        for rule in all_rules() {
            check(rule.id(), rule.specifications());
        }
        // A def's own references reach `docs/violations/<id>.md` directly, so
        // this reads them directly. They were covered only transitively before,
        // by `every_violation_spec_is_declared_by_its_rule` in another crate —
        // and a gate that holds because some other gate holds is one nobody
        // will think to re-check when that one changes.
        for def in VIOLATIONS.iter() {
            check(def.id, def.spec);
        }
    }

    /// #11d drift gate: the committed `docs/rules/` and `docs/violations/` files
    /// must equal what `gendocs` regenerates from the two catalogues. This makes
    /// the docs a verified generated artifact — editing a rule or a defect
    /// without regenerating fails CI. Run `cargo xtask gendocs` to fix drift.
    ///
    /// One test over both trees rather than one each: there is a single
    /// artifact, a single fixer command, and a single message worth printing.
    ///
    /// The gate is a loop over each catalogue, so an empty one would satisfy it
    /// over nothing at all — and both reach this crate across an rlib boundary,
    /// which is exactly where linkme can come up empty. The floor assertions are
    /// what keep a link failure from reading as 730 files in agreement;
    /// `catalogue_collected_in_xtask_link_config` in `main.rs` says the same
    /// thing where a reader will look for it.
    #[test]
    fn docs_match_generated() {
        assert_eq!(RULES.len(), REGISTERED_RULES.len());
        assert_eq!(VIOLATIONS.len(), REGISTERED_VIOLATIONS.len());
        assert!(
            !RULES.is_empty() && !VIOLATIONS.is_empty(),
            "a catalogue did not collect in the xtask link config — this gate would pass vacuously",
        );

        let root = repo_root();
        let check = |relative: String, expected: String| {
            let path = root.join(&relative);
            let on_disk = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("cannot read {}: {}", path.display(), e));
            assert!(
                on_disk == expected,
                "{} is out of date — run `cargo xtask gendocs`",
                relative
            );
        };

        for rule in all_rules() {
            check(
                format!("docs/rules/{}.md", rule.id()),
                render_doc(
                    rule.id(),
                    rule.title(),
                    rule.description(),
                    rule.violations(),
                    rule.specifications(),
                    rule.examples(),
                    Some(&config_section(rule)),
                ),
            );
        }
        check(
            "docs/rules.md".to_string(),
            render_index(&RULES, &PROTOCOL_RULES),
        );

        let declarers = declarers();
        for def in VIOLATIONS.iter() {
            let reported_by = declarers.get(def.id).map_or(&[][..], Vec::as_slice);
            check(
                format!("docs/violations/{}.md", def.id),
                render_violation_doc(def, reported_by),
            );
        }
        check(
            "docs/violations.md".to_string(),
            render_violation_index(&VIOLATIONS),
        );
    }

    /// Every rule's page lists exactly the defects that rule declares.
    ///
    /// This is the gate that makes a shipped sentence true. When a configuration
    /// carries the `[rules.*] severity` key that no longer exists, `validate_rules`
    /// refuses it and tells the operator to use `[violations.<id>]` "for the
    /// defects this rule reports — `docs/rules/<id>.md` lists them". That page
    /// did not list them for as long as the error has said so.
    ///
    /// Equality, not `contains`: a page listing all 537 defects would satisfy a
    /// presence check on every rule while telling an operator nothing. The whole
    /// bullet is compared, href included, so a wrong relative prefix fails here
    /// rather than in a reader's browser — nothing in CI resolves a markdown
    /// link.
    ///
    /// Rendered in memory rather than read off disk. Whether the tree agrees
    /// with the renderer is `docs_match_generated`'s question, and asking it
    /// twice would make this gate fail for that reason instead of its own.
    #[test]
    fn every_rule_page_lists_the_defects_it_declares() {
        assert!(!RULES.is_empty(), "catalogue did not collect");
        for rule in all_rules() {
            let doc = render_doc(
                rule.id(),
                rule.title(),
                rule.description(),
                rule.violations(),
                rule.specifications(),
                rule.examples(),
                Some(&config_section(rule)),
            );
            let listed: Vec<&str> = doc
                .split("\n## Violations\n\n")
                .nth(1)
                .unwrap_or_else(|| panic!("{} has no Violations section", rule.id()))
                .lines()
                .take_while(|line| line.starts_with("- ["))
                .collect();

            let mut expected: Vec<String> = rule
                .violations()
                .iter()
                .map(|def| format!("- [{0}](../violations/{0}.md) — {1}", def.id, def.title))
                .collect();
            expected.sort();

            assert_eq!(
                listed,
                expected,
                "docs/rules/{}.md does not list the defects it declares",
                rule.id()
            );
        }
    }

    /// Every defect's page names exactly the rules that report it.
    ///
    /// The converse of the forward declaration each rule makes, and the half no
    /// gate could state before: a def names no rule, so the back-link exists
    /// only as an inversion, and an inversion with a bug reads exactly like a
    /// defect nobody reports.
    #[test]
    fn every_violation_page_names_the_rules_that_report_it() {
        let declarers = declarers();
        for def in VIOLATIONS.iter() {
            let page =
                render_violation_doc(def, declarers.get(def.id).map_or(&[][..], Vec::as_slice));
            let listed: Vec<&str> = page
                .split("\n## Reported By\n\n")
                .nth(1)
                .expect("every page has a Reported By section")
                .lines()
                .take_while(|line| line.starts_with("- ["))
                .map(|line| {
                    line.trim_start_matches("- [")
                        .split(']')
                        .next()
                        .expect("a bullet names a rule")
                })
                .collect();
            let expected: Vec<&str> = declarers.get(def.id).cloned().unwrap_or_default();
            assert_eq!(
                listed, expected,
                "docs/violations/{}.md does not name the rules that report it",
                def.id
            );
        }
    }

    /// The violation index links every defect, exactly once.
    ///
    /// Counting rather than `contains`: a doubled entry is the failure a
    /// presence check cannot see, and the index is generated from a sorted
    /// catalogue precisely so it can be read as a complete list.
    #[test]
    fn the_violation_index_links_every_defect_once() {
        let index = render_violation_index(&VIOLATIONS);
        for def in VIOLATIONS.iter() {
            let link = format!("[{0}](violations/{0}.md)", def.id);
            assert_eq!(
                index.matches(&link).count(),
                1,
                "{} is not linked exactly once from docs/violations.md",
                def.id
            );
        }
    }

    /// Smoke test over the real catalogue: every defect renders a page with the
    /// sections a reader is entitled to, headed by the id they clicked.
    #[test]
    fn render_violation_doc_for_whole_catalogue_is_nonempty_and_well_formed() {
        assert!(!VIOLATIONS.is_empty(), "catalogue did not collect");
        let declarers = declarers();
        for def in VIOLATIONS.iter() {
            let page =
                render_violation_doc(def, declarers.get(def.id).map_or(&[][..], Vec::as_slice));
            assert!(page.starts_with(SPDX_HEADER), "{} lost its header", def.id);
            assert!(page.contains(&format!("\n# {}\n", def.id)));
            assert!(page.contains("\n## Message\n"), "{}", def.id);
            assert!(page.contains("\n## Configuration\n"), "{}", def.id);
            assert!(
                page.contains(&format!("```toml\n[violations.{}]\n", def.id)),
                "{} does not show the table that configures it",
                def.id
            );
            assert!(page.contains("\n## Reported By\n"), "{}", def.id);
        }
    }

    /// A def constructed here rather than taken from the catalogue, so the page
    /// shape is pinned against text this test can read whole.
    #[test]
    fn a_violation_page_carries_its_id_title_message_specs_config_and_declarers() {
        let def = ViolationDef {
            id: "widget_count_malformed",
            title: "Widget-Count is written with something other than digits on it",
            message: "Widget-Count is not a number",
            default_severity: Severity::Warn,
            spec: &[SpecRef {
                spec: "RFC 9110",
                section: Some("5.6.2"),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2",
                note: "Tokens",
            }],
            induced: lint_http_rules::violations::Induced::No,
            strength: Strength::Unstated,
            departure: None,
        };
        let page = render_violation_doc(&def, &["widget_count_valid", "widget_headers_consistent"]);

        assert!(page.contains("\n# widget_count_malformed\n"));
        assert!(page.contains("\nWidget-Count is written with something other than digits on it\n"));
        assert!(page.contains("\n## Message\n\nWidget-Count is not a number\n"));
        assert!(page.contains("- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens\n"));
        assert!(page.contains("```toml\n[violations.widget_count_malformed]\n"));
        assert!(page.contains("severity = \"warn\"\n```\n"));
        assert!(page.contains("- [widget_count_valid](../rules/widget_count_valid.md)\n"));
        assert!(
            page.contains("- [widget_headers_consistent](../rules/widget_headers_consistent.md)\n")
        );
    }

    /// An empty `message` is the 503-entry majority and is not a gap: the page
    /// says where the text is written instead of leaving a reader to wonder.
    #[test]
    fn a_violation_page_says_a_parameterised_message_is_written_where_it_is_reported() {
        let def = ViolationDef {
            id: "widget_count_malformed",
            title: "Widget-Count is written with something other than digits on it",
            message: "",
            default_severity: Severity::Warn,
            spec: &[],
            induced: lint_http_rules::violations::Induced::No,
            strength: Strength::Unstated,
            departure: None,
        };
        let page = render_violation_doc(&def, &["widget_count_valid"]);
        assert!(page.contains(PARAMETERISED_MESSAGE));
        assert!(!page.contains("TODO"));
    }

    /// The 33 defects no sentence states get no Specifications section at all,
    /// rather than a generated line restating why — the index preamble says it
    /// once, and 33 copies of a rationale is drift waiting to happen.
    #[test]
    fn a_violation_page_omits_specifications_when_the_defect_cites_none() {
        let def = ViolationDef {
            id: "widget_count_malformed",
            title: "Widget-Count is written with something other than digits on it",
            message: "",
            default_severity: Severity::Info,
            spec: &[],
            induced: lint_http_rules::violations::Induced::No,
            strength: Strength::Unstated,
            departure: None,
        };
        let page = render_violation_doc(&def, &["widget_count_valid"]);
        assert!(!page.contains("## Specifications"));
        assert!(page.contains("## Message"));
    }

    /// Unreachable from the catalogue — `every_defect_is_reported_by_some_rule`
    /// says so — and rendered anyway, because a page that silently loses its
    /// last declarer should say that rather than end on a blank heading.
    #[test]
    fn a_violation_page_says_when_no_rule_reports_the_defect() {
        let def = ViolationDef {
            id: "widget_count_malformed",
            title: "Widget-Count is written with something other than digits on it",
            message: "",
            default_severity: Severity::Error,
            spec: &[],
            induced: lint_http_rules::violations::Induced::No,
            strength: Strength::Unstated,
            departure: None,
        };
        let page = render_violation_doc(&def, &[]);
        assert!(page.contains("_No rule reports this defect._"));
    }
}
