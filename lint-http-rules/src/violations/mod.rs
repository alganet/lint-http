// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The violation catalogue: the defects rules report, one entry each.
//!
//! A rule is the unit of *analysis* — what gets parsed, when it runs, which
//! options it reads. A violation is the unit of *report* — what an operator
//! reads, tunes and silences. The catalogue has been asking one type to be
//! both: severity is a single scalar per rule, so a rule that says four
//! different things says them all at the same level, and the same defect
//! reported by two rules has no name the two can agree on.
//!
//! This module holds the second half of that split. A [`ViolationDef`] is a
//! defect: an id, a title, its default severity, and the specification
//! sentence it enforces. Defs live in `src/violations/<subject>.rs`, grouped
//! by subject the way `helpers/` is, and self-register into
//! [`REGISTERED_VIOLATIONS`] at link time. [`VIOLATIONS`] is the sorted view.
//!
//! Nothing emits one yet: rules keep reporting through
//! [`RuleMeta::violation`](crate::rules::RuleMeta::violation) and its cited
//! sibling until the two APIs meet. This is the registry they will meet in.

use crate::lint::Severity;
use crate::rules::SpecRef;
use linkme::distributed_slice;
use std::sync::LazyLock;

/// One reportable defect.
///
/// # These are `static`, never `const`
///
/// A rule declares the defs it may report and emits one by reference, and the
/// engine resolves that reference to a configured severity by identity —
/// `ptr::eq` against the declared list. A `const` is inlined at each use, so
/// two `&DEF` written in different functions are two different addresses and
/// the lookup misses. It compiles, and it is wrong at run time. The same
/// applies to a rule's declared list: it is a named `static`, because an array
/// of references to statics is not const-promotable and the inline `&[…]` form
/// does not typecheck as `'static`.
pub struct ViolationDef {
    /// This violation's id: the `[violations.<id>]` section that configures
    /// it, the `Violation.violation` its findings will carry, and the section
    /// heading in the owning rule's generated doc page. Disjoint from the rule
    /// ids — see `violation_ids_are_unique_and_disjoint_from_rule_ids`.
    ///
    /// `<subject>[_<part>]_<defect>`, the defect drawn from the closed list
    /// "Violation ids" in `docs/development.md` defines and
    /// `every_violation_id_names_a_defect` checks. A rule id names a claim and
    /// a violation id names the defect that breaks it, which is why the two
    /// vocabularies cannot collide — and why the id names the defect rather
    /// than the rule reporting it, since two rules may report one defect.
    pub id: &'static str,
    /// One line naming the defect, for the docs heading and `rules list`.
    pub title: &'static str,
    /// The whole message, when this defect always reads the same way. Empty
    /// when the message is parameterised, in which case the site formats it —
    /// the format strings stay where their arguments are.
    pub message: &'static str,
    /// The severity a finding carries when nothing in the configuration says
    /// otherwise. Unlike a rule *option*, which is policy about the traffic
    /// and must be chosen, this is a preference with a defensible default: a
    /// catalogue this size cannot be hand-answered entry by entry, and
    /// `docs/development.md` §6's no-defaults doctrine is reversed here for
    /// severity alone.
    pub default_severity: Severity,
    /// The sentence this defect enforces. `None` while the reading has not
    /// happened yet — the same shape `cite` has on a finding, and for the same
    /// reason: an unread sentence is carried as absent, never as a guess.
    ///
    /// This is where a `// cite` comment moves to when its statement becomes a
    /// def. The quote sits beside the reference it quotes, and the rule site
    /// keeps none.
    pub spec: Option<SpecRef>,
}

/// Every violation, self-registered at link time via
/// `linkme::distributed_slice`. Each `src/violations/<subject>.rs` appends its
/// defs here, so adding a defect requires no edit to a central list. The link
/// order is unspecified; [`VIOLATIONS`] sorts a copy by id.
#[distributed_slice]
pub static REGISTERED_VIOLATIONS: [&'static ViolationDef] = [..];

/// The whole catalogue of defects, sorted by id so anything that enumerates it
/// — the generated configuration, the generated docs, a gate — reads the same
/// order every run whatever order the linker used.
pub static VIOLATIONS: LazyLock<Vec<&'static ViolationDef>> = LazyLock::new(|| {
    let mut v: Vec<&'static ViolationDef> = REGISTERED_VIOLATIONS.iter().copied().collect();
    v.sort_by_key(|d| d.id);
    v
});

#[cfg(test)]
mod tests {
    use super::*;

    /// A subject file registers by being declared here: `linkme` collects what
    /// the linker sees, and the linker never sees a module nobody declared. So
    /// a `src/violations/<subject>.rs` that exists but is missing its `mod`
    /// line compiles, links, and contributes nothing — the whole subject
    /// silently absent from the catalogue, with every other gate passing
    /// because none of them knows the file was supposed to be there.
    ///
    /// This is the same safety net `every_rule_file_is_registered` provides
    /// for `src/rules/`, phrased against declarations rather than a count: a
    /// rule file holds exactly one rule, a subject file holds as many defs as
    /// the subject has defects, so counting cannot say which file went missing.
    #[test]
    fn every_violation_file_is_registered() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/violations");
        let source =
            std::fs::read_to_string(dir.join("mod.rs")).expect("cannot read violations/mod.rs");
        // A declaration is a whole line, so `mod tests {` below is not one and
        // neither is a commented-out one.
        let declared: std::collections::HashSet<&str> = source
            .lines()
            .map(str::trim)
            .filter_map(|l| {
                l.strip_prefix("mod ")
                    .or_else(|| l.strip_prefix("pub mod "))
                    .and_then(|rest| rest.strip_suffix(';'))
            })
            .collect();
        for entry in std::fs::read_dir(&dir).expect("cannot read src/violations") {
            let path = entry.expect("a directory entry").path();
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if stem == "mod" {
                continue;
            }
            assert!(
                declared.contains(stem),
                "src/violations/{stem}.rs is not declared in violations/mod.rs, \
                 so none of its defs reach the catalogue",
            );
        }
    }

    /// Two things at once, because they are one property: an id names exactly
    /// one thing in this catalogue.
    ///
    /// Disjointness from the rule ids is what keeps the configuration and the
    /// docs unambiguous. `[rules.<id>]` and `[violations.<id>]` are separate
    /// tables, but they are read by the same person, and a violation rendered
    /// as a section inside its rule's page would collide with that page's own
    /// anchor if the two shared a name.
    #[test]
    fn violation_ids_are_unique_and_disjoint_from_rule_ids() {
        let mut seen = std::collections::HashSet::new();
        for def in VIOLATIONS.iter() {
            assert!(!def.id.is_empty(), "a violation id must not be empty");
            assert!(seen.insert(def.id), "duplicate violation id: {}", def.id);
        }
        for rule in crate::rules::all_rules() {
            assert!(
                !seen.contains(rule.id()),
                "{} names both a rule and a violation",
                rule.id(),
            );
        }
    }

    /// The closed vocabulary a violation id ends in. Each word is defined in
    /// "Violation ids" in `docs/development.md`, beside the claim it breaks;
    /// this array and that table are extended in one commit or not at all.
    const DEFECT_ENDINGS: &[&str] = &[
        "conflicting",
        "duplicated",
        "empty",
        "forbidden",
        "ignored",
        "invalid",
        "malformed",
        "missing",
        "obsolete",
        "unregistered",
    ];

    /// Whether `id` is `<subject>[_<part>]_<defect>`: a defect from the list
    /// above, with at least one character of subject in front of it.
    fn names_a_defect(id: &str) -> bool {
        DEFECT_ENDINGS.iter().any(|defect| {
            id.strip_suffix(defect)
                .is_some_and(|subject| subject.len() > 1 && subject.ends_with('_'))
        })
    }

    /// Whether `id` can be spelled as the def's `static`, which is the id in
    /// `SCREAMING_SNAKE_CASE` and therefore a Rust identifier.
    fn is_snake_case(id: &str) -> bool {
        id.starts_with(|c: char| c.is_ascii_lowercase())
            && id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    }

    /// A rule id names a claim about the traffic and a violation id names the
    /// defect that breaks it, so an id ending in a claim — `..._valid`,
    /// `..._present` — is a def that copied the id of the rule reporting it.
    /// That is the mistake this catches, and it is worth catching mechanically
    /// because it is invisible until an operator reads a report and cannot
    /// tell which of the two catalogues a name came from.
    ///
    /// The closed list is also what makes
    /// `violation_ids_are_unique_and_disjoint_from_rule_ids` hold by
    /// construction: no rule id ends in any of these words.
    #[test]
    fn every_violation_id_names_a_defect() {
        let stray: Vec<&str> = VIOLATIONS
            .iter()
            .map(|def| def.id)
            .filter(|id| !names_a_defect(id) || !is_snake_case(id))
            .collect();
        assert!(stray.is_empty(), "not <subject>_<defect> ids: {stray:?}");
    }

    /// The shape check itself, against ids built here rather than against the
    /// catalogue, so the convention is pinned whatever the catalogue holds.
    #[test]
    fn the_id_shape_takes_a_defect_and_refuses_a_claim() {
        for id in [
            "if_match_empty",
            "if_match_member_malformed",
            "www_authenticate_parameter_value_invalid",
            "status_426_upgrade_missing",
        ] {
            assert!(names_a_defect(id) && is_snake_case(id), "{id} is the shape");
        }
        for id in [
            // A rule id: the claim, not the defect.
            "if_match_etag_syntax",
            "content_type_valid",
            // A defect with no subject in front of it.
            "malformed",
            "_malformed",
            // A defect word that is not the ending.
            "empty_member_reported",
            // Spellings the def's `static` cannot take.
            "IfMatchEmpty",
            "2_members_conflicting",
        ] {
            assert!(
                !(names_a_defect(id) && is_snake_case(id)),
                "{id} is not the shape",
            );
        }
    }

    /// The sorted view must hold exactly what was registered, in id order —
    /// what everything downstream enumerates.
    #[test]
    fn linkme_collects_the_violation_catalogue_in_order() {
        assert_eq!(VIOLATIONS.len(), REGISTERED_VIOLATIONS.len());
        let ids: Vec<&str> = VIOLATIONS.iter().map(|d| d.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "VIOLATIONS must be sorted by id");
    }
}
