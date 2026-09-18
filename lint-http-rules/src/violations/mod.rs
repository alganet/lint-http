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
//! sentence it enforces — sentences, where a requirement is written once per
//! protocol version and no one of them governs. Defs live in `src/violations/<subject>.rs`, grouped
//! by subject the way `helpers/` is, written in a `defects!` block that
//! self-registers each one into [`REGISTERED_VIOLATIONS`] at link time.
//! [`VIOLATIONS`] is the sorted view.
//!
//! **There is one way to report now.** Every finding goes through
//! [`RuleContext::report`](crate::rules::RuleContext::report) or its
//! `report_with` sibling, which resolve the id, the configured severity and
//! the citation off the def. The two methods that let a rule write a message
//! out at the site and pass a reference beside it — `RuleMeta::violation` and
//! `RuleMeta::cited` — coexisted with these while the catalogue filled and were
//! deleted with the last site that called them.

use crate::lint::{Severity, Strength};
use crate::rules::SpecRef;
use linkme::distributed_slice;
use std::sync::LazyLock;

pub mod accept;
pub mod accept_encoding;
pub mod accept_patch;
pub mod accept_ranges;
pub mod access_control_allow_credentials;
pub mod access_control_allow_origin;
pub mod alpn;
pub mod alt_svc;
pub mod auth_param;
pub mod auth_scheme;
pub mod authority;
pub mod base64;
pub mod basic_credentials;
pub mod boundary;
pub mod bws;
pub mod cache;
pub mod cache_control;
pub mod challenge;
pub mod charset;
pub mod clear_site_data;
pub mod comment;
pub mod conditional;
pub mod connection;
pub mod content_coding;
pub mod content_disposition;
pub mod content_length;
pub mod content_location;
pub mod content_range;
pub mod content_security_policy;
pub mod content_transfer_encoding;
pub mod content_type;
pub mod cookie;
pub mod credentials;
pub mod cross_origin;
pub mod delta_seconds;
pub mod deprecation;
pub mod digest;
pub mod digest_credentials;
pub mod domain;
pub mod early_data;
pub mod etag;
pub mod expect;
pub mod expires;
pub mod ext_value;
pub mod field;
pub mod forwarded;
pub mod host;
pub mod http3_goaway;
pub mod http3_max_push_id;
pub mod http3_settings;
pub mod http_date;
pub mod http_version;
pub mod if_range;
pub mod keep_alive;
pub mod language;
pub mod last_modified;
pub mod link;
pub mod list;
pub mod location;
pub mod mailbox;
pub mod max_forwards;
pub mod media_range;
pub mod media_type;
pub mod method;
pub mod multipart_body;
pub mod node;
pub mod oauth2;
pub mod origin;
pub mod origin_agent_cluster;
pub mod parameter;
pub mod permissions_policy;
pub mod pragma;
pub mod prefer;
pub mod priority;
pub mod problem_details;
pub mod product;
pub mod proxy_authenticate;
pub mod proxy_connection;
pub mod quic_transport_parameters;
pub mod quoted_pair;
pub mod quoted_string;
pub mod qvalue;
pub mod range;
pub mod referer;
pub mod refresh;
pub mod request_target;
pub mod retry_after;
pub mod sec_fetch;
pub mod sec_websocket_accept;
pub mod sec_websocket_extensions;
pub mod sec_websocket_key;
pub mod sec_websocket_protocol;
pub mod sec_websocket_version;
pub mod server_timing;
pub mod status;
pub mod strict_transport_security;
pub mod structured_fields;
pub mod te;
pub mod token;
pub mod token68;
pub mod trailer;
pub mod transfer_coding;
pub mod transfer_encoding;
pub mod upgrade;
pub mod uri;
pub mod user_agent;
pub mod validator;
pub mod vary;
pub mod via;
pub mod warning;
pub mod websocket_frame;
pub mod well_known;
pub mod x_content_type_options;
pub mod x_frame_options;
pub mod x_xss_protection;

/// Whether a defect exists because the traffic was observed through a proxy.
///
/// **Two variants rather than a `bool`**, because the marked state needs
/// somewhere to carry its name and because a second instrument class was
/// considered and rejected rather than merely not built — see
/// [`ByTheProxy`](Induced::ByTheProxy).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Induced {
    /// Traffic on the wire, whoever is watching. Every entry but the marked
    /// ones, which is why it is the default and why the `defects!` key that
    /// sets it is the one key an entry may leave out.
    #[default]
    No,
    /// **This proxy's presence in the path is what produced what is being
    /// reported.** `proxy_connection_obsolete` is the entry the distinction was
    /// written for: the field exists to be sent *to a proxy*, so a capture
    /// taken without one cannot contain it, and a session that runs through
    /// this proxy provokes exactly what it then reports. The finding is still
    /// true and still the client's — it says something real about that client —
    /// but a reader deserves to know it is looking at a reflection.
    ///
    /// **What this deliberately does not mark is a defect the *probe* causes.**
    /// `accept_encoding_missing` fires on nearly every session under `curl`,
    /// because curl sends no `Accept-Encoding` unless asked. That is a fact
    /// about curl, not about this crate: marking it would have the catalogue
    /// assert which clients trip which defects, which is unbounded and wrong
    /// the moment a client changes a default — and worse in the case that
    /// matters, since an operator running a curl invocation through CI *is*
    /// testing that invocation, and the finding is a true report about the
    /// client under test. Quieting what a probe causes is a driver's business
    /// and belongs in configuration, not here.
    ByTheProxy,
}

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
///
/// Which is why nothing constructs one of these by hand. `defects!` writes
/// the `static` and its registration together, and
/// `every_defect_comes_from_the_macro` keeps that the only way in.
pub struct ViolationDef {
    /// This violation's id: the `[violations.<id>]` section that configures
    /// it, the `Violation.violation` its findings will carry, the
    /// `docs/violations/<id>.md` page that documents it, and the link every
    /// rule page that reports it carries. Disjoint from the rule ids — see
    /// `violation_ids_are_unique_and_disjoint_from_rule_ids`.
    ///
    /// `<subject>[_<part>]_<defect>`, the defect drawn from the closed list
    /// "Violation ids" in `docs/development.md` defines and
    /// `every_violation_id_names_a_defect` checks. A rule id names a claim and
    /// a violation id names the defect that breaks it, which is why the two
    /// vocabularies cannot collide — and why the id names the defect rather
    /// than the rule reporting it, since two rules may report one defect.
    pub id: &'static str,
    /// One line naming the defect, in the four places the catalogue is read
    /// out: the lead line of its `docs/violations/<id>.md` page, the summary
    /// beside it in the `docs/violations.md` index, the bullet beside it on
    /// every rule page that reports it, and the comment above its
    /// `[violations.<id>]` section in `config_example.toml`.
    ///
    /// Not a heading: a page is headed by the id, since a title is a sentence
    /// with no derivable relation to the name a finding carried.
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
    /// The sentences this defect enforces. Empty while the reading has not
    /// happened yet, or when nothing states the requirement — an unread
    /// sentence is carried as absent, never as a guess.
    ///
    /// This is where a `// cite` comment moves to when its statement becomes a
    /// def. The quote sits beside the reference it quotes, and the rule site
    /// keeps none.
    ///
    /// # Why more than one
    ///
    /// Almost every entry names exactly one, and the shape to reach for first
    /// is a single-element slice. What made this a slice instead of an
    /// `Option` is the requirement written *once per protocol version*: RFC
    /// 9113 § 8.2.2 and RFC 9114 § 4.2 state the same prohibition about the
    /// same defect, both in force at the same time, and neither is *the*
    /// sentence. Holding one would cite the wrong document on half the
    /// findings; splitting the entry in two would give one defect two ids,
    /// which is the duplication this catalogue exists to remove. So the entry
    /// holds both, and [`RuleContext::finding`](crate::rules::RuleContext)
    /// carries a citation onto a finding only when there is exactly one to
    /// carry — a message governed by two documents names its own section in
    /// its own words, as it did while these entries had no reference at all.
    ///
    /// This is not a licence to pile on further reading. A second entry means
    /// the defect genuinely has two governing statements and no way to choose
    /// between them from the catalogue; anything a rule merely wants a reader
    /// to know belongs in
    /// [`specifications()`](crate::rules::RuleMeta::specifications).
    pub spec: &'static [SpecRef],
    /// Whether the instrument produced what this reports. Defaults to
    /// [`Induced::No`], one of the three keys in this struct an entry may
    /// omit: an entry that says nothing is describing traffic, which is what
    /// all but one of them do.
    pub induced: Induced,
    /// What the sentence this defect enforces obliges, and of whom.
    ///
    /// [`Strength::Unstated`] by default, and the default is the honest answer
    /// for a third of the catalogue — see the type. Where it is *not*
    /// unstated, [`Strength::default_severity`] fixes `default_severity`
    /// above, and `a_stated_strength_sets_the_default_severity` holds the two
    /// together.
    ///
    /// **This is a reading, not a scan.** A `// cite` comment beside the entry
    /// carries the sentence; a machine can see the keyword in it and cannot see
    /// whom the keyword binds. So the reading is written here once and the
    /// mechanical half is checked against the comment by
    /// `a_stated_strength_quotes_the_keyword_it_claims`.
    pub strength: Strength,
    /// Why this entry's severity is not the one its strength implies.
    ///
    /// `None` for all but a handful. A def that states a strength takes the
    /// level that strength maps to; anything else is a decision someone made
    /// against the mapping, and this is where the decision is written — on the
    /// entry, where a reader of the catalogue is, rather than in a side file
    /// nobody opens. `a_stated_strength_sets_the_default_severity` prints it
    /// when it fails, so the argument is what a maintainer sees first.
    ///
    /// The archetype is `cookie_path_control_character_forbidden`: RFC 6265
    /// § 4.1.1 states its own grammar as "Servers SHOULD NOT send Set-Cookie
    /// headers that fail to conform to the following grammar", weakly and for
    /// historical reasons, and a control character in a cookie `Path` is a
    /// hazard regardless. The mapping says `warn`; the entry says `error` and
    /// says why.
    ///
    /// **Capped, not merely available.** `few_defects_depart_from_their_strength`
    /// is a ceiling in the shape `few_defects_blame_the_instrument` already
    /// established: an escape hatch with no ceiling stops being an exception.
    pub departure: Option<&'static str>,
}

/// Define a subject's defects, and register every one of them.
///
/// The body is one entry per defect, each written as its `ViolationDef`
/// fields. The doc comment and the `// cite` comment quoting the sentence the
/// defect enforces go above the entry, where they would sit on any other item:
///
/// ```ignore
/// defects! {
///     /// What this defect is, and why it is its own entry.
///     FIELD_VALUE_MALFORMED = {
///         id: "field_value_malformed",
///         title: "Field value does not match the grammar",
///         message: "",
///         default_severity: Severity::Warn,
///         spec: &[RFC_9110_5_5],
///     }
/// }
/// ```
///
/// What it buys, at a catalogue this size, is that the two ways a def can be
/// written wrong stop being writable:
///
/// - **`static`, never `const`.** A `const` is inlined at each use, so the
///   `ptr::eq` lookup [`crate::rules::RuleContext::report`] does misses and the
///   configured severity is unreachable. It compiles and it is wrong at run
///   time, which is the worst shape a mistake can have.
/// - **Registered, always.** The `#[distributed_slice]` entry is what puts a
///   def in the catalogue, and it is separate from the def itself. Forgotten,
///   the defect still reports — the rule declares it, the severity resolves —
///   and vanishes from everything that *enumerates* the catalogue: no
///   `[violations.<id>]` section, no `docs/violations/<id>.md` page, and no
///   bullet on the page of any rule that reports it. That last clause was
///   aspiration when it was written and is now literally true.
///
/// Three keys may be left out, and are written in this order when they are
/// not: `strength`, then `departure`, then `induced`. Each defaults to the
/// answer that says nothing — `Strength::Unstated`, no departure, traffic
/// rather than instrument — so an entry states only what someone read.
///
/// Each entry hides its registration in an anonymous `const` block, so every
/// one can use the same name for it: the linker collects the section entry, and
/// nothing needs a second name derived from the first.
macro_rules! defects {
    // Internal arms, and they come first because the general arm below would
    // otherwise try to read `@induced` as an entry. They exist so `induced:`
    // can be left out of an entry entirely: `Default::default()` is not const,
    // and a second whole arm for the marked case would have the five ordinary
    // keys written twice.
    (@induced) => {
        $crate::violations::Induced::No
    };
    (@induced $value:expr) => {
        $value
    };
    (@strength) => {
        $crate::lint::Strength::Unstated
    };
    (@strength $value:expr) => {
        $value
    };
    (@departure) => {
        ::core::option::Option::None
    };
    (@departure $value:expr) => {
        ::core::option::Option::Some($value)
    };
    ($(
        $(#[$attr:meta])*
        $name:ident = {
            id: $id:literal,
            title: $title:literal,
            message: $message:literal,
            default_severity: $severity:expr,
            spec: $spec:expr,
            $(strength: $strength:expr,)?
            $(departure: $departure:expr,)?
            $(induced: $induced:expr,)?
        }
    )*) => {$(
        $(#[$attr])*
        pub static $name: $crate::violations::ViolationDef = $crate::violations::ViolationDef {
            id: $id,
            title: $title,
            message: $message,
            default_severity: $severity,
            spec: $spec,
            induced: $crate::violations::defects!(@induced $($induced)?),
            strength: $crate::violations::defects!(@strength $($strength)?),
            departure: $crate::violations::defects!(@departure $($departure)?),
        };

        const _: () = {
            #[linkme::distributed_slice($crate::violations::REGISTERED_VIOLATIONS)]
            static REGISTRATION: &$crate::violations::ViolationDef = &$name;
        };
    )*};
}
pub(crate) use defects;

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

/// The catalogue entry a finding's `violation` id names, or `None`.
///
/// A finding carries the id and nothing else — `Violation` is what survives a
/// capture file, so it holds owned strings and no pointer back here. Anything
/// that wants the *catalogue's* words about a defect (its one-line title, the
/// severity it would carry unconfigured, the sentences it enforces) comes
/// through this. A binary search, because [`VIOLATIONS`] is sorted by id and
/// the report looks a defect up once per finding.
///
/// `None` for a finding built the pre-catalogue way, where the rule id is the
/// only name it has, and for a capture written by a build whose catalogue held
/// an id this one has since renamed — an old file is read, not rejected.
pub fn by_id(id: &str) -> Option<&'static ViolationDef> {
    VIOLATIONS
        .binary_search_by_key(&id, |d| d.id)
        .ok()
        .map(|i| VIOLATIONS[i])
}

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
    /// tables, but they are read by the same person — and the two catalogues
    /// are two page trees, so a shared name would mean `docs/rules/x.md` and
    /// `docs/violations/x.md`, a pair no reader can tell apart from a link and
    /// no sentence can name without spelling out which table it means.
    ///
    /// The rationale used to be about anchor collision inside a rule's page,
    /// which was a layout considered and not built.
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

    /// A def written out longhand is a def that can be `const` and a def that
    /// can go unregistered — the two mistakes `defects!` exists to make
    /// unwritable, one of which is invisible until an operator's
    /// `[violations.<id>]` silently does nothing. So the macro is not merely
    /// available, it is the only way in: a subject file states its defects and
    /// nothing else.
    ///
    /// Textual, like `no_rule_constructs_a_violation_literal`, and for the same
    /// reason — what is being refused is a *shape of source*, which no type can
    /// express.
    /// **A ceiling, not a floor**, and the only one in this file — every other
    /// gate here ratchets a number upward.
    ///
    /// A catalogue that decides many of its own defects are artefacts of its own
    /// presence is a catalogue that has stopped reporting traffic, and the
    /// pressure runs the wrong way: marking a noisy finding as induced is an
    /// easy way to quieten it, and the argument for doing so is always
    /// available. So the count is capped and a second entry has to arrive in a
    /// commit that argues for it, rather than sliding in behind a number nobody
    /// reads.
    ///
    /// Read what the assertion prints. A second entry wants the argument
    /// written on it, not this constant bumped.
    #[test]
    fn few_defects_blame_the_instrument() {
        const CEILING: usize = 1;
        let induced: Vec<&str> = VIOLATIONS
            .iter()
            .filter(|d| d.induced == Induced::ByTheProxy)
            .map(|d| d.id)
            .collect();
        assert!(
            induced.len() <= CEILING,
            "{} defects are marked as induced by the proxy, above the ceiling of {CEILING}: {induced:?}",
            induced.len(),
        );
    }

    #[test]
    fn every_defect_comes_from_the_macro() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/violations");
        for entry in std::fs::read_dir(&dir).expect("cannot read src/violations") {
            let path = entry.expect("a directory entry").path();
            if path.extension().is_none_or(|e| e != "rs")
                || path.file_name().is_some_and(|n| n == "mod.rs")
            {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("a subject file");
            for (i, line) in src.lines().enumerate() {
                assert!(
                    !line.contains("= ViolationDef {"),
                    "{}:{}: defects are declared in a defects! block, which registers them \
                     and keeps them `static`",
                    path.display(),
                    i + 1,
                );
            }
        }
    }

    /// Every defect a rule declares must be in the catalogue, and the only
    /// thing that puts it there is its own `#[distributed_slice]` entry beside
    /// it. A def with no entry still works on the finding path — the rule
    /// declares it, the severity resolves, findings carry its id — and is
    /// absent from everything that enumerates the catalogue instead: no
    /// `[violations.<id>]` section to tune it with, no docs, no gate. Nothing
    /// else notices, because every other check reads one side or the other.
    ///
    /// By identity, not by id: two defs with one id are what
    /// `violation_ids_are_unique_and_disjoint_from_rule_ids` is for, and a
    /// declared def whose *twin* is registered is exactly the confusion this
    /// would otherwise pass.
    #[test]
    fn every_declared_violation_is_registered() {
        for rule in crate::rules::all_rules() {
            for def in rule.violations() {
                assert!(
                    VIOLATIONS.iter().any(|d| std::ptr::eq(*d, *def)),
                    "{} declares {}, which no distributed_slice entry registers",
                    rule.id(),
                    def.id,
                );
            }
        }
    }

    /// Every registered defect is declared by some rule — the converse of
    /// `every_declared_violation_is_registered`, which this file had in one
    /// direction and not the other.
    ///
    /// A def nothing declares is unreachable: no rule can report it, so its
    /// `[violations.<id>]` section tunes nothing and its page names no rule.
    /// It is not a compile error and it is not a run-time one either — it is a
    /// catalogue entry describing a defect the linter cannot find, which reads
    /// exactly like one it can.
    ///
    /// A merge is how one appears. Folding two rules into one, or moving a
    /// reading to a shared helper, leaves behind the defs the retired side was
    /// the only declarer of, and nothing else looks.
    #[test]
    fn every_defect_is_reported_by_some_rule() {
        let declared: std::collections::HashSet<&str> = crate::rules::all_rules()
            .flat_map(|rule| rule.violations().iter().map(|def| def.id))
            .collect();
        let orphans: Vec<&str> = VIOLATIONS
            .iter()
            .map(|def| def.id)
            .filter(|id| !declared.contains(id))
            .collect();
        assert!(
            orphans.is_empty(),
            "no rule declares these defects, so nothing can report them: {:?}",
            orphans,
        );
    }

    /// A def's `spec` is what its findings cite, and `specifications()` is
    /// what the rule's doc page lists — so a def citing a document its rule
    /// never names would put a reference in a report that the docs do not
    /// explain. This is `cited`'s debug assertion, moved to a gate: the check
    /// it made per finding site is answerable once, for the whole catalogue,
    /// now that the reference lives on the def.
    ///
    /// `specifications()` stays deliberately wider than the cited set — it may
    /// carry further-reading a defect does not enforce — so this is one-way.
    #[test]
    fn every_violation_spec_is_declared_by_its_rule() {
        for rule in crate::rules::all_rules() {
            for def in rule.violations() {
                for spec in def.spec {
                    assert!(
                        rule.specifications().contains(spec),
                        "{} reports {}, which cites {} {} — not in the rule's specifications()",
                        rule.id(),
                        def.id,
                        spec.spec,
                        spec.section.unwrap_or("(whole document)"),
                    );
                }
            }
        }
    }

    /// An upward ratchet on the defs, not on the finding sites: the sentence a
    /// defect enforces is now something the catalogue can hold, and the point
    /// of the migration is that it does. `citation_coverage_does_not_regress`
    /// counts sites and keeps the old shape honest until the last one
    /// converts; this counts entries and keeps the new one honest from the
    /// first.
    ///
    /// Not every defect can have one, which is why this is a floor and not an
    /// equality. `cookie_path_whitespace_invalid` is the first proof: no
    /// specification asks for it, this crate refuses the character anyway, and
    /// carrying a citation there would be a guess dressed as a reference.
    /// `content_length_numeral_invalid` is the second, and its reason is a
    /// different one worth having beside the first: that value *derives* from
    /// its production — `1*DIGIT` sets no ceiling — and what refuses it is this
    /// crate's inability to represent it, which no document asked for either.
    ///
    /// **There was a third reason and it is retired.** Two entries —
    /// `field_connection_specific_forbidden` and `te_member_forbidden` — were
    /// uncited not because no sentence states them but because two do: RFC 9113
    /// § 8.2.2 and RFC 9114 § 4.2 write the same requirement once per version,
    /// both in force at the same time, and a [`ViolationDef`] held a single
    /// [`SpecRef`], so naming either would have put an HTTP/2 citation on an
    /// HTTP/3 finding half the time. This docstring recorded a third entry of
    /// that shape as the threshold at which `spec` should become a slice, and
    /// the threshold was reached. So `spec` is a slice, both entries name both
    /// sections, and the count below is of entries with **at least** one.
    ///
    /// **A third reason has since been written, and it is about a sentence that
    /// does not exist either**: `keep_alive_timeout_invalid` reports a value
    /// above a bound *an operator configured*, and no document states a maximum
    /// for that parameter. It is the first entry whose limit belongs to neither
    /// a specification nor this crate, and a reference on it would dress a
    /// deployment's policy as a requirement.
    ///
    /// **A fourth reason arrived with `weight_duplicated`, and it is the first
    /// that is not about a missing sentence.** `[ weight ]` is bracketed once
    /// per field — RFC 9110 § 10.1.4, § 12.5.1, § 12.5.3 and § 12.5.4 each
    /// print it for their own — and one entry is declared by the rules that
    /// read those fields. `every_violation_spec_is_declared_by_its_rule`
    /// compares a def's references against *each* declaring rule's, so a
    /// shared entry may only name a sentence every declarer states, and no
    /// rule here states another field's production. **The slice answers a def
    /// whose sections are all stated by one rule and cannot answer a def whose
    /// sections are stated one per rule** — so this is the shape to look for
    /// next time an entry has too many sentences rather than none.
    ///
    /// **What is left uncited is those four reasons only** — three of them
    /// about sentences that do not exist. An entry naming two is still the exception
    /// rather than a licence: no finding of one carries a citation, because
    /// none of the sentences governs the message on its own.
    #[test]
    fn every_violation_declares_a_spec() {
        /// Raised by the commit that adds defs with specs; never lowered.
        ///
        /// **It sat at 318 through four commits that said they had raised it**,
        /// because those commits edited this line by *number* in a file whose
        /// numbering they had just changed, and a floor is a one-way assertion:
        /// nothing fails when it is left too low. The gate stayed green and the
        /// catalogue grew past it unwatched. Two things follow — never address
        /// this constant by line, and read a ratchet's *number* when a commit
        /// claims to have moved it, because the only evidence that a floor
        /// moved is the floor.
        ///
        /// **It was one behind again when `structured_headers_valid`
        /// converted**: 419 defs cited a sentence against a floor of 418, so
        /// some earlier commit added a cited entry and left this alone. The
        /// two entries that rule declares make it 421, which is the count and
        /// not the previous number plus two — the recipe is to read what the
        /// failing assertion prints, never to increment. The `priority`
        /// subject was read the same way: 425 of 447, and 428 of 450 when the
        /// Structured Fields reader was typed, and 429 of 451 with the
        /// `Priority` response's caching entry, and 432 of 454 with
        /// `Permissions-Policy`'s two, and 435 of 457 with the trailer
        /// section's three, and 436 of 460 with the authentication loop's one,
        /// and 437 of 461 with the shared realm, and 439 of 463 with the two
        /// method-content entries, and 443 of 467 with the well-known
        /// subject's four, and 446 of 470 with `Refresh`'s three, and
        /// 449 of 473 with the media type's suffix entries, and 452 of 476
        /// with the OAuth 2.0 `state` subject, and 453 of 477 with `Vary`'s
        /// `Prefer` entry, and 455 of 479 with the range request's two, and 456
        /// of 480 with the first entry whose subject is a cache, and 458 of 482
        /// with the last unconverted rule's two, and 463 of 487 with the two
        /// CORS origin rules' five, and 467 of 493 with the Fetch Metadata
        /// family's six — of which two name nothing, for the reason above — and
        /// 470 of 497 with the three cross-origin policies' four, and 477 of
        /// 505 with the `Prefer` exchange's seven, and 480 of 508 with the
        /// three one-site fields, 482 of 510 with the deprecation pair, 484
        /// of 513 with the three timestamp comparisons, 489 of 518 with the
        /// `Forwarded` field's own grammar, and 490 of 520 with the `name` a
        /// `form-data` disposition has to carry — where the entry beside it
        /// names nothing, because the value it reports derives — and 492 of 523
        /// with the two legacy security fields, whose third entry names nothing
        /// either, because no document ever defined the field it is about, and
        /// 493 of 524 with the `=` a ranges-specifier is written around, and 495
        /// of 526 with the assembly `Server` and `User-Agent` share — where the
        /// entry two rules declare cites Appendix A, because the collected ABNF
        /// is the one section printing a production neither field's own section
        /// restates, and 497 of 528 with the two `Connection`-shaped lists —
        /// where one entry is what a sender may *declare* about the hop and the
        /// other what a declaration may *announce* about the section after it,
        /// and 501 of 532 with the four things `Referer` says past its grammar
        /// — a subject where every entry is about disclosure and none about the
        /// reference being well formed. **`location_empty` is the third field to
        /// report one empty `URI-reference` and the third entry to name no
        /// sentence for it**, so 533 entries still cite 501: an entry that
        /// exists because *no* production refuses a value can never move this
        /// number, and three of them now say so on one value. 502 of 534 with
        /// the draft ALPN token, which is the reverse case in one commit: a
        /// site that *was* cited gave its sentence to an entry, so the floor
        /// here rose as the site floor fell. 503 of 535 with the method token
        /// written in another case — **the last sentence to leave a finding
        /// site for an entry**, since `self.cited(` has no caller left in
        /// `src/rules/`. 504 of 536 with the response to a `HEAD` that carries
        /// octets — a requirement the *method's* definition states about a
        /// message the method did not travel in. **537 entries still cite 504**:
        /// the version floor a WebSocket handshake requires is a sentence in
        /// whichever document defines the exchange, so an entry two protocols
        /// could declare can name none of them.
        const FLOOR: usize = 504;
        let cited = VIOLATIONS.iter().filter(|d| !d.spec.is_empty()).count();
        assert!(
            cited >= FLOOR,
            "{cited} of {} defs cite a sentence, below the floor of {FLOOR}",
            VIOLATIONS.len(),
        );
    }

    /// The closed vocabulary a violation id ends in. Each word is defined in
    /// "Violation ids" in `docs/development.md`, beside the claim it breaks;
    /// this array and that table are extended in one commit or not at all.
    const DEFECT_ENDINGS: &[&str] = &[
        "ambiguous",
        "conflicting",
        "duplicated",
        "empty",
        "forbidden",
        "ignored",
        "invalid",
        "malformed",
        "misdirected",
        "missing",
        "obsolete",
        "redundant",
        "unregistered",
        "unsolicited",
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

    /// **No message restates the citation the finding already carries.**
    ///
    /// A finding prints its message and then its specification reference, so a
    /// message ending `(RFC 9114 §7.2.4)` puts the same six words on screen
    /// twice — once in the sentence and once in the label beside it. Neither
    /// place was wrong on its own; the duplication is only visible composed,
    /// which is exactly the kind of thing nobody sees while writing one entry.
    ///
    /// Fixed messages only. A parameterised message is a format string at the
    /// rule site and is not reachable from here, so this holds the half of the
    /// catalogue it can reach and the sweep held the other half by hand. What
    /// it does *not* forbid is a message naming some **other** document, or
    /// naming its own inside the sentence's grammar — "RFC 9110 §13.1.2
    /// requires a 304" is a sentence using its reference, not repeating it.
    #[test]
    fn no_message_restates_its_own_citation() {
        let mut offenders = Vec::new();
        for def in VIOLATIONS.iter() {
            if def.message.is_empty() {
                continue;
            }
            for spec in def.spec {
                let Some(section) = spec.section else {
                    continue;
                };
                let label = format!("{} \u{a7}{section}", spec.spec);
                if def.message.contains(&label) {
                    offenders.push(format!("{}: message repeats `{label}`", def.id));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "the citation is printed beside the message; drop it from the message:\n{}",
            offenders.join("\n")
        );
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
            "conditional_etag_syntax",
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

    /// Every `// cite` comment in this tree, attached to the def whose doc
    /// block it sits in.
    ///
    /// Returns `(id, source, quoted text)`. A cite in a module doc or in a test
    /// belongs to no entry and is not returned — 21 of the 564 in this tree are
    /// one of those, and attaching them to whatever def happened to follow is
    /// the failure mode this shape exists to avoid.
    ///
    /// **A textual read, like `every_defect_comes_from_the_macro`, and for the
    /// same reason**: what is being checked is a relation between an entry and
    /// the *comment* above it, and a comment is not reachable from any type. It
    /// is safe to read this way because the shape is uniform — every one of the
    /// cites in `src/violations/` is a single line ending in its closing quote,
    /// which `a_cite_is_one_line` pins so this parse cannot silently start
    /// missing half of one.
    ///
    /// It deliberately does not read `specs/specs_generated.yaml`, which holds
    /// the same sentences with their file and line. That file is `apycite`'s
    /// derivation of these comments; reading it here would put a YAML parser
    /// between this gate and the text it is checking, to learn something the
    /// text says directly.
    fn cites_by_violation() -> Vec<(String, String, String)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/violations");
        let mut out = Vec::new();
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
            .expect("cannot read src/violations")
            .map(|e| e.expect("a directory entry").path())
            .filter(|p| p.extension().is_some_and(|e| e == "rs"))
            .filter(|p| p.file_name().is_some_and(|n| n != "mod.rs"))
            .collect();
        files.sort();
        for path in files {
            let src = std::fs::read_to_string(&path).expect("a subject file");
            let lines: Vec<&str> = src.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                // An entry opens at exactly one indent inside the `defects!`
                // block: `    NAME = {`. Nothing else in these files is written
                // that way.
                let Some(rest) = line.strip_prefix("    ") else {
                    continue;
                };
                if rest.starts_with(' ') || !rest.ends_with(" = {") {
                    continue;
                }
                if !rest
                    .trim_end_matches(" = {")
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                {
                    continue;
                }
                // The id is in the body, which is where the catalogue's own
                // name for this entry lives — the `static`'s name is a second
                // spelling of it and not the one anything else uses.
                let id = lines[i..]
                    .iter()
                    .take_while(|l| l.trim() != "}")
                    .find_map(|l| {
                        l.trim()
                            .strip_prefix("id: \"")
                            .and_then(|r| r.strip_suffix("\","))
                    })
                    .unwrap_or_else(|| panic!("{}:{}: entry with no id", path.display(), i + 1));
                // Walk the contiguous comment block above the entry. A blank
                // line ends it: two entries are always separated by one, so
                // this cannot reach past the entry above.
                for line in lines[..i].iter().rev() {
                    let trimmed = line.trim();
                    if !trimmed.starts_with("//") {
                        break;
                    }
                    if let Some((source, text)) = parse_cite(trimmed) {
                        out.push((id.to_string(), source.to_string(), text.to_string()));
                    }
                }
            }
        }
        out
    }

    /// The token a citation comment opens with, assembled rather than spelled.
    ///
    /// Written out, it would be cite-shaped text that `apycite` cannot read as
    /// a citation, and its `marker_outside_comments` gate refuses that for a
    /// good reason: a quote in that shape is a quote nobody is verifying. This
    /// scanner needs the token as *data*, so it gets it as data — and every
    /// fixture below builds its sample lines from this rather than writing one.
    const MARKER: &str = concat!("ci", "te(");

    /// A citation comment split into the source it names and the sentence it
    /// quotes, or `None` for a comment that is not one.
    ///
    /// The comment has to *open* with the marker once its slashes are off, not
    /// merely contain it. Prose in a doc comment may talk about the form —
    /// [`cites_by_violation`] above does — and a scan that matched anywhere
    /// would read that sentence as a citation of a document called "source".
    fn parse_cite(comment: &str) -> Option<(&str, &str)> {
        let rest = comment.trim_start_matches('/').trim_start();
        let (source, rest) = rest.strip_prefix(MARKER)?.split_once("): \"")?;
        Some((source, rest.strip_suffix('"')?))
    }

    /// Whether `line` is an attempt at a citation: a comment opening with the
    /// marker. What [`a_cite_is_one_line`] holds to the one-line shape, and the
    /// same test [`parse_cite`] applies before it splits.
    fn opens_a_cite(line: &str) -> bool {
        let trimmed = line.trim();
        trimmed.starts_with("//")
            && trimmed
                .trim_start_matches('/')
                .trim_start()
                .starts_with(MARKER)
    }

    /// Whether `text` states `word` as an RFC 2119 keyword: the letters in
    /// upper case, standing as a whole word.
    ///
    /// Upper case only, which is RFC 8174's rule and not a shortcut — HTTP's
    /// documents are full of lower-case "must" and "should" used descriptively,
    /// and 35 entries in this catalogue cite one. Treating those as
    /// requirements is exactly the mistake this vocabulary exists to prevent.
    fn states_keyword(text: &str, word: &str) -> bool {
        let bytes = text.as_bytes();
        text.match_indices(word).any(|(at, _)| {
            let before = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
            let after_at = at + word.len();
            let after = after_at == bytes.len() || !bytes[after_at].is_ascii_alphanumeric();
            before && after
        })
    }

    /// Every RFC 2119 keyword, in the spelling that makes it one.
    ///
    /// The negated forms are absent because they contain the positive one —
    /// `MUST NOT` states `MUST` — and [`states_keyword`] matches on a word
    /// boundary, so seven entries answer for all twelve.
    ///
    /// `MAY` and `OPTIONAL` are here for the same reason the other five are:
    /// what the ratchet asks is whether an entry has been read, and a
    /// permission is as readable as a requirement. Nine entries quote one and
    /// state nothing, because the permission is granted to the peer they do not
    /// report.
    const KEYWORDS: &[&str] = &[
        "MUST",
        "SHALL",
        "REQUIRED",
        "SHOULD",
        "RECOMMENDED",
        "MAY",
        "OPTIONAL",
    ];

    /// Whether `text` is the conformance sentence itself: a `MUST` about
    /// matching a grammar.
    ///
    /// The other half of what satisfies a `Grammar` entry. Almost all of them
    /// quote the production they measure a value against, and RFC 9110 § 2.2 is
    /// what turns that production into an obligation — but two entries quote
    /// § 2.2 *directly*, because the request-target has forms rather than one
    /// production and no single rule name is the thing the value failed to
    /// derive from. Both spellings are the same claim, so both are accepted.
    fn is_conformance_sentence(text: &str) -> bool {
        states_keyword(text, "MUST") && text.contains("grammar")
    }

    /// Whether `text` is an ABNF rule definition: a rule name, `=` or `=/`,
    /// and something after it.
    ///
    /// The shape RFC 5234 § 2.2 prints, and the reason a `Grammar` entry needs
    /// no keyword of its own — what obliges it is RFC 9110 § 2.2, which
    /// obliges every production at once.
    fn is_abnf_production(text: &str) -> bool {
        let text = text.trim_start();
        let name: String = text
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if name.is_empty() || !name.starts_with(|c: char| c.is_ascii_alphabetic()) {
            return false;
        }
        let rest = text[name.len()..].trim_start();
        let rest = rest.strip_prefix('=').map(|r| r.trim_start_matches('/'));
        rest.is_some_and(|r| r.starts_with(char::is_whitespace) && !r.trim().is_empty())
    }

    /// **The parse above is only safe while every cite is one line.**
    ///
    /// A cite whose quoted sentence wrapped onto a second line would be read
    /// here as a truncated sentence, and a truncated sentence is exactly where
    /// a keyword goes missing without anything failing. `apycite` has its own
    /// reasons to want them unwrapped; this is the gate that lets
    /// [`cites_by_violation`] assume it.

    #[test]
    fn a_cite_is_one_line() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/violations");
        for entry in std::fs::read_dir(&dir).expect("cannot read src/violations") {
            let path = entry.expect("a directory entry").path();
            if path.extension().is_none_or(|e| e != "rs")
                || path.file_name().is_some_and(|n| n == "mod.rs")
            {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("a subject file");
            for (i, line) in src.lines().enumerate() {
                if opens_a_cite(line) {
                    assert!(
                        parse_cite(line.trim()).is_some(),
                        "{}:{}: a cite is written on one line, ending in its closing quote",
                        path.display(),
                        i + 1,
                    );
                }
            }
        }
    }

    /// **Gate A: a defect that states what its sentence obliges takes the level
    /// that obligation carries.**
    ///
    /// [`Strength::default_severity`] is the mapping and the only copy of it.
    /// An entry may depart from it — RFC 6265 writes its own grammar as a
    /// `SHOULD NOT` and a control character in a cookie `Path` is a hazard
    /// anyway — but a departure is a decision, so it is written on the entry in
    /// `departure:` and printed here when this fails.
    ///
    /// Two directions, because both are wrong in ways nothing else notices:
    /// an entry whose level contradicts its reading with no argument, and an
    /// argument on an entry whose level does not contradict anything. The
    /// second is what a departure becomes after someone fixes the severity and
    /// leaves the prose, and it reads to the next maintainer as a live
    /// exception.
    #[test]
    fn a_stated_strength_sets_the_default_severity() {
        let mut wrong = Vec::new();
        for def in VIOLATIONS.iter() {
            match (def.strength.default_severity(), def.departure) {
                (Some(implied), None) if implied != def.default_severity => wrong.push(format!(
                    "{}: states {} and so reports at {}, but its default is {} — \
                     move it, or write a `departure:` saying why not",
                    def.id,
                    def.strength.name(),
                    implied.name(),
                    def.default_severity.name(),
                )),
                (Some(implied), Some(why)) if implied == def.default_severity => {
                    wrong.push(format!(
                        "{}: departs from nothing — it states {} and already reports at {}. \
                         Drop the departure: {why}",
                        def.id,
                        def.strength.name(),
                        implied.name(),
                    ))
                }
                (None, Some(why)) => wrong.push(format!(
                    "{}: states no strength, so there is nothing to depart from: {why}",
                    def.id,
                )),
                _ => {}
            }
        }
        assert!(
            wrong.is_empty(),
            "{} defects disagree with what they say their sentence obliges:\n{}",
            wrong.len(),
            wrong.join("\n"),
        );
    }

    /// **Gate B: a defect that claims a keyword quotes one.**
    ///
    /// The half of the reading a machine can check. A `Must` entry has to cite
    /// a sentence stating `MUST`, `MUST NOT`, `SHALL`, `SHALL NOT` or
    /// `REQUIRED`; a `Should` entry one stating `SHOULD`, `SHOULD NOT` or
    /// `RECOMMENDED`; a `May` entry one stating `MAY` or `OPTIONAL`; a
    /// `Grammar` entry an ABNF production.
    ///
    /// # It is deliberately one-directional
    ///
    /// Nothing here objects to an entry that quotes a `MUST` and states
    /// [`Strength::Unstated`]. That is not an oversight, it is the point: 16
    /// entries quote a `MUST` addressed to the *recipient* —
    /// `conditional_date_redundant` quotes "a recipient MUST ignore
    /// If-Modified-Since if the request contains an If-None-Match header
    /// field", and the client that sent both broke nothing — and they are
    /// `info` correctly. A converse gate would fail on every one of them, and
    /// the pressure would be to relabel them rather than to keep them right.
    ///
    /// So this test can say "you claimed a keyword that is not there" and can
    /// never say "you missed one". The second question is a reading, and
    /// `every_defect_states_a_strength` is what keeps it from going unasked.
    #[test]
    fn a_stated_strength_quotes_the_keyword_it_claims() {
        let cites = cites_by_violation();
        let mut wrong = Vec::new();
        for def in VIOLATIONS.iter() {
            let words: &[&str] = match def.strength {
                Strength::Must => &["MUST", "SHALL", "REQUIRED"],
                Strength::Should => &["SHOULD", "RECOMMENDED"],
                Strength::May => &["MAY", "OPTIONAL"],
                Strength::Grammar | Strength::Unstated => &[],
            };
            let quoted: Vec<&str> = cites
                .iter()
                .filter(|(id, _, _)| id == def.id)
                .map(|(_, _, text)| text.as_str())
                .collect();
            let satisfied = match def.strength {
                Strength::Grammar => quoted
                    .iter()
                    .any(|t| is_abnf_production(t) || is_conformance_sentence(t)),
                Strength::Unstated => true,
                _ => quoted
                    .iter()
                    .any(|t| words.iter().any(|w| states_keyword(t, w))),
            };
            if !satisfied {
                wrong.push(format!(
                    "{}: states {}, and none of its {} cited sentences {}",
                    def.id,
                    def.strength.name(),
                    quoted.len(),
                    match def.strength {
                        Strength::Grammar =>
                            "is an ABNF production or the conformance sentence".to_string(),
                        _ => format!("states {}", words.join(" / ")),
                    },
                ));
            }
        }
        assert!(
            wrong.is_empty(),
            "{} defects claim a reading their cited text does not carry:\n{}",
            wrong.len(),
            wrong.join("\n"),
        );
    }

    /// The parse and the two predicates, pinned against text written here
    /// rather than against the catalogue — so the convention holds whatever the
    /// catalogue happens to contain, which is the same reason
    /// `the_id_shape_takes_a_defect_and_refuses_a_claim` exists.
    #[test]
    fn the_keyword_scan_reads_case_and_word_boundaries() {
        // RFC 8174: the keyword is the upper-case spelling. Everything else is
        // a document using an English word.
        assert!(states_keyword(
            "A sender MUST NOT generate BWS in messages.",
            "MUST"
        ));
        assert!(!states_keyword(
            "the request-uri's scheme must denote a \"secure\" protocol",
            "MUST"
        ));
        // A whole word, so a keyword inside a longer token is not one.
        assert!(!states_keyword("MUSTARD is not a keyword", "MUST"));
        assert!(states_keyword("value MUST be a Date", "MUST"));
        // Productions, in the two forms RFC 5234 prints.
        assert!(is_abnf_production("Content-Length = 1*DIGIT"));
        assert!(is_abnf_production(
            "alternative   = protocol-id \"=\" alt-authority"
        ));
        assert!(is_abnf_production("qdtext =/ obs-text"));
        // Prose that happens to contain an `=` is not a production.
        assert!(!is_abnf_production(
            "Clients MUST ignore \"persist\" parameters with values other than \"1\"."
        ));
        assert!(!is_abnf_production("= leads with the operator"));
        assert!(!is_abnf_production("trailing = "));
        // The conformance sentence, which stands in for a production on the
        // two entries whose value derives from a set of forms rather than one
        // rule. A MUST about anything else is not it.
        assert!(is_conformance_sentence(
            "A sender MUST NOT generate protocol elements that do not match the \
             grammar defined by the corresponding ABNF rules."
        ));
        assert!(!is_conformance_sentence(
            "The value of this header field MUST be 13."
        ));
        // The citation parse, including the two shapes it must refuse. Every
        // sample is built from `MARKER` rather than written out: a citation
        // spelled in a string literal is a quote `apycite` cannot verify, and
        // it fails the tree for exactly that.
        let good = format!("// {MARKER}RFC 9110 \u{a7} 8.6): \"Content-Length = 1*DIGIT\"");
        assert_eq!(
            parse_cite(&good),
            Some(("RFC 9110 \u{a7} 8.6", "Content-Length = 1*DIGIT")),
        );
        assert!(opens_a_cite(&format!("    {good}")));
        assert_eq!(parse_cite("// an ordinary comment"), None);
        assert_eq!(
            parse_cite(&format!("// {MARKER}RFC 9110 \u{a7} 8.6): \"unterminated")),
            None,
        );
        // Prose about the form is not the form.
        let prose = format!("/// Every `// {MARKER}source): \"text\"` comment");
        assert_eq!(parse_cite(&prose), None);
        assert!(!opens_a_cite(&prose));
    }

    /// The 37 entries that quote an RFC 2119 keyword or an ABNF production and
    /// state [`Strength::Unstated`] anyway.
    ///
    /// **Every one has been read, and each says on its own page what the
    /// reading found** — a keyword binding the recipient, a sentence whose
    /// antecedent no capture can reach, a store the finding reconstructs and
    /// cannot attribute, or two reporting sites governed by two different
    /// keywords. This list is not an exemption from that reading; it is the
    /// record that it happened.
    ///
    /// **It may only shrink.** Nothing here can enforce that — a baseline never
    /// can — but a line added to it is a visible diff on a reviewed file, which
    /// is the whole mechanism `specs/ratchet.txt` runs on and the reason that
    /// migration finished. A new defect whose cited sentence carries a keyword
    /// states what the keyword obliges, or someone writes its id here and says
    /// in the entry above it why not.
    const READ_AND_UNSTATED: &[&str] = &[
        "accept_ranges_ignored",
        "access_control_allow_credentials_redundant",
        "alt_svc_parameter_empty",
        "alt_svc_persist_invalid",
        "alt_svc_port_empty",
        "alt_svc_port_invalid",
        "alt_svc_port_missing",
        "authority_value_conflicting",
        "cache_control_missing",
        "cache_control_must_revalidate_ignored",
        "cache_control_no_cache_ignored",
        "cache_control_no_store_ignored",
        "cache_control_private_ignored",
        "cache_control_storage_conflicting",
        "cache_response_conflicting",
        "conditional_date_ignored",
        "conditional_date_redundant",
        "content_range_missing",
        "content_range_numeral_invalid",
        "cookie_scope_ignored",
        "early_data_duplicated",
        "expires_conflicting",
        "location_redirect_redundant",
        "method_case_invalid",
        "oauth2_state_conflicting",
        "preference_applied_unsolicited",
        "referer_empty",
        "status_101_unsolicited",
        "status_301_ambiguous",
        "status_302_ambiguous",
        "status_401_ignored",
        "status_invalid",
        "strict_transport_security_directive_value_forbidden",
        "structured_field_malformed",
        "trailer_connection_option_forbidden",
        "trailer_member_invalid",
        "transfer_encoding_coding_redundant",
        "vary_ignored",
        "well_known_name_empty",
        "well_known_name_malformed",
    ];

    /// **The ratchet: a defect whose cited sentence carries a keyword or a
    /// production has to say what it makes of it.**
    ///
    /// Gate B can say "you claimed a keyword that is not there" and, for the
    /// reason its own comment gives, can never say "you missed one" — an entry
    /// quoting a `MUST` addressed to the recipient is right to state nothing,
    /// and a converse gate would fail on every one of them. This is the
    /// converse question asked the only way it can be: not "is this entry
    /// wrong" but "has anybody looked".
    ///
    /// [`Strength::Unstated`] is two claims wearing one word — *nothing binds
    /// this sender* and *nobody has read this yet* — and the whole risk of the
    /// vocabulary is that the second hides inside the first. So the entries
    /// where the two are told apart are the ones with a keyword or a production
    /// in front of them, and those are enumerated. Everything else is
    /// `Unstated` because there is nothing to read.
    ///
    /// Two directions, like Gate A: a new entry that needs a line, and a stale
    /// line for an entry that has since stated a strength or lost its citation.
    /// The second is what keeps the list shrinking rather than merely not
    /// growing.
    #[test]
    fn every_defect_that_quotes_a_keyword_states_a_reading() {
        let cites = cites_by_violation();
        let mut unread = Vec::new();
        let mut quotes_something: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        for def in VIOLATIONS.iter() {
            let quoted: Vec<&str> = cites
                .iter()
                .filter(|(id, _, _)| id == def.id)
                .map(|(_, _, text)| text.as_str())
                .collect();
            let readable = quoted
                .iter()
                .any(|t| is_abnf_production(t) || KEYWORDS.iter().any(|w| states_keyword(t, w)));
            if !readable {
                continue;
            }
            quotes_something.insert(def.id);
            if def.strength == Strength::Unstated && !READ_AND_UNSTATED.contains(&def.id) {
                unread.push(format!(
                    "{}: quotes a keyword or a production and states no reading. Say what it \
                     obliges of the sender, or add the id to READ_AND_UNSTATED and say on the \
                     entry why it obliges nothing",
                    def.id,
                ));
            }
        }
        let stale: Vec<&&str> = READ_AND_UNSTATED
            .iter()
            .filter(|id| {
                by_id(id).is_none_or(|def| {
                    def.strength != Strength::Unstated || !quotes_something.contains(def.id)
                })
            })
            .collect();
        assert!(
            unread.is_empty(),
            "{} defects have not been read:\n{}",
            unread.len(),
            unread.join("\n"),
        );
        assert!(
            stale.is_empty(),
            "these ids no longer need a line in READ_AND_UNSTATED — delete them: {stale:?}",
        );
    }

    /// **A ceiling, and the second one in this file** — see
    /// `few_defects_blame_the_instrument`, which this is shaped after and for
    /// the same reason.
    ///
    /// A departure is an argument that the mapping is wrong about one entry.
    /// Each one is defensible; what is not defensible is a catalogue where the
    /// mapping is advisory, and the pressure runs that way, because writing a
    /// sentence is always easier than moving a level and re-reading what the
    /// move does to a report. So they are counted, and the count is small
    /// enough that a new one arrives in a commit that argues for it.
    ///
    /// Read what the assertion prints. A further departure wants the argument
    /// written on its entry, not this constant bumped.
    #[test]
    fn few_defects_depart_from_their_strength() {
        const CEILING: usize = 3;
        let departures: Vec<&str> = VIOLATIONS
            .iter()
            .filter(|d| d.departure.is_some())
            .map(|d| d.id)
            .collect();
        assert!(
            departures.len() <= CEILING,
            "{} defects depart from the severity their strength implies, above the \
             ceiling of {CEILING}: {departures:?}",
            departures.len(),
        );
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
