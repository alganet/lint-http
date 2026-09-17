// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Lint result types.
//!
//! The dispatch engine that produces these from a transaction lives in the
//! `lint-http-rules` crate, in its `engine` module — it sits above the rule
//! catalogue, while these data types sit below it (every rule returns a
//! [`Violation`]). This crate depends on no other, so the reference is by name:
//! the arrow only points one way.

use serde::{Deserialize, Serialize};

/// A structured reference to the specification text a finding enforces.
///
/// Owned strings, unlike the rule metadata this is built from: a finding
/// round-trips through serde (captures are re-read by `lint <captures>` and
/// by capture seeding), and `&'static str` cannot come back out of a file.
/// The allocation happens only on the rare finding path.
///
/// Deliberately absent: the quoted sentence. The verbatim text lives in the
/// `// cite` comment at the enforcing statement, where it is verified against
/// the published document — copying it here would create a second, unverified
/// copy that can drift. `spec + section + url` is enough to open the exact
/// text.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SpecCitation {
    /// The document, in the vocabulary `specs/sources.yaml` uses: `"RFC 9110"`.
    pub spec: String,
    /// The section within it: `"7.2"`. `None` when the reference names the
    /// document as a whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// Where to read it.
    pub url: String,
}

impl SpecCitation {
    /// The document and section alone: `RFC 9110 §7.2`.
    ///
    /// What a report shows when it can put the URL somewhere other than the
    /// line — behind a terminal hyperlink, or on an expanded sub-line. The
    /// section number is spelled here *and* in the URL fragment, so a report
    /// printing both spells it twice for no reader who wanted it twice.
    pub fn label(&self) -> String {
        match &self.section {
            Some(section) => format!("{} §{}", self.spec, section),
            None => self.spec.clone(),
        }
    }
}

impl std::fmt::Display for SpecCitation {
    /// `RFC 9110 §7.2 <url>` — the form a report falls back to when it cannot
    /// make the label itself clickable, and the form the logs use.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.label(), self.url)
    }
}

/// Who a finding holds answerable: the peer that wrote the message the
/// evidence was found in.
///
/// The proxy records each half of a transaction as its own peer wrote it —
/// `tx.request` before hop-by-hop stripping, `tx.response` before filtering —
/// so "which half the evidence is in" is a statement about which peer produced
/// it, not merely about where a rule happened to look.
///
/// # This is not [`MessageDirection`](crate::protocol_event::MessageDirection)
///
/// [`MessageDirection`](crate::protocol_event::MessageDirection) records which
/// *leg* a frame was observed on. This records who a *report* holds answerable.
/// The two agree on ordinary traffic and come apart the moment a message is not
/// written by the peer whose position it occupies — which happens here: a proxy
/// error reply is recorded in the response half and no origin wrote it. One
/// type for both would make that difference unsayable, so a protocol finding
/// *derives* this from its event's direction, and the derivation is a
/// conversion written once rather than an identity.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Party {
    /// The sender of the request.
    Client,
    /// The sender of the response.
    Server,
    /// The defect is in the exchange rather than in either message, so no one
    /// peer wrote it. `authentication_failure_loop` is the shape: its own
    /// description names "a broken client, misconfigured credentials, or a
    /// flawed authentication handshake" and declines to choose between them.
    ///
    /// Distinct from an *absent* party, which says only that nobody has read
    /// the site yet. This one is an answer; that one is the absence of one.
    Neither,
}

impl From<crate::protocol_event::MessageDirection> for Party {
    /// Who sent a frame is who is answerable for what is wrong with it.
    ///
    /// **True of a frame and not of a transaction**, which is why this
    /// conversion exists and its transaction-level equivalent does not. A
    /// protocol event is one message with one sender, recorded on the leg it
    /// was observed on. A transaction is two messages by two authors fused into
    /// one record — the request as the client wrote it, the response as the
    /// origin did — so nothing about a transaction converts to a single party,
    /// and a rule that reads both halves has to say which half a finding came
    /// from.
    fn from(direction: crate::protocol_event::MessageDirection) -> Self {
        match direction {
            crate::protocol_event::MessageDirection::Client => Self::Client,
            crate::protocol_event::MessageDirection::Server => Self::Server,
        }
    }
}

impl Party {
    /// The name this party goes by outside the type: what `--about` accepts,
    /// and what a capture file records. One vocabulary, spelled once, for the
    /// same reason [`Severity::name`] is.
    pub fn name(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
            Self::Neither => "neither",
        }
    }
}

/// Represents a single rule violation detected by the linter.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Violation {
    pub rule: String,
    /// The catalogue id of the defect this finding reports, when the rule named
    /// one. That is the name `[violations.<id>]` tunes and the one an operator
    /// grepping a capture for a single defect can use — a rule that says four
    /// different things reports them under four of these and one `rule`.
    ///
    /// Empty when the finding was built the pre-catalogue way, where the rule
    /// id is the only name a report has. Serde-defaulted both ways, exactly as
    /// `cite` was: a capture written before the field existed reads back with
    /// it empty, and a finding that names no defect serializes as it always has.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub violation: String,
    pub severity: Severity,
    pub message: String,
    /// The specification text this finding enforces, when the rule attached
    /// one at the violation site. Serde-defaulted both ways: captures written
    /// before the field existed read back as `None`, and an un-cited finding
    /// serializes exactly as it always has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cite: Option<SpecCitation>,
    /// Who this finding holds answerable, when the rule that made it said.
    ///
    /// `None` is not a third answer: it means no one has yet read this
    /// reporting site and decided. A report must therefore never treat it as
    /// "neither" and quietly drop it under a narrowing filter — the two are
    /// told apart at the only place that narrows, and counted separately.
    ///
    /// Serde-defaulted both ways, exactly as `cite` and `violation` were: a
    /// capture written before the field existed reads back with it absent, and
    /// an unattributed finding serializes exactly as it always has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party: Option<Party>,
    /// True when this finding exists because the traffic was observed through
    /// a proxy — the field a client sends only *because* one is configured, and
    /// which a capture taken without one cannot contain.
    ///
    /// **A `bool` where `party` directly above is an `Option`, and the contrast
    /// is the argument for both.** "Not induced" and "nothing said" are the same
    /// fact about a finding; "neither peer" and "not yet read" are two different
    /// ones. A field whose absence and whose `false` mean the same thing does
    /// not need three states.
    ///
    /// Copied onto the finding rather than looked up from the catalogue when a
    /// report is drawn, following `cite`: a capture has to stay readable by a
    /// build whose catalogue has moved on.
    #[serde(default, skip_serializing_if = "is_not_induced")]
    pub proxy_induced: bool,
    /// What the sentence this defect enforces obliges, and of whom — the
    /// catalogue's [`Strength`], copied onto the finding.
    ///
    /// Copied rather than looked up, following `cite` and `proxy_induced`: a
    /// capture has to stay readable by a build whose catalogue has moved on,
    /// and a consumer asking "show me only the broken MUSTs" should not have to
    /// carry a copy of the catalogue to ask it.
    ///
    /// **A plain value where `party` is an `Option`**, for the reason
    /// `proxy_induced` is a `bool`: [`Strength::Unstated`] and "nobody has read
    /// this yet" are the same fact about a finding, so a third state would
    /// distinguish nothing. It is skipped on the wire, so a finding whose
    /// defect states no reading serializes exactly as it always has.
    #[serde(default, skip_serializing_if = "is_unstated")]
    pub strength: Strength,
}

/// `skip_serializing_if` for [`Violation::strength`]. A free function for the
/// same reason [`is_not_induced`] is one: serde needs a path.
fn is_unstated(strength: &Strength) -> bool {
    matches!(strength, Strength::Unstated)
}

/// `skip_serializing_if` for [`Violation::proxy_induced`]. A free function
/// because serde needs a path and `bool` has no inherent method that reads
/// right at the call site.
fn is_not_induced(induced: &bool) -> bool {
    !*induced
}

impl Violation {
    /// Construct an un-cited finding. Rule code goes through the `Rule` /
    /// `ProtocolRule` `violation()` helpers instead (which fill `rule` from
    /// the rule itself); this constructor serves the callers that have only a
    /// rule *name* — fixtures, replay tooling, tests.
    pub fn new(rule: impl Into<String>, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            violation: String::new(),
            severity,
            message: message.into(),
            cite: None,
            party: None,
            proxy_induced: false,
            strength: Strength::Unstated,
        }
    }
}

/// Severity level for a rule violation. Ordered by increasing severity
/// (`Info < Warn < Error`) so callers can gate on a minimum level.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    /// The name this level goes by outside the type: what a configuration
    /// writes, what a generated configuration renders, and what a report
    /// prints. One vocabulary, spelled once — the config reader, the config
    /// generator and the text report each used to spell it out themselves,
    /// which is three places for a fourth level to be forgotten.
    pub fn name(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    /// The level a configuration named, or `None` for a name that is not one
    /// of the three. The exact inverse of [`name`](Severity::name), so what
    /// the generator writes is always what the reader accepts. Callers phrase
    /// their own error: what a bad name means differs between a rule's table
    /// and a violation's.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "info" => Some(Self::Info),
            "warn" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// What the specification sentence a defect enforces obliges, and of whom.
///
/// Not the RFC 2119 keyword by itself. A keyword binds *somebody*, and the
/// only reading that says anything about a defect is the one that binds the
/// **sender of the message the defect is in** — RFC 9110 § 13.1.3 says "a
/// recipient MUST ignore `If-Modified-Since` if the request contains an
/// `If-None-Match` header field", which is an obligation on the server and
/// leaves the client that sent both having broken no sentence at all. So a def
/// quoting a `MUST` is not thereby [`Must`](Strength::Must); a def quoting a
/// `MUST` *addressed to the sender it is reporting* is.
///
/// # Sender and recipient, not client and server
///
/// Deliberately coarser than [`Party`], which names the peer a *finding* holds
/// answerable. 69 defects are reported by rules of differing party, because the
/// same syntax defect occurs in either half — `bws_forbidden`,
/// `etag_delimiter_missing`, `media_type_empty` — so "which peer" has no answer
/// at catalogue level. "Whoever wrote this message" always does: "a sender MUST
/// NOT generate BWS in messages" binds whichever half the octet turned up in.
///
/// # Why this is a level and not a lookup
///
/// The keyword is mechanically readable out of the `// cite` comment beside a
/// def; the addressee is not, and no regex has ever got it right. This field is
/// where the reading is written down once, so that the half a machine can check
/// — that a def claiming `Must` does quote a `MUST` — is checked on every run,
/// and the half only a reader can settle is settled in review. See
/// `a_stated_strength_quotes_the_keyword_it_claims` in the rules crate.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Strength {
    /// `MUST`, `MUST NOT`, `SHALL`, `SHALL NOT` or `REQUIRED`, binding the
    /// sender of the message. The message breaks a requirement, so the finding
    /// is an `error`.
    Must,
    /// `SHOULD`, `SHOULD NOT`, `RECOMMENDED` or `NOT RECOMMENDED`, binding the
    /// sender. Advice a specification gives in its own voice and the sender
    /// declined, so the finding is a `warn`.
    Should,
    /// `MAY` or `OPTIONAL`: a permission the sender did not take up, or a
    /// component its own definition marks optional. Nothing is broken and the
    /// finding is worth saying anyway, so it is an `info`.
    May,
    /// The defect is a value that does not derive from the ABNF production it
    /// quotes.
    ///
    /// The obligation is not in the quoted production — a grammar states no
    /// keyword — it is in the one sentence that governs every production HTTP
    /// has: *"A sender MUST NOT generate protocol elements that do not match
    /// the grammar defined by the corresponding ABNF rules"* (RFC 9110 § 2.2).
    /// That is a sender-binding `MUST`, so this maps to `error` exactly as
    /// [`Must`](Strength::Must) does.
    ///
    /// **It is a separate variant because the evidence is different, not
    /// because the level is.** A `Must` def quotes its requirement on itself; a
    /// `Grammar` def quotes a production and inherits the requirement. Keeping
    /// the two apart means the 147 defects that inherit it can be re-levelled
    /// by one line here if that judgement is ever revisited, instead of by
    /// re-reading 147 entries to find out which ones were which.
    Grammar,
    /// The default, and the honest answer far more often than not.
    ///
    /// Either nothing states a requirement about this defect at all — 37
    /// entries cite no sentence, because the value is refused by this
    /// implementation, or the bound was configured by a deployment — or a
    /// keyword is present and binds the *recipient*, and so says nothing about
    /// the sender being reported. Severity is then the author's, argued in the
    /// doc comment above the entry, and no gate derives it.
    Unstated,
}

impl Default for Strength {
    /// [`Unstated`](Strength::Unstated), which is what a defect nobody has read
    /// says — and what a capture written before this field existed reads back
    /// as. The two are the same claim, which is why one value serves both.
    fn default() -> Self {
        Self::Unstated
    }
}

impl Strength {
    /// The name this reading goes by outside the type: what a generated
    /// configuration comments, what a documentation page prints, and what a
    /// finding carries on the wire. One vocabulary, spelled once, exactly as
    /// [`Severity::name`] is.
    pub fn name(self) -> &'static str {
        match self {
            Self::Must => "must",
            Self::Should => "should",
            Self::May => "may",
            Self::Grammar => "grammar",
            Self::Unstated => "unstated",
        }
    }

    /// The severity a defect carries by default when it states this reading,
    /// or `None` where the reading derives no level.
    ///
    /// [`Unstated`](Strength::Unstated) is the `None`, and it is the whole
    /// reason this returns an `Option` rather than a `Severity`: a defect no
    /// sentence obliges still has a level, and that level is a judgement
    /// nothing here can make for it.
    ///
    /// This is the mapping, and it is the only copy of it. The gate that holds
    /// the catalogue to it, the documentation page that prints it and the
    /// argument in `docs/development.md` all name this function rather than
    /// restating the three-way correspondence.
    pub fn default_severity(self) -> Option<Severity> {
        match self {
            Self::Must | Self::Grammar => Some(Severity::Error),
            Self::Should => Some(Severity::Warn),
            Self::May => Some(Severity::Info),
            Self::Unstated => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A capture line written before the `cite` and `violation` fields existed
    /// still parses, and a finding carrying neither still serializes
    /// byte-identically to what that older line held — the capture format is
    /// unchanged until a rule actually cites or names a defect.
    #[test]
    fn legacy_capture_line_round_trips_without_cite() {
        let legacy = r#"{"rule":"host_header","severity":"warn","message":"m"}"#;
        let v: Violation = serde_json::from_str(legacy).expect("pre-cite line parses");
        assert!(v.cite.is_none());
        assert!(v.violation.is_empty());
        assert_eq!(serde_json::to_string(&v).expect("serializes"), legacy);
    }

    /// A finding that names the peer answerable for it carries that name into
    /// the capture, spelled the way `--about` accepts it.
    #[test]
    fn an_attributed_finding_round_trips_with_its_party() {
        for (party, word) in [
            (Party::Client, "client"),
            (Party::Server, "server"),
            (Party::Neither, "neither"),
        ] {
            let v = Violation {
                party: Some(party),
                ..Violation::new("host_header", Severity::Warn, "m")
            };
            let json = serde_json::to_string(&v).expect("serializes");
            assert_eq!(
                json,
                format!(
                    r#"{{"rule":"host_header","severity":"warn","message":"m","party":"{word}"}}"#
                ),
            );
            let back: Violation = serde_json::from_str(&json).expect("parses");
            assert_eq!(back.party, Some(party));
            // The wire word and the word a report prints are one vocabulary.
            assert_eq!(party.name(), word);
        }
    }

    /// **The migration is invisible in the capture file until a rule is read.**
    /// A finding nobody has attributed serializes to the bytes it always did —
    /// which is what makes it safe to land the field long before the catalogue
    /// has an answer for it. `legacy_capture_line_round_trips_without_cite`
    /// above asserts the same thing from the reading side; this is the writing
    /// side, and the two together are the whole back-compat claim.
    #[test]
    fn an_unattributed_finding_omits_the_party_key() {
        let v = Violation::new("host_header", Severity::Warn, "m");
        assert_eq!(v.party, None);
        assert_eq!(
            serde_json::to_string(&v).expect("serializes"),
            r#"{"rule":"host_header","severity":"warn","message":"m"}"#,
        );
    }

    /// A capture written by a build that knows about parties is still read by
    /// one that does not — the other direction of the same promise, and the
    /// reason nothing here carries `deny_unknown_fields`. Standing in for the
    /// older binary with a key no `Violation` has ever had.
    #[test]
    fn a_finding_carrying_an_unknown_key_is_read_rather_than_refused() {
        let future = r#"{"rule":"host_header","severity":"warn","message":"m","party":"client","some_later_field":7}"#;
        let v: Violation = serde_json::from_str(future).expect("an unknown key is ignored");
        assert_eq!(v.party, Some(Party::Client));
    }

    /// A finding that exists because a proxy is in the path says so, and one
    /// that does not serializes exactly as it always did — the same
    /// both-ways default `party` and `cite` carry, and the reason the marker
    /// could be added to a shipped capture format at all.
    #[test]
    fn only_an_induced_finding_carries_the_marker() {
        let plain = Violation::new("host_header", Severity::Warn, "m");
        assert!(!plain.proxy_induced);
        assert_eq!(
            serde_json::to_string(&plain).expect("serializes"),
            r#"{"rule":"host_header","severity":"warn","message":"m"}"#,
        );

        let induced = Violation {
            proxy_induced: true,
            ..Violation::new("host_header", Severity::Warn, "m")
        };
        let json = serde_json::to_string(&induced).expect("serializes");
        assert_eq!(
            json,
            r#"{"rule":"host_header","severity":"warn","message":"m","proxy_induced":true}"#,
        );
        let back: Violation = serde_json::from_str(&json).expect("parses");
        assert!(back.proxy_induced);
    }

    /// A finding that names the defect it reports carries both names: the rule
    /// that ran, and the entry an operator tunes.
    #[test]
    fn a_finding_naming_its_defect_round_trips_with_both_names() {
        let v = Violation {
            violation: "host_header_absent".to_string(),
            ..Violation::new("host_header", Severity::Error, "m")
        };
        let json = serde_json::to_string(&v).expect("serializes");
        assert_eq!(
            json,
            r#"{"rule":"host_header","violation":"host_header_absent","severity":"error","message":"m"}"#
        );
        let back: Violation = serde_json::from_str(&json).expect("parses");
        assert_eq!(back.violation, v.violation);
    }

    /// The two halves of the severity vocabulary are inverses, which is what
    /// lets the generated configuration be read back by the configuration
    /// reader. A level whose name did not parse back would be a section the
    /// generator writes and the loader rejects.
    #[test]
    fn every_severity_name_parses_back_to_its_level() {
        for level in [Severity::Info, Severity::Warn, Severity::Error] {
            assert_eq!(Severity::from_name(level.name()), Some(level));
        }
        assert_eq!(Severity::from_name("fatal"), None);
        assert_eq!(Severity::from_name("Warn"), None);
    }

    #[test]
    fn cited_finding_round_trips_with_its_citation() {
        let v = Violation {
            cite: Some(SpecCitation {
                spec: "RFC 9110".to_string(),
                section: Some("7.2".to_string()),
                url: "https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2".to_string(),
            }),
            ..Violation::new("host_header", Severity::Warn, "m")
        };
        let json = serde_json::to_string(&v).expect("serializes");
        assert!(json.contains("\"cite\""));
        let back: Violation = serde_json::from_str(&json).expect("parses");
        assert_eq!(back.cite, v.cite);
    }

    #[test]
    fn sectionless_citation_omits_the_section_key() {
        let c = SpecCitation {
            spec: "Fetch".to_string(),
            section: None,
            url: "https://fetch.spec.whatwg.org/".to_string(),
        };
        let json = serde_json::to_string(&c).expect("serializes");
        assert!(!json.contains("section"));
        let back: SpecCitation = serde_json::from_str(&json).expect("parses");
        assert_eq!(back, c);
    }
}
