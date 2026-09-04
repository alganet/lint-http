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

impl std::fmt::Display for SpecCitation {
    /// `RFC 9110 §7.2 <url>` — the form the text report and logs append to a
    /// cited finding.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.section {
            Some(section) => write!(f, "{} §{} {}", self.spec, section, self.url),
            None => write!(f, "{} {}", self.spec, self.url),
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
        }
    }
}

/// Severity level for a rule violation. Ordered by increasing severity
/// (`Info < Warn < Error`) so callers can gate on a minimum level.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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
