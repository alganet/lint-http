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

#[cfg(test)]
mod tests {
    use super::*;

    /// A capture line written before the `cite` field existed still parses,
    /// and an un-cited finding still serializes byte-identically to what that
    /// older line held — the capture format is unchanged until a rule
    /// actually cites.
    #[test]
    fn legacy_capture_line_round_trips_without_cite() {
        let legacy = r#"{"rule":"host_header","severity":"warn","message":"m"}"#;
        let v: Violation = serde_json::from_str(legacy).expect("pre-cite line parses");
        assert!(v.cite.is_none());
        assert_eq!(serde_json::to_string(&v).expect("serializes"), legacy);
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
