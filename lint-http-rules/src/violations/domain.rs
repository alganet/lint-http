// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Domain name defects — the preferred name syntax, wherever a field carries a
//! host name.
//!
//! These are the clearest case for a catalogue that is not indexed by rule.
//! A `Set-Cookie` `Domain`, a `From` mailbox's domain half and every other
//! field holding a name are all answered by the same five sentences of RFC
//! 1035, through the same helper — so an operator who does not care about a
//! hyphen at the edge of a label should be able to say so once, not once per
//! field. Each rule that reads a name declares these; none of them owns one.
//!
//! The `name` defects are about the whole string and the `label` defects about
//! one dot-separated piece of it, which is also the order the helper checks
//! them in.

use crate::helpers::domain::PreferredNameDefect;
use crate::lint::Severity;
use crate::rules::SpecRef;
use crate::violations::{defects, ViolationDef};

/// The preferred name syntax: what a label may be made of, and how long it may
/// be. One section behind four of the five defects here, which is why they are
/// four entries rather than one — the sentence does not distinguish them, and
/// an operator tuning them does.
pub const RFC_1035_2_3_1: SpecRef = SpecRef {
    spec: "RFC 1035",
    section: Some("2.3.1"),
    url: "https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.1",
    note: "Preferred name syntax — labels start with a letter, end with a letter or digit, hold only letters, digits and hyphen, and run to 63 characters",
};

/// The size limits, which are stated where the sizes are, not with the
/// grammar.
pub const RFC_1035_2_3_4: SpecRef = SpecRef {
    spec: "RFC 1035",
    section: Some("2.3.4"),
    url: "https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4",
    note: "Size limits — a name is 255 octets or less",
};

defects! {
    /// A name over 255 octets. Not a grammar failure — every label in it may
    /// be well formed — which is why it is `_invalid` and not `_malformed`.
    ///
    // cite(RFC 1035 § 2.3.4): "names 255 octets or less"
    DOMAIN_NAME_LENGTH_INVALID = {
        id: "domain_name_length_invalid",
        title: "Domain name is longer than 255 octets",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_1035_2_3_4],
    }

    /// Whitespace or a control character anywhere in the name — checked over
    /// the whole string, before it is split into labels, because neither can
    /// appear in any of them.
    ///
    // cite(RFC 1035 § 2.3.1): "They must start with a letter, end with a letter or digit, and have as interior characters only letters, digits, and hyphen."
    DOMAIN_NAME_WHITESPACE_OR_CONTROL_FORBIDDEN = {
        id: "domain_name_whitespace_or_control_forbidden",
        title: "Domain name holds whitespace or a control character",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_1035_2_3_1],
    }

    /// A `.` with nothing between it and its neighbour: `a..example` or a name
    /// that opens on the separator.
    ///
    // cite(RFC 1035 § 2.3.1): "They must start with a letter, end with a letter or digit, and have as interior characters only letters, digits, and hyphen."
    DOMAIN_LABEL_EMPTY = {
        id: "domain_label_empty",
        title: "Domain name has an empty label",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_1035_2_3_1],
    }

    /// One label over 63 characters, in a name that may be inside its own
    /// limit.
    ///
    // cite(RFC 1035 § 2.3.1): "Labels must be 63 characters or less."
    DOMAIN_LABEL_LENGTH_INVALID = {
        id: "domain_label_length_invalid",
        title: "Domain label is longer than 63 characters",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_1035_2_3_1],
    }

    /// A label opening or closing on `-`. Only the hyphen is checked at the
    /// ends: § 2.3.1 asks for a letter first and RFC 1123 § 2 relaxed that to
    /// a letter or a digit, so a leading digit is not this defect.
    ///
    // cite(RFC 1035 § 2.3.1): "They must start with a letter, end with a letter or digit, and have as interior characters only letters, digits, and hyphen."
    DOMAIN_LABEL_EDGE_HYPHEN_FORBIDDEN = {
        id: "domain_label_edge_hyphen_forbidden",
        title: "Domain label starts or ends with a hyphen",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_1035_2_3_1],
    }

    /// A label octet outside letters, digits and hyphen — an underscore, most
    /// often.
    ///
    // cite(RFC 1035 § 2.3.1): "They must start with a letter, end with a letter or digit, and have as interior characters only letters, digits, and hyphen."
    DOMAIN_LABEL_CHARACTER_FORBIDDEN = {
        id: "domain_label_character_forbidden",
        title: "Domain label holds a character outside letters, digits and hyphen",
        message: "",
        default_severity: Severity::Warn,
        spec: &[RFC_1035_2_3_1],
    }
}

/// The defect a [`PreferredNameDefect`] reports as, for every field that reads
/// a name through the shared syntax.
pub fn preferred_name_defect(defect: PreferredNameDefect) -> &'static ViolationDef {
    match defect {
        PreferredNameDefect::TooLong => &DOMAIN_NAME_LENGTH_INVALID,
        PreferredNameDefect::EmptyLabel => &DOMAIN_LABEL_EMPTY,
        PreferredNameDefect::LabelTooLong => &DOMAIN_LABEL_LENGTH_INVALID,
        PreferredNameDefect::LabelHyphenAtEdge => &DOMAIN_LABEL_EDGE_HYPHEN_FORBIDDEN,
        PreferredNameDefect::LabelBadCharacter => &DOMAIN_LABEL_CHARACTER_FORBIDDEN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mapping, spelled out: a variant answering with the wrong def would
    /// report the right complaint under the wrong name and the wrong
    /// configured severity, and every other gate here would pass.
    #[test]
    fn each_preferred_name_defect_maps_to_its_own_id() {
        for (defect, id) in [
            (PreferredNameDefect::TooLong, "domain_name_length_invalid"),
            (PreferredNameDefect::EmptyLabel, "domain_label_empty"),
            (
                PreferredNameDefect::LabelTooLong,
                "domain_label_length_invalid",
            ),
            (
                PreferredNameDefect::LabelHyphenAtEdge,
                "domain_label_edge_hyphen_forbidden",
            ),
            (
                PreferredNameDefect::LabelBadCharacter,
                "domain_label_character_forbidden",
            ),
        ] {
            assert_eq!(preferred_name_defect(defect).id, id);
        }
    }
}
