// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! What a response's `Vary` field nominates.
//!
//! Three answers, not two, which is the whole reason this is a typed enum and
//! not a `Vec<String>`: a response may nominate a set of field names, may
//! nominate `*` — which is not a name and never matches — or may say nothing at
//! all. A caller that flattened the middle case into an empty set would read
//! "varies on everything, cache nothing" as "varies on nothing".
//!
//! The field is read across the whole section, because it is a list field and
//! one list however many lines carry it.

use crate::helpers::headers::combined_field_value_as_written;
use crate::helpers::list::list_members;
use hyper::HeaderMap;

/// What a response's `Vary` nominates.
///
/// The two arms are the two alternatives of `Vary = #( "*" / field-name )`, and
/// they are kept apart because a caller cannot treat them the same: `*` says the
/// response varies on something a request's fields do not name, which RFC 9111
/// § 4.1 turns into *always fails to match*, while a list of names is something
/// a cache can compare. A member of `*` anywhere in the list makes the whole
/// value that, since the sentence says *containing a member*.
pub enum VaryNomination {
    /// Some member is `*`.
    Wildcard,
    /// The field names nominated, folded to lowercase, in the order written.
    /// Empty for a field that is absent and for a zero-element list, which
    /// nominate the same nothing.
    Fields(Vec<String>),
}

impl VaryNomination {
    /// Whether `name` is nominated. `*` nominates every name.
    pub fn nominates(&self, name: &str) -> bool {
        match self {
            Self::Wildcard => true,
            Self::Fields(fields) => {
                let name = name.trim().to_ascii_lowercase();
                fields.contains(&name)
            }
        }
    }

    /// Whether some member is `*`.
    pub fn is_wildcard(&self) -> bool {
        matches!(self, Self::Wildcard)
    }
}

/// Read a response's `Vary` field.
///
/// **Three rules asked this question and the three disagreed; two of them were
/// wrong, and in the same two ways.** Both read `get_all("vary")` line by line
/// and bailed on a line `to_str` refused — one returning no finding, the other
/// silently skipping the line — so a single `obs-text` octet anywhere in the
/// value stood the whole rule down. And neither joined the lines, so a `*`
/// written on a second field line was a `*` to the third rule and not to them.
/// § 5.3 makes the lines one value; the field is a `#` list, which is what
/// licenses the join.
///
/// The walk is [`list_members`] — a naive comma split, `OWS`-trimmed, empty
/// members dropped — and this is its second caller. **Naive is the right answer
/// here and it is the grammar that says so**: `Vary`'s members are `"*"` and
/// `field-name`, and a `field-name` is a `token`, which admits no
/// `quoted-string`. Where an element cannot hold one, a DQUOTE is a character
/// the member may not have, and reading it as opening a quoted-string makes the
/// *next* comma data when there is no quoted-string for it to be data in — so
/// `Vary: "x, prefer` nominates `Prefer`, and the quote-aware walk one caller
/// used said it did not.
///
/// The fold is licensed: a `field-name` is a field name.
// cite(RFC 9110 § 12.5.5, label: Vary grammar): "Vary = #( "*" / field-name )"
// cite(RFC 9110 § 5.1): "Field names are case-insensitive"
// cite(RFC 9110 § 5.3): "A recipient MAY combine multiple field lines within a field section that have the same field name into one field line, without changing the semantics of the message, by appending each subsequent field line value to the initial field line value in order, separated by a comma (",") and optional whitespace (OWS, defined in Section 5.6.3)."
// cite(RFC 9111 § 4.1): "A stored response with a Vary header field value containing a member "*" always fails to match."
pub fn vary_nomination(response_headers: &HeaderMap) -> VaryNomination {
    let Some(value) = combined_field_value_as_written(response_headers, "vary") else {
        return VaryNomination::Fields(Vec::new());
    };
    let mut fields = Vec::new();
    for member in list_members(&value) {
        if member == "*" {
            return VaryNomination::Wildcard;
        }
        fields.push(member.to_ascii_lowercase());
    }
    VaryNomination::Fields(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four axes the three hand copies of this predicate disagreed on: the
    /// join across field lines, an `obs-text` octet, the walk, and the fold.
    #[test]
    fn vary_nomination_reads_the_whole_field() {
        use hyper::header::{HeaderName, HeaderValue};
        let read = |lines: &[&[u8]]| {
            let mut h = HeaderMap::new();
            for l in lines {
                h.append(
                    HeaderName::from_static("vary"),
                    HeaderValue::from_bytes(l).expect("a test Vary value"),
                );
            }
            vary_nomination(&h)
        };

        // A `*` written on a second field line is a `*`: §5.3 makes the lines
        // one value and `#` is what licenses the join. Two of the three rules
        // read the lines one at a time and said it was not.
        assert!(read(&[b"accept", b"*"]).is_wildcard());
        assert!(read(&[b"*"]).is_wildcard());
        assert!(read(&[b"accept, *, accept-encoding"]).is_wildcard());

        // One `obs-text` octet used to stand the whole rule down, in two rules,
        // by two different routes. It is a member that nominates nothing and it
        // does not reach the other members.
        let n = read(&[b"accept-encoding, caf\xe9", b"*"]);
        assert!(n.is_wildcard(), "the second line still answers");
        let n = read(&[b"accept-encoding, caf\xe9"]);
        assert!(
            n.nominates("Accept-Encoding"),
            "the first member still reads"
        );
        // The octet stays inside the member it was written in — it is no `OWS`
        // character and nothing trims it — so that member nominates no field a
        // request could carry under the name without it.
        assert!(!n.nominates("caf"), "the octet is part of the member");
        assert!(
            n.nominates("caf\u{e9}"),
            "and the member is read as written"
        );

        // `field-name = token` admits no `quoted-string`, so a DQUOTE is a
        // character no member may hold and the comma after it is still a
        // separator. The quote-aware walk one caller used said otherwise.
        assert!(read(&[b"\"x, prefer"]).nominates("prefer"));

        // Field names are case-insensitive, both directions.
        assert!(read(&[b"Accept-Encoding"]).nominates("accept-encoding"));
        assert!(read(&[b"accept-encoding"]).nominates("ACCEPT-ENCODING"));

        // Absent and zero-element nominate the same nothing, and an empty member
        // is not an element.
        assert!(!read(&[]).nominates("accept"));
        assert!(!read(&[b""]).nominates("accept"));
        assert!(!read(&[b"a,,b"]).nominates(""));
        assert!(read(&[b"a,,b"]).nominates("b"));
    }
}
