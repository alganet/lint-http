// SPDX-FileCopyrightText: 2026 GitHub Copilot <copilot@example.com>
//
// SPDX-License-Identifier: ISC

//! One heuristic about an IPv6 literal written without its brackets.
//!
//! **What is left here is not a shelf, it is a remainder.** The module held three
//! functions and two have gone to `helpers::uri`, each because the question it
//! answered was about a URI component and not about an address family: a port's
//! namespace (`parse_port_str` -> `port_number`) and where a bracketed host ends
//! (`parse_bracketed_ipv6` -> `split_host_and_port` + `validate_uri_host`). The
//! one below stays because its question really is about the brackets --
//! *what does a value that has none but looks like it wants them mean* -- which
//! no component rule asks, because no component rule generates such a value.

// `parse_bracketed_ipv6` was here, and its own doc comment is what condemned it:
// *"the inner text is handed back unexamined, so quoting a production that
// constrains it would claim a check that happens -- when it happens at all -- in
// the caller."* It happened in no caller. Its last one,
// `helpers::headers::is_valid_serialized_origin`, therefore read `https://[foo]`
// as an origin, and the two halves it answered are `helpers::uri`'s:
// `split_host_and_port` finds the port past the `]`, and `validate_uri_host`
// quotes `IP-literal = "[" ( IPv6address / IPvFuture ) "]"` and measures the
// inner text against it.
//
// Second function to leave this module for `helpers::uri`, after `parse_port_str`
// below, and for the same reason both times: **the shelf is keyed by a construct
// of the document rather than by a question**, so a function about *where a host
// ends* and a function about *what a port is* were filed under the address family
// that happens to need brackets.

// `parse_port_str` was here. It answered "is this a port in the sixteen-bit
// namespace", which is a question about a URI component and not about an IPv6
// literal, and it answered it a third time and differently: `1..=65535` where
// the two rules that had audited the bound both admit `0`. It is
// `crate::helpers::uri::port_number` now, with the sentences on it.

/// Detects an unbracketed IPv6-ish string that contains a port-like suffix,
/// e.g., `fe80::1:80` — callers should treat these as violations for headers
/// where IPv6+port must be bracketed.
///
/// This is the same sentence as `parse_bracketed_ipv6`'s, read the other way
/// round: the brackets are what distinguish an IPv6 literal host, so a bare
/// `fe80::1:80` cannot be one, and the trailing `:80` is unreachable as a port
/// because nothing marks where the address stopped. The second sentence is why
/// the answer is knowable at all -- brackets appear nowhere else in the syntax,
/// so their absence is not ambiguous.
///
// cite(RFC 3986 § 3.2.2): "A host identified by an Internet Protocol literal address, version 6 [RFC3513] or later, is distinguished by enclosing the IP literal within square brackets ("[" and "]")."
// cite(RFC 3986 § 3.2.2): "This is the only place where square bracket characters are allowed in the URI syntax."
pub fn looks_like_unbracketed_ipv6_with_port(s: &str) -> bool {
    // Conservative check: ensure trailing ':<digits>' exists and the part before the last ':'
    // parses as an IPv6 address. This avoids misclassifying strings like "::1" as having a
    // port.
    let colons = s.chars().filter(|&c| c == ':').count();
    if colons < 2 {
        return false;
    }
    if let Some(pos) = s.rfind(':') {
        let port = &s[pos + 1..];
        if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        let maybe_host = &s[..pos];
        if let Ok(ip) = maybe_host.parse::<std::net::IpAddr>() {
            return matches!(ip, std::net::IpAddr::V6(_));
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_unbracketed_ipv6_with_port_cases() {
        assert!(looks_like_unbracketed_ipv6_with_port("fe80::1:80"));
        assert!(!looks_like_unbracketed_ipv6_with_port("example.com:80"));
        assert!(!looks_like_unbracketed_ipv6_with_port("::1"));
    }
}
