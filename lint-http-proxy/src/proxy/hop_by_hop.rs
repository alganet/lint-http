// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Hop-by-hop header utilities and HTTP version formatting.
//!
//! These helpers are shared by the HTTP/1.1+H2, WebSocket relay, and HTTP/3
//! handlers when building responses to forward to the client.

// Fields an intermediary removes before forwarding, whether or not the sender
// nominated them in Connection. The first five are the list RFC 9110 § 7.6.1
// gives; `connection` is removed by the same section's separate instruction to
// drop the Connection field itself after acting on it. Proxy-Authenticate and
// Proxy-Authorization are not § 7.6.1's, and are justified one entry down.
//
// `Trailer` is deliberately absent: § 7.6.1 does not list it, and § 6.6.2 has it
// surviving the hop -- it is the hint telling a recipient what metadata was lost
// when an intermediary dropped the trailer section. We forward trailers, so
// stripping the field that announces them was self-defeating.
// cite(RFC 9110 § 7.6.1): "Furthermore, intermediaries SHOULD remove or replace fields that are known to require removal before forwarding, whether or not they appear as a connection-option, after applying those fields' semantics."
pub(super) static HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "transfer-encoding",
    "upgrade",
    // Not § 7.6.1's list: these two are single-hop by their own definition.
    "proxy-authenticate",
    "proxy-authorization",
];

/// Convert hyper::Version into the textual HTTP-version token used in start/status lines.
pub(super) fn format_http_version(v: hyper::Version) -> String {
    match v {
        hyper::Version::HTTP_09 => "HTTP/0.9".to_string(),
        hyper::Version::HTTP_10 => "HTTP/1.0".to_string(),
        hyper::Version::HTTP_11 => "HTTP/1.1".to_string(),
        hyper::Version::HTTP_2 => "HTTP/2.0".to_string(),
        hyper::Version::HTTP_3 => "HTTP/3".to_string(),
        _ => "HTTP/1.1".to_string(),
    }
}

/// Parse a Connection header value into a lowercased set of tokens.
pub(super) fn parse_connection_tokens(
    val: Option<&hyper::header::HeaderValue>,
) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    if let Some(conn_val) = val {
        if let Ok(conn_str) = conn_val.to_str() {
            // cite(RFC 9110 § 7.6.1): "Connection = #connection-option connection-option = token"
            for token in conn_str.split(',') {
                // The lowercasing is the sentence below; the set is matched case-insensitively.
                // cite(RFC 9110 § 7.6.1): "Connection options are case-insensitive."
                let trimmed = token.trim().to_ascii_lowercase();
                if !trimmed.is_empty() {
                    set.insert(trimmed);
                }
            }
        }
    }
    set
}

pub(super) fn is_hop_by_hop_header(
    name: &str,
    connection_hop_headers: &std::collections::HashSet<String>,
) -> bool {
    // The `connection_hop_headers` half is the nomination clause: whatever Connection
    // named is hop-by-hop for this message, on top of the table's fixed set.
    // cite(RFC 9110 § 7.6.1): "Intermediaries MUST parse a received Connection header field before a message is forwarded and, for each connection-option in this field, remove any header or trailer field(s) from the message with the same name as the connection-option, and then remove the Connection header field itself (or replace it with the intermediary's own control options for the forwarded message)."
    connection_hop_headers.contains(name) || HOP_BY_HOP_HEADERS.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Version;
    use rstest::rstest;

    #[rstest]
    #[case(Version::HTTP_09, "HTTP/0.9")]
    #[case(Version::HTTP_10, "HTTP/1.0")]
    #[case(Version::HTTP_11, "HTTP/1.1")]
    #[case(Version::HTTP_2, "HTTP/2.0")]
    #[case(Version::HTTP_3, "HTTP/3")]
    fn format_http_version_cases(#[case] ver: Version, #[case] expected: &str) {
        assert_eq!(format_http_version(ver), expected.to_string());
    }

    #[test]
    fn hop_by_hop_headers_are_recognized() {
        use std::collections::HashSet;
        // Empty set of connection tokens means we rely solely on the static list
        let set: HashSet<String> = HashSet::new();
        for &h in HOP_BY_HOP_HEADERS.iter() {
            assert!(is_hop_by_hop_header(h, &set));
        }
        // A non-standard header should not be recognized
        assert!(!is_hop_by_hop_header("x-not-hop", &set));

        // If the connection header explicitly names a token, it should be recognized
        let mut conn_set: HashSet<String> = HashSet::new();
        conn_set.insert("x-not-hop".to_string());
        assert!(is_hop_by_hop_header("x-not-hop", &conn_set));
    }

    #[test]
    fn hop_by_hop_header_constants_have_expected_entries() {
        // Ensure the static list contains known hop-by-hop headers
        assert!(HOP_BY_HOP_HEADERS.contains(&"connection"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"transfer-encoding"));
        assert!(HOP_BY_HOP_HEADERS.contains(&"upgrade"));
    }

    #[test]
    fn parse_connection_tokens_handles_non_utf8() {
        use hyper::header::HeaderValue;
        // Construct a header value that is not valid UTF-8
        let hv = HeaderValue::from_bytes(&[0xffu8]).expect("create header val");
        let parsed = parse_connection_tokens(Some(&hv));
        // to_str() will fail and we should just return empty set
        assert!(parsed.is_empty());
    }
}
