// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

/// Returns true if `status` is a redirection status (3xx).
pub fn is_redirection_status(status: u16) -> bool {
    // cite(RFC 9110 § 15.4, label: 3xx redirection class): "The 3xx (Redirection) class of status code indicates that further action needs to be taken by the user agent in order to fulfill the request."
    (300..=399).contains(&status)
}

/// Whether `status` is one a cache may reuse with a heuristic expiration,
/// which is what lets a response with no explicit freshness be stored at all.
///
/// RFC 9111 § 4.2.2 calls the set "heuristically cacheable" and RFC 9110 § 15.1
/// enumerates it; § 3 makes it the last of the alternatives a storable response
/// must satisfy.
///
/// **§ 15.1's twelve and a `451`.** § 15.1 names the statuses defined "in this
/// specification", and § 4.2.2 points at it with an "e.g.": a status another
/// document defines is heuristically cacheable when that document says so.
/// RFC 7725 § 3 says it of `451` in RFC 7231's words for the same property.
/// This list used to say a status defined elsewhere "is not read here", so a
/// `451` with no lifetime was reported as one no cache stores by default, and
/// its heuristic lifetime went unreported.
// cite(RFC 9110 § 15.1): "Responses with status codes that are defined as heuristically cacheable (e.g., 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, and 501 in this specification) can be reused by a cache with heuristic expiration unless otherwise indicated by the method definition or explicit cache controls"
// cite(RFC 7725 § 3): "A 451 response is cacheable by default, i.e., unless otherwise indicated by the method definition or explicit cache controls; see [RFC7234]."
pub fn is_heuristically_cacheable(status: u16) -> bool {
    matches!(
        status,
        200 | 203 | 204 | 206 | 300 | 301 | 308 | 404 | 405 | 410 | 414 | 451 | 501
    )
}

/// Whether the document defining `status` forbids a cache to store a response
/// carrying it, whatever else the response says.
///
/// RFC 6585 defines four statuses and closes each definition with the same
/// sentence. RFC 9111 § 3 lists what a cache needs before it may store a
/// response, and a MUST NOT in the status's own document is a further term
/// none of § 3's licences answers: a `429` carrying `max-age=60` is still a
/// response no cache keeps.
// cite(RFC 6585 § 3): "Responses with the 428 status code MUST NOT be stored by a cache."
// cite(RFC 6585 § 4): "Responses with the 429 status code MUST NOT be stored by a cache."
// cite(RFC 6585 § 5): "Responses with the 431 status code MUST NOT be stored by a cache."
// cite(RFC 6585 § 6): "Responses with the 511 status code MUST NOT be stored by a cache."
pub fn forbids_storage(status: u16) -> bool {
    matches!(status, 428 | 429 | 431 | 511)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The twelve § 15.1 names and RFC 7725's `451`, and the neighbours a
    /// reader might assume in.
    #[test]
    fn the_heuristically_cacheable_set_is_the_enumerated_one() {
        for s in [
            200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 451, 501,
        ] {
            assert!(is_heuristically_cacheable(s), "{s}");
        }
        for s in [
            100, 101, 201, 202, 302, 303, 304, 307, 400, 401, 403, 412, 416, 429, 500, 503,
        ] {
            assert!(!is_heuristically_cacheable(s), "{s}");
        }
    }

    /// RFC 6585's four, and the neighbours that share a class with them.
    #[test]
    fn the_statuses_whose_document_forbids_storage_are_rfc_6585s_four() {
        for s in [428, 429, 431, 511] {
            assert!(forbids_storage(s), "{s}");
        }
        for s in [200, 404, 412, 416, 430, 451, 500, 503, 510] {
            assert!(!forbids_storage(s), "{s}");
        }
    }

    #[test]
    fn redirection_boundaries_and_neighbors() {
        assert!(!is_redirection_status(299));
        assert!(is_redirection_status(300));
        assert!(is_redirection_status(301));
        assert!(is_redirection_status(308));
        assert!(is_redirection_status(399));
        assert!(!is_redirection_status(400));
    }
}
