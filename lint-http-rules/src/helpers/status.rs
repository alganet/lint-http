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
/// must satisfy. The list is this specification's — a status defined
/// elsewhere may declare itself cacheable and is not read here.
// cite(RFC 9110 § 15.1): "Responses with status codes that are defined as heuristically cacheable (e.g., 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, and 501 in this specification) can be reused by a cache with heuristic expiration unless otherwise indicated by the method definition or explicit cache controls"
pub fn is_heuristically_cacheable(status: u16) -> bool {
    matches!(
        status,
        200 | 203 | 204 | 206 | 300 | 301 | 308 | 404 | 405 | 410 | 414 | 501
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The twelve § 15.1 names, and the neighbours a reader might assume in.
    #[test]
    fn the_heuristically_cacheable_set_is_the_enumerated_one() {
        for s in [200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501] {
            assert!(is_heuristically_cacheable(s), "{s}");
        }
        for s in [
            100, 101, 201, 202, 302, 303, 304, 307, 400, 401, 403, 412, 416, 500, 503,
        ] {
            assert!(!is_heuristically_cacheable(s), "{s}");
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
