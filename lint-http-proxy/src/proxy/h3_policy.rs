// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The HTTP/3 upstream **selection policy**: whether a request goes to its
//! origin over HTTP/3 at all, where that connection is dialed, and what an H3
//! failure becomes.
//!
//! Before this module the policy's state sat in the middle of
//! [`super::upstream_h3`], between the quinn endpoint and the response-body
//! adapter, and every assertion about it had to go through a client that binds
//! a UDP socket. It lives here now, and every one of its tests runs without a
//! socket and without a runtime.
//!
//! # The stages, in order
//!
//! 1. **Allow / deny.** `h3_upstream_denylist` vetoes an origin outright and
//!    wins over every other stage, including a live discovery entry;
//!    `h3_upstream_authorities` opts an origin in unconditionally and dials the
//!    origin itself.
//! 2. **Discovery.** An origin that is on neither list may still be reached over
//!    H3 when it has advertised an `h3=` alternative in `Alt-Svc` (RFC 7838) and
//!    that advertisement is still fresh. Trust in `Alt-Svc` is configurable
//!    (`h3_upstream_trust_alt_svc`); with it off the cache is never written, so
//!    the allowlist becomes the only way in.
//! 3. **Negative cache.** An origin whose H3 connect or handshake failed is
//!    suppressed for a backoff window that doubles per consecutive failure, and
//!    is cleared the moment an H3 exchange succeeds. Suppression is checked
//!    *before* routing, so it overrides both the allowlist and discovery.
//! 4. **Pool.** Given a route, the connection to use is a live, non-idle pooled
//!    one where there is one (RFC 9114 §3.3 SHOULD NOT open more than one
//!    connection to an endpoint), else a fresh one, LRU-evicting past
//!    `h3_upstream_pool_max`; a pooled connection that refuses a stream is
//!    invalidated and the request retried once on a fresh one.
//!
//! Stages 1–3 are decided here. Stage 4 stays in [`super::upstream_h3`], with
//! the live quinn connections and driver tasks it decides between — it is named
//! here because it is the fourth stage of the same policy, and it is *only*
//! named here because a decision that owns connections cannot be moved away
//! from them.
//!
//! # One key for every lookup
//!
//! Allowlist, denylist, discovery, negative cache and pool are all keyed on
//! [`normalize_authority`], so an operator's `example.com` matches a request's
//! `EXAMPLE.com:443` and a discovery entry written under one spelling is found
//! under the other.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use hyper::HeaderMap;
use parking_lot::Mutex;

use crate::config::Config;

/// Upper bound on distinct authorities held in the negative cache; expired
/// entries are pruned before this is exceeded so a churn of one-off origins
/// can't grow the map without bound.
const NEGATIVE_CACHE_CAP: usize = 1024;

/// Same bound for the Alt-Svc discovery cache — a proxy that sees many distinct
/// origins advertising H3 must not accumulate mappings without limit.
const DISCOVERY_CACHE_CAP: usize = 1024;

/// Default freshness for a discovered Alt-Svc mapping when it carries no `ma`
/// (RFC 7838 §3.1 leaves the default to the client; 24h is the common choice,
/// matching the alt-svc rule's documented assumption).
const DEFAULT_ALT_SVC_MA_SECS: u64 = 24 * 60 * 60;

/// One negative-cache entry: the origin is not attempted over H3 until `until`,
/// and `failures` drives the exponential backoff of that window.
struct NegEntry {
    until: Instant,
    failures: u32,
}

/// A discovered Alt-Svc mapping: the advertised H3 endpoints and when the
/// mapping stops being fresh (`ma`).
struct DiscoveryEntry {
    endpoints: Vec<(String, u16)>,
    expiry: Instant,
}

/// Where and how to open an H3 connection for an origin authority: the QUIC
/// endpoint to dial (the origin itself, or an Alt-Svc alternative) and the TLS
/// server name — always the **origin** authority host, so the endpoint's
/// certificate must validate *for the origin* (RFC 7838 §2.1 / RFC 9114 §3.3),
/// not merely for the alternative's own name. `authority` is the pool key.
pub(super) struct H3Route {
    pub(super) dial_host: String,
    pub(super) dial_port: u16,
    pub(super) authority_host: String,
    pub(super) authority: String,
}

/// The routing state stages 1–3 decide against: the operator's two lists, the
/// Alt-Svc discovery cache, and the negative cache.
///
/// Owned by [`super::upstream_h3::H3UpstreamClient`], which adds the endpoint
/// and the pool. It is separable from them on purpose — none of this needs a
/// bound socket, so all of it is directly testable.
pub(super) struct H3Policy {
    /// Origin authorities (`host:port`) the operator opted into always
    /// forwarding over H3, pre-seeding discovery.
    authorities: HashSet<String>,
    /// Origin authorities that must never use H3, overriding both the allowlist
    /// and Alt-Svc discovery.
    denylist: HashSet<String>,
    /// Whether an origin's Alt-Svc header may add an H3 route at runtime.
    trust_alt_svc: bool,
    /// Base backoff window for the negative cache.
    negative_ttl: Duration,
    //
    // Both maps below are `parking_lot::Mutex`, matching the stores in
    // `lint-http-core`. They were `std::sync::Mutex` behind twelve
    // `.lock().unwrap()`s, and the unwrap is the part that mattered: a panic
    // anywhere under one of these locks poisons it, and every later acquisition
    // panics too. A single bad request would have taken H3 upstream down for
    // the life of the process, with each subsequent request re-panicking on a
    // lock rather than on anything wrong with itself.
    //
    // parking_lot does not poison, so the failure mode after such a panic is a
    // possibly-stale entry instead of a dead subsystem. For a negative cache and
    // a discovery cache that is the right trade: every entry here is already
    // expiring or evictable.
    /// Authorities whose H3 connect/handshake recently failed, suppressed from
    /// H3 attempts until their backoff window elapses.
    negative: Mutex<HashMap<String, NegEntry>>,
    /// Alt-Svc discovery cache: origin authority → advertised H3 endpoints.
    discovery: Mutex<HashMap<String, DiscoveryEntry>>,
}

impl H3Policy {
    /// Read the policy out of the configuration. Canonicalizes the configured
    /// authorities so an operator's intent matches a request authority whether
    /// or not either side spells out `:443` (unparseable entries are dropped).
    pub(super) fn from_config(cfg: &Config) -> Self {
        Self {
            authorities: cfg
                .general
                .h3_upstream_authorities
                .iter()
                .filter_map(|a| normalize_authority(a))
                .collect(),
            denylist: cfg
                .general
                .h3_upstream_denylist
                .iter()
                .filter_map(|a| normalize_authority(a))
                .collect(),
            trust_alt_svc: cfg.general.h3_upstream_trust_alt_svc,
            negative_ttl: Duration::from_secs(cfg.general.h3_upstream_negative_ttl_seconds),
            negative: Mutex::new(HashMap::new()),
            discovery: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `authority` is currently suppressed from H3 attempts by a live
    /// negative-cache backoff window.
    pub(super) fn is_suppressed(&self, authority: &str) -> bool {
        let Some(key) = normalize_authority(authority) else {
            return false;
        };
        let map = self.negative.lock();
        map.get(&key).is_some_and(|e| e.until > Instant::now())
    }

    /// Record a connect/handshake failure for `authority`, extending its
    /// backoff window (doubling per consecutive failure, capped).
    pub(super) fn record_failure(&self, authority: &str) {
        let Some(key) = normalize_authority(authority) else {
            return;
        };
        let now = Instant::now();
        let mut map = self.negative.lock();
        if map.len() >= NEGATIVE_CACHE_CAP {
            map.retain(|_, e| e.until > now);
        }
        let entry = map.entry(key).or_insert(NegEntry {
            until: now,
            failures: 0,
        });
        entry.failures = entry.failures.saturating_add(1);
        // ttl * 2^(failures-1), shift capped at 6 (×64) to bound the window.
        // `checked_add` guards against an absurdly large configured ttl whose
        // saturated Duration would overflow `Instant` and panic this request task.
        let shift = (entry.failures - 1).min(6);
        let backoff = self.negative_ttl.saturating_mul(1u32 << shift);
        entry.until = now
            .checked_add(backoff)
            .unwrap_or_else(|| now + Duration::from_secs(24 * 60 * 60));
    }

    /// Clear any negative-cache entry for `authority` after a successful H3
    /// exchange, so a recovered origin resumes H3 immediately.
    pub(super) fn record_success(&self, authority: &str) {
        if let Some(key) = normalize_authority(authority) {
            self.negative.lock().remove(&key);
        }
    }

    /// Resolve how to reach `authority` over HTTP/3, or `None` if it should not
    /// be attempted. The denylist wins over everything; otherwise the configured
    /// allowlist dials the origin directly, and a fresh Alt-Svc discovery dials
    /// the advertised endpoint. Either way the TLS name stays the origin host so
    /// the endpoint cert is validated for the origin (RFC 7838 §2.1).
    pub(super) fn route_for(&self, authority: &str) -> Option<H3Route> {
        // Match on the canonical key so allowlist/denylist/discovery/pool all
        // agree regardless of whether `:443` is spelled out (host case-folded).
        let key = normalize_authority(authority)?;
        if self.denylist.contains(&key) {
            return None;
        }
        let (host, port) = split_authority(&key)?;
        if self.authorities.contains(&key) {
            return Some(H3Route {
                dial_host: host.clone(),
                dial_port: port,
                authority_host: host,
                authority: key,
            });
        }
        let (dial_host, dial_port) = self.discovered(&key)?;
        Some(H3Route {
            dial_host,
            dial_port,
            authority_host: host,
            authority: key,
        })
    }

    /// Return a fresh discovered H3 endpoint for `authority`, if any.
    fn discovered(&self, authority: &str) -> Option<(String, u16)> {
        let map = self.discovery.lock();
        let entry = map.get(authority)?;
        if entry.expiry <= Instant::now() {
            return None;
        }
        entry.endpoints.first().cloned()
    }

    /// Fold an origin's `Alt-Svc` response header(s) into the discovery cache:
    /// `clear` drops the mapping, an `h3` advertisement (re)populates it with the
    /// advertised endpoints and an `ma`-derived expiry. No-op when Alt-Svc trust
    /// is disabled. `origin_host` resolves the `":port"` (same-host) form.
    pub(super) fn record_alt_svc(&self, authority: &str, origin_host: &str, headers: &HeaderMap) {
        if !self.trust_alt_svc {
            return;
        }
        // Key discovery on the canonical authority so `route_for` finds it
        // regardless of how the port was spelled on either side.
        let Some(authority) = normalize_authority(authority) else {
            return;
        };
        let authority = authority.as_str();
        let origin_host = origin_host.trim_start_matches('[').trim_end_matches(']');
        for hv in headers.get_all("alt-svc").iter() {
            let Ok(s) = hv.to_str() else { continue };
            match parse_alt_svc(s, origin_host) {
                Some(AltSvc::Clear) => {
                    self.discovery.lock().remove(authority);
                }
                Some(AltSvc::Advertise { endpoints, ma }) => {
                    let now = Instant::now();
                    let expiry = now
                        .checked_add(Duration::from_secs(ma))
                        .unwrap_or_else(|| now + Duration::from_secs(DEFAULT_ALT_SVC_MA_SECS));
                    let mut map = self.discovery.lock();
                    // Bound the map: drop stale mappings before admitting a new
                    // authority (refreshing an existing key never grows it).
                    if map.len() >= DISCOVERY_CACHE_CAP && !map.contains_key(authority) {
                        map.retain(|_, e| e.expiry > now);
                    }
                    map.insert(authority.to_string(), DiscoveryEntry { endpoints, expiry });
                }
                None => {}
            }
        }
    }
}

/// Split an `host[:port]` authority into its bracket-stripped host and port,
/// defaulting the port to 443 when absent (H3 is always TLS — this mirrors the
/// original `port_u16().unwrap_or(443)` so a no-port allowlist entry still
/// routes over H3). `Authority::host()` keeps the brackets on an IPv6 literal
/// (`[::1]`), which neither `lookup_host` nor a rustls `ServerName` accepts.
fn split_authority(authority: &str) -> Option<(String, u16)> {
    let (host_part, port) = match authority.rfind(':') {
        // A ':' inside a bracketed IPv6 literal (before the closing ']') is not
        // a port separator, e.g. bare "[::1]".
        Some(i) if authority[i..].contains(']') => (authority, 443),
        Some(i) => (&authority[..i], authority[i + 1..].parse().ok()?),
        None => (authority, 443),
    };
    let host = host_part.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

/// Canonical authority key used for every H3 routing lookup: the port is
/// defaulted to 443 (H3 is always TLS), the host is lower-cased (host
/// comparison is case-insensitive, RFC 9110 §4.2.3), and an IPv6 literal is
/// re-bracketed so the key round-trips through DNS/SNI unchanged. This collapses
/// `example.com`, `example.com:443`, and `EXAMPLE.com:443` to one key so a
/// config entry matches a request authority regardless of how the port was
/// written. `None` when the authority cannot be parsed.
fn normalize_authority(authority: &str) -> Option<String> {
    let (host, port) = split_authority(authority)?;
    let host = host.to_ascii_lowercase();
    Some(if host.contains(':') {
        // Bare IPv6 literal (split_authority stripped the brackets) — re-wrap it.
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

/// The routing-relevant content of an `Alt-Svc` header.
enum AltSvc {
    /// `Alt-Svc: clear` — drop any cached mapping for the origin.
    Clear,
    /// One or more `h3=` advertisements plus the smallest `ma` seen.
    Advertise {
        endpoints: Vec<(String, u16)>,
        ma: u64,
    },
}

/// Parse an `Alt-Svc` header value for HTTP/3 routing. Reuses the alt-svc rules'
/// list/param splitting (`crate::helpers::headers`) and their acceptance
/// criteria — only the final `h3` token (draft `h3-NN` is rejected, as
/// `alt_svc_h3_advertisement_valid` flags). `origin_host` resolves the
/// `":port"` (same-host) advertisement form. Returns `None` when the header
/// carries no usable h3 route and no `clear`.
fn parse_alt_svc(header: &str, origin_host: &str) -> Option<AltSvc> {
    use crate::helpers::list::{list_members, split_semicolons_respecting_quotes};

    let mut endpoints = Vec::new();
    let mut ma = DEFAULT_ALT_SVC_MA_SECS;
    for entry in list_members(header) {
        let mut parts = entry.splitn(2, ';');
        let proto_auth = parts.next().unwrap_or("").trim();
        let params = parts.next().unwrap_or("");

        if proto_auth.eq_ignore_ascii_case("clear") {
            return Some(AltSvc::Clear);
        }
        let Some(eq) = proto_auth.find('=') else {
            continue;
        };
        // Only the final `h3` ALPN token routes; draft `h3-NN` is not usable
        // (mirrors `alt_svc_h3_advertisement_valid`).
        if !proto_auth[..eq].trim().eq_ignore_ascii_case("h3") {
            continue;
        }
        let auth = proto_auth[eq + 1..].trim().trim_matches('"');
        let Some(endpoint) = parse_alt_authority(auth, origin_host) else {
            continue;
        };

        // An `ma=0` invalidates the advertisement; otherwise track the smallest
        // freshness across the h3 entries as the mapping's expiry.
        if let Some(entry_ma) = alt_svc_ma(&split_semicolons_respecting_quotes(params)) {
            if entry_ma == 0 {
                continue;
            }
            ma = ma.min(entry_ma);
        }
        endpoints.push(endpoint);
    }

    (!endpoints.is_empty()).then_some(AltSvc::Advertise { endpoints, ma })
}

/// Parse an Alt-Svc `alt-authority` (`[uri-host] ":" port`) into a dialable
/// `(host, port)`; an empty host means "same host as the origin".
fn parse_alt_authority(auth: &str, origin_host: &str) -> Option<(String, u16)> {
    let colon = auth.rfind(':')?;
    let port: u16 = auth[colon + 1..].parse().ok()?;
    let host = auth[..colon].trim_start_matches('[').trim_end_matches(']');
    let host = if host.is_empty() {
        origin_host.to_string()
    } else {
        host.to_string()
    };
    Some((host, port))
}

/// Extract the `ma` (max-age) parameter value from split Alt-Svc params, if any.
fn alt_svc_ma(params: &[&str]) -> Option<u64> {
    for param in params {
        let mut kv = param.splitn(2, '=');
        let key = kv.next().unwrap_or("").trim();
        if !key.eq_ignore_ascii_case("ma") {
            continue;
        }
        let raw = kv.next().unwrap_or("").trim();
        let val = raw
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(raw);
        return val.parse::<u64>().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every test here builds the policy straight out of a `Config` — no UDP
    /// bind and no runtime. That is the point of the split: the same assertions
    /// used to have to go through `H3UpstreamClient::build`, which binds a
    /// socket, so they were `#[tokio::test]`s for no reason of their own.
    fn policy_with(mutate: impl FnOnce(&mut crate::config::GeneralConfig)) -> H3Policy {
        let mut cfg = Config::default();
        cfg.general.h3_upstream_enabled = true;
        mutate(&mut cfg.general);
        H3Policy::from_config(&cfg)
    }

    fn policy_with_ttl(negative_ttl_seconds: u64) -> H3Policy {
        policy_with(|g| g.h3_upstream_negative_ttl_seconds = negative_ttl_seconds)
    }

    #[test]
    fn negative_cache_suppresses_then_clears_on_success() {
        let policy = policy_with_ttl(30);
        let auth = "origin.example:443";

        assert!(
            !policy.is_suppressed(auth),
            "fresh authority is not suppressed"
        );

        policy.record_failure(auth);
        assert!(
            policy.is_suppressed(auth),
            "a connect failure suppresses H3 for the backoff window"
        );

        // A second failure keeps it suppressed (window doubles).
        policy.record_failure(auth);
        assert!(policy.is_suppressed(auth));

        policy.record_success(auth);
        assert!(
            !policy.is_suppressed(auth),
            "a success clears the negative-cache entry"
        );
    }

    #[test]
    fn negative_cache_window_expires() {
        // A zero-second base TTL means the window is already elapsed on insert,
        // so the authority is not suppressed.
        let policy = policy_with_ttl(0);
        let auth = "origin.example:443";
        policy.record_failure(auth);
        assert!(
            !policy.is_suppressed(auth),
            "an elapsed window no longer suppresses"
        );
    }

    #[test]
    fn negative_cache_only_covers_the_failing_authority() {
        let policy = policy_with_ttl(30);
        policy.record_failure("a.example:443");
        assert!(policy.is_suppressed("a.example:443"));
        assert!(
            !policy.is_suppressed("b.example:443"),
            "suppression is per authority"
        );
    }

    fn alt_svc_headers(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("alt-svc", v.parse().unwrap());
        }
        h
    }

    #[test]
    fn parse_alt_svc_same_host_and_explicit_host() {
        match parse_alt_svc("h3=\":443\"; ma=3600", "example.com") {
            Some(AltSvc::Advertise { endpoints, ma }) => {
                assert_eq!(endpoints, vec![("example.com".to_string(), 443)]);
                assert_eq!(ma, 3600);
            }
            _ => panic!("expected an h3 advertisement"),
        }
        match parse_alt_svc("h3=\"alt.example.com:8443\"", "example.com") {
            Some(AltSvc::Advertise { endpoints, ma }) => {
                assert_eq!(endpoints, vec![("alt.example.com".to_string(), 8443)]);
                assert_eq!(ma, DEFAULT_ALT_SVC_MA_SECS, "absent ma defaults");
            }
            _ => panic!("expected advertise"),
        }
    }

    #[test]
    fn parse_alt_svc_rejects_draft_and_non_h3_and_clear() {
        assert!(
            parse_alt_svc("h3-29=\":443\"", "example.com").is_none(),
            "draft h3-NN is not a usable route"
        );
        assert!(
            parse_alt_svc("h2=\":443\"", "example.com").is_none(),
            "non-h3 protocols do not route H3"
        );
        assert!(matches!(
            parse_alt_svc("clear", "example.com"),
            Some(AltSvc::Clear)
        ));
        // ma=0 invalidates the h3 entry.
        assert!(parse_alt_svc("h3=\":443\"; ma=0", "example.com").is_none());
    }

    #[test]
    fn discovery_populates_consults_and_clears() {
        let policy = policy_with(|_| {});
        let auth = "origin.example:443";

        assert!(policy.route_for(auth).is_none(), "nothing discovered yet");

        policy.record_alt_svc(
            auth,
            "origin.example",
            &alt_svc_headers(&["h3=\":8443\"; ma=3600"]),
        );
        let route = policy.route_for(auth).expect("discovered route");
        assert_eq!(route.dial_host, "origin.example");
        assert_eq!(route.dial_port, 8443);
        assert_eq!(
            route.authority_host, "origin.example",
            "TLS name stays the origin authority (cert-for-origin)"
        );

        policy.record_alt_svc(auth, "origin.example", &alt_svc_headers(&["clear"]));
        assert!(
            policy.route_for(auth).is_none(),
            "Alt-Svc: clear drops the mapping"
        );
    }

    #[test]
    fn discovery_honours_ma_expiry() {
        let policy = policy_with(|_| {});
        let auth = "origin.example:443";
        // A fresh mapping is consulted.
        policy.record_alt_svc(
            auth,
            "origin.example",
            &alt_svc_headers(&["h3=\":8443\"; ma=3600"]),
        );
        assert!(
            policy.route_for(auth).is_some(),
            "fresh mapping is consulted"
        );

        // Force the entry's expiry into the past: it must no longer be consulted.
        {
            let mut map = policy.discovery.lock();
            let entry = map.get_mut(auth).unwrap();
            entry.expiry = Instant::now() - Duration::from_secs(1);
        }
        assert!(
            policy.route_for(auth).is_none(),
            "an expired mapping (ma elapsed) is not consulted"
        );
    }

    #[test]
    fn discovery_ignored_when_trust_disabled() {
        let policy = policy_with(|g| g.h3_upstream_trust_alt_svc = false);
        let auth = "origin.example:443";
        policy.record_alt_svc(
            auth,
            "origin.example",
            &alt_svc_headers(&["h3=\":8443\"; ma=3600"]),
        );
        assert!(
            policy.route_for(auth).is_none(),
            "Alt-Svc discovery is off, so no route"
        );
    }

    #[test]
    fn route_allowlist_and_denylist() {
        let policy = policy_with(|g| {
            g.h3_upstream_authorities = vec!["allow.example:443".to_string()];
            g.h3_upstream_denylist = vec!["deny.example:443".to_string()];
        });
        let route = policy.route_for("allow.example:443").expect("allowlisted");
        assert_eq!(route.dial_host, "allow.example");
        assert_eq!(route.dial_port, 443);
        assert!(
            policy.route_for("other.example:443").is_none(),
            "not allowlisted, not discovered"
        );

        // Denylist wins even over a discovered mapping.
        policy.record_alt_svc(
            "deny.example:443",
            "deny.example",
            &alt_svc_headers(&["h3=\":8443\"; ma=3600"]),
        );
        assert!(
            policy.route_for("deny.example:443").is_none(),
            "denylist overrides discovery"
        );
    }

    #[test]
    fn route_defaults_missing_port_to_443() {
        // A no-port allowlist entry still routes over H3 (H3 is always TLS), as
        // it did before Alt-Svc routing landed.
        let policy = policy_with(|g| {
            g.h3_upstream_authorities = vec!["example.com".to_string()];
        });
        let route = policy
            .route_for("example.com")
            .expect("no-port entry routes");
        assert_eq!(route.dial_host, "example.com");
        assert_eq!(route.dial_port, 443);
    }

    #[test]
    fn split_authority_forms() {
        assert_eq!(
            split_authority("example.com:8443"),
            Some(("example.com".to_string(), 8443))
        );
        assert_eq!(
            split_authority("example.com"),
            Some(("example.com".to_string(), 443)),
            "absent port defaults to 443"
        );
        assert_eq!(split_authority("[::1]:443"), Some(("::1".to_string(), 443)));
        assert_eq!(
            split_authority("[::1]"),
            Some(("::1".to_string(), 443)),
            "bracketed IPv6 without a port defaults to 443, not a mis-split"
        );
    }

    #[test]
    fn normalize_authority_canonicalizes_port_case_and_ipv6() {
        assert_eq!(
            normalize_authority("example.com").as_deref(),
            Some("example.com:443"),
            "absent port defaults to 443"
        );
        assert_eq!(
            normalize_authority("example.com:443").as_deref(),
            Some("example.com:443"),
            "explicit :443 is the same key as the bare host"
        );
        assert_eq!(
            normalize_authority("EXAMPLE.com:8443").as_deref(),
            Some("example.com:8443"),
            "host is case-folded, non-443 port preserved"
        );
        assert_eq!(
            normalize_authority("[::1]").as_deref(),
            Some("[::1]:443"),
            "IPv6 literal is re-bracketed with the default port"
        );
        assert_eq!(
            normalize_authority("[::1]:8443").as_deref(),
            Some("[::1]:8443")
        );
    }

    #[test]
    fn allowlist_matches_regardless_of_port_spelling() {
        // Configured without a port; requests may or may not carry `:443`.
        let policy = policy_with(|g| {
            g.h3_upstream_authorities = vec!["example.com".to_string()];
        });
        assert!(
            policy.route_for("example.com:443").is_some(),
            "a `:443` request authority matches a no-port allowlist entry"
        );
        assert!(
            policy.route_for("example.com").is_some(),
            "a no-port request authority also matches"
        );
        // Reciprocal: configured *with* a port, requested without.
        let policy = policy_with(|g| {
            g.h3_upstream_authorities = vec!["origin.example:443".to_string()];
        });
        assert!(policy.route_for("origin.example").is_some());
    }

    #[test]
    fn denylist_matches_regardless_of_port_spelling() {
        let policy = policy_with(|g| {
            g.h3_upstream_authorities = vec!["deny.example:443".to_string()];
            g.h3_upstream_denylist = vec!["deny.example".to_string()];
        });
        assert!(
            policy.route_for("deny.example:443").is_none(),
            "a no-port denylist entry blocks a `:443` request authority"
        );
    }

    #[test]
    fn discovery_matches_regardless_of_port_spelling() {
        let policy = policy_with(|_| {});
        // Advertisement recorded under the bare-host authority form.
        policy.record_alt_svc(
            "origin.example",
            "origin.example",
            &alt_svc_headers(&["h3=\":8443\"; ma=3600"]),
        );
        let route = policy
            .route_for("origin.example:443")
            .expect("discovery found via the `:443` form");
        assert_eq!(route.dial_port, 8443);
    }

    #[test]
    fn negative_cache_normalizes_authority() {
        let policy = policy_with_ttl(30);
        policy.record_failure("a.example");
        assert!(
            policy.is_suppressed("a.example:443"),
            "a failure recorded without a port suppresses the `:443` form"
        );
        policy.record_success("a.example:443");
        assert!(
            !policy.is_suppressed("a.example"),
            "clearing the `:443` form clears the no-port form"
        );
    }
}
