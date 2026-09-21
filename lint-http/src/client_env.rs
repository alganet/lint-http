// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! The environment a child process needs to reach the world through this proxy
//! and trust the CA it intercepts with.
//!
//! One question, asked once: *what has to be in a process's environment for its
//! HTTP client to proxy through `addr` and accept a certificate signed by the
//! CA at `ca_path`?* There is no single answer, because there is no standard
//! here — every ecosystem minted its own variable, and what each one does is
//! decided by the client that reads it rather than by any specification of
//! HTTP. So the answer is a table, one row per variable, and every row carries
//! the sentence from the document that defines it.
//!
//! **The quotes are the maintenance mechanism, not decoration.** A variable a
//! client renames, stops reading, or narrows to one TLS backend leaves no trace
//! in a Rust program: the wrapper keeps exporting it, the child keeps ignoring
//! it, and the failure arrives as a certificate error in somebody else's
//! terminal. `just quotes` opens each of these documents and fails when the
//! sentence is no longer in it, which is the only check that can see that
//! coming. Adding a client is a row and a cite; nothing else in the tree
//! changes.
//!
//! ## What no variable here can reach
//!
//! Brief and deliberately un-argued — these are the clients `run` cannot wrap,
//! recorded so the list is somewhere other than in a support conversation.
//!
//! - **Go on macOS and Windows.** `crypto/x509` goes to the platform store;
//!   `SSL_CERT_FILE` is honoured on Linux and the BSDs only.
//! - **Java.** Trust is a keystore plus `-Djavax.net.ssl.trustStore`, which is
//!   an argument, not an environment variable.
//! - **A Rust binary built against `webpki-roots`.** Anchors are compiled in
//!   and no environment is consulted. (`CARGO_HTTP_CAINFO` covers `cargo`'s own
//!   downloads, not the programs it builds.)
//! - **Anything that pins a certificate or a public key.** Working as intended.
//! - **A pre-set `NO_PROXY` that already excludes the target.** `run` leaves it
//!   alone rather than overriding a deliberate exclusion, so a broad one set
//!   elsewhere in the environment silently keeps traffic away from the proxy.
//!   The quote for that one sits on [`client_env`], which is where the decision
//!   not to touch it is actually taken.

use std::net::SocketAddr;
use std::path::Path;

/// What a row wants written into it — the proxy's URL, the path to the CA
/// certificate, or a bare `1`. The caller fills the first two in once for the
/// whole table; the third needs nothing from the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvValue {
    /// The `http://host:port` the proxy is listening on.
    ProxyUrl,
    /// The filesystem path of the CA certificate, in PEM.
    CaFile,
    /// The literal `1`: a switch, not an address.
    ///
    /// A row takes this when its client reads the proxy variables **only when
    /// told to**. Setting the addresses is then not enough, and that failure is
    /// silent in the worst way — the client makes the request directly,
    /// succeeds, and the report is empty rather than wrong.
    ///
    /// It is a routing value, so it survives when there is no CA to point at,
    /// exactly as [`EnvValue::ProxyUrl`] does.
    On,
}

/// One environment variable, the value it takes, and who reads it.
///
/// `reads` is prose for a human — it appears in `run --print-env` and in no
/// decision. The row's meaning is the cite above it.
#[derive(Debug, Clone, Copy)]
pub struct ClientEnvVar {
    pub name: &'static str,
    pub value: EnvValue,
    pub reads: &'static str,
}

/// Every variable `run` exports into the command it wraps.
///
/// Ordered proxy-routing first, then trust, because that is the order a reader
/// debugging a wrapped command asks the two questions in: *did it go through
/// the proxy at all*, then *did it accept the certificate*.
pub static CLIENT_ENV: &[ClientEnvVar] = &[
    // ── Routing ──────────────────────────────────────────────────────────
    //
    // Both cases of each name, and that is not belt-and-braces: the convention
    // is split, and curl — the most-wrapped client there is — resolves the
    // split in favour of the lower-case spelling.
    //
    // cite(curl): "The environment variables can be specified in lower case or upper case. The lower case version has precedence."
    //
    // `http_proxy` is why the lower-case half of the table is not optional.
    // cite(curl): ""http_proxy" is an exception as it is only available in lower case."
    // cite(curl): "Sets the proxy server to use for HTTP."
    ClientEnvVar {
        name: "http_proxy",
        value: EnvValue::ProxyUrl,
        reads: "curl, and the de-facto convention almost every client follows",
    },
    ClientEnvVar {
        name: "HTTP_PROXY",
        value: EnvValue::ProxyUrl,
        reads: "the upper-case half of the same convention",
    },
    // cite(curl): "Sets the proxy server to use for HTTPS."
    ClientEnvVar {
        name: "https_proxy",
        value: EnvValue::ProxyUrl,
        reads: "curl; the variable that matters, since interception is the point",
    },
    ClientEnvVar {
        name: "HTTPS_PROXY",
        value: EnvValue::ProxyUrl,
        reads: "the upper-case half of the same convention",
    },
    // The catch-all, for a client that asks for a scheme the two above do not
    // name. Listed after them so a client reading several picks a specific one.
    // cite(curl): "Sets the proxy server to use if no protocol-specific proxy is set."
    ClientEnvVar {
        name: "all_proxy",
        value: EnvValue::ProxyUrl,
        reads: "curl, when no scheme-specific proxy is set",
    },
    ClientEnvVar {
        name: "ALL_PROXY",
        value: EnvValue::ProxyUrl,
        reads: "the upper-case half of the same convention",
    },
    // Node reads none of the six addresses above unless this is set. It is the
    // only client in the table that has to be *asked*, which is why the row
    // sits here rather than beside `NODE_EXTRA_CA_CERTS` in the trust half:
    // that row answers "will it accept the certificate", and this one answers
    // the question before it, "will it go through the proxy at all".
    //
    // Without it a wrapped Node process reaches the origin directly, exits
    // zero, and the run reports no findings — the empty report being
    // indistinguishable from a clean one, which is the failure this whole
    // table exists to make impossible.
    //
    // Harmless on a Node too old to know the name, and on every other client,
    // since an unread variable costs nothing.
    // cite(Node.js CLI): "When enabled, Node.js parses the HTTP_PROXY, HTTPS_PROXY and NO_PROXY environment variables during startup, and routes requests through the specified proxy."
    ClientEnvVar {
        name: "NODE_USE_ENV_PROXY",
        value: EnvValue::On,
        reads: "Node.js, which ignores the proxy variables above until this asks it not to",
    },
    // ── Trust ────────────────────────────────────────────────────────────
    //
    // The widest reach in the table: everything that verifies through OpenSSL
    // rather than through a platform store, which on Linux is most things.
    // cite(OpenSSL Environment): "Specify the default directory or file containing CA certificates."
    ClientEnvVar {
        name: "SSL_CERT_FILE",
        value: EnvValue::CaFile,
        reads: "OpenSSL, and everything that verifies through it",
    },
    // cite(curl): "curl recognizes the environment variable named 'CURL_CA_BUNDLE' if it is set and the TLS backend is not Schannel, and uses the given path as a path to a CA cert bundle."
    ClientEnvVar {
        name: "CURL_CA_BUNDLE",
        value: EnvValue::CaFile,
        reads: "curl, unless it was built against Schannel",
    },
    // Set alongside `CURL_CA_BUNDLE` rather than instead of it: requests
    // documents the fallback, so setting both costs nothing and setting either
    // alone would depend on which of two documented paths a version takes.
    // cite(Requests Advanced Usage): "This list of trusted CAs can also be specified through the REQUESTS_CA_BUNDLE environment variable."
    // cite(Requests Advanced Usage): "If REQUESTS_CA_BUNDLE is not set, CURL_CA_BUNDLE will be used as fallback."
    ClientEnvVar {
        name: "REQUESTS_CA_BUNDLE",
        value: EnvValue::CaFile,
        reads: "python-requests, and the rest of the Python HTTP stack that follows it",
    },
    // cite(Node.js CLI): "The file should consist of one or more trusted certificates in PEM format."
    ClientEnvVar {
        name: "NODE_EXTRA_CA_CERTS",
        value: EnvValue::CaFile,
        reads: "Node.js — and Deno, which reads it too",
    },
    // cite(Deno Environment Variables): "Load certificate authorities from a PEM encoded file. The file can contain more than one certificate, each in its own PEM block."
    ClientEnvVar {
        name: "DENO_CERT",
        value: EnvValue::CaFile,
        reads: "Deno",
    },
    // Documented against the configuration key rather than in its own entry,
    // so the sentence names `http.sslCAInfo` and the variable that overrides it.
    // cite(git-config): "File containing the certificates to verify the peer with when fetching or pushing over HTTPS. Can be overridden by the GIT_SSL_CAINFO environment variable."
    ClientEnvVar {
        name: "GIT_SSL_CAINFO",
        value: EnvValue::CaFile,
        reads: "git, fetching or pushing over HTTPS",
    },
    // Reaches cargo's own downloads, which go through libcurl. It says nothing
    // about a binary cargo built — see the gap list in this module's header.
    // cite(Cargo Environment Variables): "The TLS certificate Certificate Authority file"
    ClientEnvVar {
        name: "CARGO_HTTP_CAINFO",
        value: EnvValue::CaFile,
        reads: "cargo, fetching crates",
    },
    // cite(AWS CLI Environment Variables): "Specifies the path to a certificate bundle to use for HTTPS certificate validation."
    ClientEnvVar {
        name: "AWS_CA_BUNDLE",
        value: EnvValue::CaFile,
        reads: "the AWS CLI and the SDKs that share its configuration",
    },
];

/// The proxy URL a routing variable takes.
///
/// `http://` and not `https://` whatever the traffic is: the variable names the
/// hop to the proxy, and that hop is plaintext — the intercepted TLS session is
/// established through it by `CONNECT`, not to it.
pub fn proxy_url(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

/// The whole table, resolved against one proxy address and one CA path.
///
/// Returns owned pairs ready for [`std::process::Command::env`]. Nothing is
/// read from the current environment and nothing is removed from the child's:
/// this is what `run` *adds*, and a variable the user set deliberately — a
/// `NO_PROXY`, a `REQUESTS_CA_BUNDLE` pointing at a corporate bundle — is
/// overridden only where this table names it.
// `NO_PROXY` is the one that can silently empty a run: it is not in the table,
// so a broad value already in the environment keeps the child away from the
// proxy and `run` reports a clean nothing. Left alone deliberately — it is the
// variable a user sets on purpose, and overriding it would route traffic they
// had excluded.
// cite(curl): "list of hostnames that should not go through any proxy."
pub fn client_env(addr: SocketAddr, ca_path: Option<&Path>) -> Vec<(&'static str, String)> {
    let proxy = proxy_url(addr);
    let ca = ca_path.map(|p| p.display().to_string());
    CLIENT_ENV
        .iter()
        .filter_map(|var| {
            let value = match var.value {
                EnvValue::ProxyUrl => proxy.clone(),
                // No CA to point at means the trust rows are *omitted*, not set
                // to something empty or absent. Every one of them names a file
                // to verify against, so a path to nothing does not degrade to
                // the system store — it replaces it, and the child fails to
                // verify anything at all. `None` happens when TLS interception
                // is off, where there is no forged certificate to trust anyway.
                EnvValue::CaFile => ca.clone()?,
                EnvValue::On => "1".to_string(),
            };
            Some((var.name, value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:8123".parse().unwrap()
    }

    #[test]
    fn proxy_url_is_plaintext_to_the_proxy() {
        assert_eq!(proxy_url(addr()), "http://127.0.0.1:8123");
    }

    /// With no CA, the trust rows vanish rather than pointing at nothing —
    /// the difference between "verify normally" and "verify against an empty
    /// file", which is a hard failure in every client in the table.
    #[test]
    fn without_a_ca_only_the_routing_rows_survive() {
        let env = client_env(addr(), None);
        assert!(env
            .iter()
            .all(|(_, v)| v.starts_with("http://") || v == "1"));
        assert_eq!(
            env.len(),
            CLIENT_ENV
                .iter()
                .filter(|v| v.value != EnvValue::CaFile)
                .count()
        );
        assert!(!env.iter().any(|(n, _)| *n == "SSL_CERT_FILE"));
    }

    /// Setting the six addresses is not enough for Node, and the way it fails
    /// is an empty report rather than an error — so the switch travels with
    /// them, including when there is no CA and the trust rows are dropped.
    #[test]
    fn node_is_asked_to_read_the_proxy_variables() {
        for ca in [None, Some(Path::new("/tmp/ca.crt"))] {
            let env = client_env(addr(), ca);
            assert_eq!(
                env.iter()
                    .find(|(n, _)| *n == "NODE_USE_ENV_PROXY")
                    .map(|(_, v)| v.as_str()),
                Some("1"),
                "the opt-in must survive with ca={ca:?}"
            );
        }
    }

    #[test]
    fn every_row_gets_a_value() {
        let env = client_env(addr(), Some(Path::new("/tmp/ca.crt")));
        assert_eq!(env.len(), CLIENT_ENV.len());
        assert!(env.iter().all(|(_, v)| !v.is_empty()));
    }

    #[test]
    fn routing_rows_take_the_proxy_and_trust_rows_take_the_ca() {
        let env = client_env(addr(), Some(Path::new("/tmp/ca.crt")));
        let get = |name: &str| {
            env.iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.as_str())
                .unwrap()
        };
        assert_eq!(get("http_proxy"), "http://127.0.0.1:8123");
        assert_eq!(get("HTTPS_PROXY"), "http://127.0.0.1:8123");
        assert_eq!(get("SSL_CERT_FILE"), "/tmp/ca.crt");
        assert_eq!(get("NODE_EXTRA_CA_CERTS"), "/tmp/ca.crt");
    }

    /// The lower-case spelling is the one curl gives precedence to, and
    /// `http_proxy` has no upper-case form at all — so a table that carried
    /// only `HTTP_PROXY` would miss the client most likely to be wrapped.
    #[test]
    fn both_cases_of_every_routing_variable_are_present() {
        let names: Vec<&str> = CLIENT_ENV.iter().map(|v| v.name).collect();
        for pair in [
            ("http_proxy", "HTTP_PROXY"),
            ("https_proxy", "HTTPS_PROXY"),
            ("all_proxy", "ALL_PROXY"),
        ] {
            assert!(names.contains(&pair.0), "missing {}", pair.0);
            assert!(names.contains(&pair.1), "missing {}", pair.1);
        }
    }

    #[test]
    fn no_variable_is_listed_twice() {
        let mut names: Vec<&str> = CLIENT_ENV.iter().map(|v| v.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "a variable is listed twice");
    }

    /// `run` must never quietly turn off verification. No row may name a
    /// variable whose effect is to accept any certificate — the wrapper adds
    /// trust in one CA, and a client that will not take it is a documented gap,
    /// not something to work around.
    #[test]
    fn no_row_disables_verification() {
        for var in CLIENT_ENV {
            assert!(
                !matches!(
                    var.name,
                    "NODE_TLS_REJECT_UNAUTHORIZED" | "PYTHONHTTPSVERIFY" | "GIT_SSL_NO_VERIFY"
                ),
                "{} switches verification off",
                var.name
            );
        }
    }
}
