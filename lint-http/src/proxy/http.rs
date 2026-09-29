// SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! HTTP/1.1 and HTTP/2 request dispatch and forwarding.

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::{Method, Request, Response, Uri};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::time::Instant;
use tracing::{error, warn};

use super::body::{collect_limited, CollectLimitedError};
use super::connect::handle_connect;
use super::exchange::{exchange, record_error_transaction, ErrorFacts, ProxiedRequest};
use super::hop_by_hop::format_http_version;
use super::tee_body;
use super::websocket::{handle_websocket_upgrade, is_websocket_upgrade, WsUpgradeRequest};
use super::{boxed_full, BoxError, ResponseBody, Shared};

pub(super) async fn handle_request<B>(
    req: Request<B>,
    shared: Arc<Shared>,
    conn_metadata: Arc<crate::connection::ConnectionMetadata>,
    scheme: hyper::http::uri::Scheme,
) -> Result<Response<ResponseBody>, Infallible>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if req.method() == Method::CONNECT {
        // Judge the tunnel request before it is consumed by the upgrade. Its
        // target is authority-form — `example.com:443`, not a URI — and it is
        // recorded exactly as the client wrote it, because that authority *is*
        // what the rules about it read. Nothing is reconstructed here for the
        // reason the exchange path reconstructs below: there is no `Host` to
        // fall back to and no origin-form to repair.
        let tunnel_facts = tunnel_facts(&req, &conn_metadata);

        if shared.ca.is_some() {
            let uri = req.uri().clone();
            // The 200 below is this proxy's own answer and no origin sent it,
            // which `record_tunnel_transaction` marks so that only the request
            // half is judged.
            super::exchange::record_tunnel_transaction(&shared, &tunnel_facts, 200).await;
            // `shared` and `conn_metadata` are owned `Arc`s and this branch
            // returns, so the task takes them rather than a second handle to
            // each. They were cloned here only because the surrounding function
            // goes on to use them — down a path this branch never reaches.
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = handle_connect(upgraded, uri, shared, conn_metadata).await {
                            error!("connect error: {}", e);
                        }
                    }
                    Err(e) => error!("upgrade error for {}: {}", uri, e),
                }
            });
            return Ok(Response::new(boxed_full(Bytes::new())));
        } else {
            super::exchange::record_tunnel_transaction(&shared, &tunnel_facts, 405).await;
            return Ok(Response::builder()
                .status(405)
                .body(boxed_full(Bytes::from(
                    "CONNECT not supported (TLS disabled)",
                )))
                .unwrap_or_else(|e| {
                    error!("failed to build 405 response: {}", e);
                    Response::new(boxed_full(Bytes::from(
                        "CONNECT not supported (TLS disabled)",
                    )))
                }));
        }
    }

    // Serve CA certificate
    if req.uri().path() == "/_lint_http/cert" && req.method() == Method::GET {
        if let Some(ca) = &shared.ca {
            let pem = ca.get_ca_cert_pem();
            return Ok(Response::builder()
                .header("Content-Type", "application/x-x509-ca-cert")
                .header(
                    "Content-Disposition",
                    "attachment; filename=\"lint-http-ca.crt\"",
                )
                .body(boxed_full(Bytes::from(pem.clone())))
                .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from(pem.clone())))));
        } else {
            return Ok(Response::builder()
                .status(404)
                .body(boxed_full(Bytes::from("TLS not enabled")))
                .unwrap_or_else(|_| Response::new(boxed_full(Bytes::from("TLS not enabled")))));
        }
    }

    // Live capture stream (SSE). Gated by general.live_stream_enabled; returns
    // 404 when disabled, mirroring the cert endpoint's gating shape.
    if req.uri().path() == "/_lint_http/stream" && req.method() == Method::GET {
        return Ok(super::stream::stream_response(&shared));
    }

    handle_http_logic(req, shared, conn_metadata, scheme).await
}

pub(super) async fn handle_inner_request<B>(
    req: Request<B>,
    shared: Arc<Shared>,
    conn_metadata: Arc<crate::connection::ConnectionMetadata>,
    scheme: hyper::http::uri::Scheme,
) -> Result<Response<ResponseBody>, Infallible>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if req.method() == Method::CONNECT {
        return Ok(Response::builder()
            .status(405)
            .body(boxed_full(Bytes::from("Nested CONNECT not supported")))
            .unwrap_or_else(|_| {
                Response::new(boxed_full(Bytes::from("Nested CONNECT not supported")))
            }));
    }
    handle_http_logic(req, shared, conn_metadata, scheme).await
}

/// The request facts for a CONNECT.
///
/// Separate from the exchange path's because almost nothing it does applies: a
/// tunnel request has no body to read, no `Host` to reconcile against an
/// origin-form target, and no upstream to forward to. What it has is a method,
/// an authority, and the client that wrote them.
fn tunnel_facts<B>(
    req: &Request<B>,
    conn_metadata: &Arc<crate::connection::ConnectionMetadata>,
) -> super::exchange::RequestFacts {
    let headers = req.headers().clone();
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    super::exchange::RequestFacts {
        method: req.method().clone(),
        uri_str: req.uri().to_string(),
        headers,
        version: format_http_version(req.version()),
        client_id: crate::state::ClientIdentifier::new(conn_metadata.remote_addr.ip(), user_agent),
        connection_id: conn_metadata.id,
        // A tunnel takes a sequence number like any other request: it is one
        // message from this client on this connection, and the requests that
        // follow it inside the tunnel are numbered after it.
        sequence_number: conn_metadata.next_sequence_number(),
    }
}

/// Build a boxed plaintext error response. Thin wrapper over the one shared
/// builder, [`super::exchange::error_response`], which owns the rationale for
/// the `Content-Type` these responses carry.
pub(super) fn error_resp(status: u16, msg: &str) -> Response<ResponseBody> {
    super::exchange::into_response(super::exchange::error_response(status, msg.to_string()))
}

/// The target URI of a request whose request-target carries no scheme of its
/// own, in the three components RFC 9112 § 3.3 names them in.
///
/// **The parts are kept apart because a concatenation of them does not survive
/// being read back.** `Host` is written by the client, and it is not an
/// authority merely because it arrived in that field: pasted between a scheme
/// and a path, every delimiter inside it becomes a delimiter of the result. A
/// `/` prepends path segments to the target, a `?` turns the request's path
/// into a query, a `#` drops the path entirely, and a value that is no
/// authority at all leaves a string naming a host nobody asked for. What comes
/// out of `format!` is not what went in, and both the request this proxy
/// forwards and the record it writes down are built from what came out.
///
/// **Two of the four forms carry no path**, which is why the path is a field
/// here rather than something the URI builder is handed: `path_and_query("*")`
/// glues the asterisk onto the authority exactly as the concatenation did.
/// § 3.3 says an asterisk-form target's combined path and query component is
/// empty, and empty is not something a `Uri` can hold — it normalises to `/` —
/// so the request-target's own form has to be read before either consumer is
/// built.
// cite(RFC 9112 § 3.3): "The target URI is the request-target when the request-target is in absolute-form."
// cite(RFC 9112 § 3.3): "If the request-target is in authority-form, the target URI's authority component is the request-target.  Otherwise, the target URI's authority component is the field value of the Host header field."
// cite(RFC 9112 § 3.3): "If there is no Host header field or if its field value is empty or invalid, the target URI's authority component is empty."
struct TargetUri {
    scheme: hyper::http::uri::Scheme,
    /// § 3.3's authority, and `None` is its *"empty or invalid"*: no `Host`
    /// field, a value that is not an authority, or — since `Host` is a
    /// singleton — more than one field line, which is a message § 3.2 makes a
    /// 400 rather than one to pick a host out of by position.
    authority: Option<hyper::http::uri::Authority>,
    /// Empty for an asterisk-form target, and the request-target otherwise.
    path_and_query: String,
}

impl TargetUri {
    /// Read the three components off a request whose target carries no scheme.
    fn reconstruct<B>(req: &Request<B>, scheme: &hyper::http::uri::Scheme) -> Self {
        let target = req.uri();
        // `Host` is a singleton. Two field lines are not two candidates: the
        // message is one a server answers with a 400, and reading the first of
        // them would choose a host by position rather than by anything the
        // sender said.
        // cite(RFC 9112 § 3.2): "A server MUST respond with a 400 (Bad Request) status code to any HTTP/1.1 request message that lacks a Host header field and to any request message that contains more than one Host header field line or a Host header field with an invalid field value."
        let mut lines = req.headers().get_all(hyper::header::HOST).iter();
        let authority = match (lines.next(), lines.next()) {
            (Some(only), None) => only
                .to_str()
                .ok()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .and_then(|value| value.parse::<hyper::http::uri::Authority>().ok()),
            _ => None,
        };

        // The asterisk is the whole target when it is the target at all, so it
        // is compared as a whole: a path of `*` inside a longer target is a
        // path segment and not this form.
        // cite(RFC 9112 § 3.2.4, label: asterisk-form target): "The "asterisk-form" of request-target is only used for a server-wide OPTIONS request"
        let path_and_query = match target.path_and_query().map(|pq| pq.as_str()) {
            Some("*") | None => String::new(),
            Some(pq) => pq.to_string(),
        };

        Self {
            scheme: scheme.clone(),
            authority,
            path_and_query,
        }
    }

    /// The URI to forward to, or `None` when § 3.3 leaves the authority empty:
    /// there is then no origin this request names and nothing to open a
    /// connection to.
    ///
    /// An asterisk-form target has no `Uri` either. Its path is empty and a
    /// `Uri` normalises an empty path to `/`, which would forward a request for
    /// the root where the client asked about the server as a whole — a
    /// different request, which is the mistake this whole type exists to stop
    /// making. Such a request is refused rather than translated.
    fn to_uri(&self) -> Option<Uri> {
        if self.path_and_query.is_empty() {
            return None;
        }
        Uri::builder()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone()?)
            .path_and_query(self.path_and_query.as_str())
            .build()
            .ok()
    }

    /// The target URI as it is written down, which is § 3.3's reconstruction
    /// and not a `Uri`: both of the cases a `Uri` cannot hold are cases a
    /// record has to be able to state. An empty authority serialises as the
    /// `//` with nothing between it and the path — `http:///p`, which is a URI
    /// naming no host and is read as naming none — and an empty path
    /// serialises as nothing after the authority.
    fn to_target_string(&self) -> String {
        format!(
            "{}://{}{}",
            self.scheme,
            self.authority
                .as_ref()
                .map(|a| a.as_str())
                .unwrap_or_default(),
            self.path_and_query
        )
    }
}

async fn handle_http_logic<B>(
    mut req: Request<B>,
    shared: Arc<Shared>,
    conn_metadata: Arc<crate::connection::ConnectionMetadata>,
    scheme: hyper::http::uri::Scheme,
) -> Result<Response<ResponseBody>, Infallible>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let started = Instant::now();

    // A target already in absolute-form *is* the target URI and nothing is
    // reconstructed from it; anything else is § 3.3's reconstruction, kept in
    // its components by [`TargetUri`] because a string built out of them cannot
    // be read back into them.
    // cite(RFC 9112 § 3.3): "The target URI is the request-target when the request-target is in absolute-form."
    let target = if req.uri().scheme().is_some() {
        None
    } else {
        Some(TargetUri::reconstruct(&req, &scheme))
    };
    let uri = match &target {
        None => Some(req.uri().clone()),
        Some(target) => target.to_uri(),
    };

    let is_ws_upgrade = is_websocket_upgrade(&req);

    let method = req.method().clone();
    // The *target URI*, not `req.uri()`. Over HTTP/1.1 a request inside a
    // CONNECT tunnel arrives in origin-form — `GET / HTTP/1.1` with the
    // authority in `Host` — so recording `req.uri()` writes `"/"` into the
    // capture and loses which host was asked. HTTP/2 and HTTP/3 carry
    // `:authority` and already record an absolute URI, so this is also what
    // makes one logical request look the same whichever version carried it.
    //
    // What that cost: two different hosts both print as `GET / -> 200`, and
    // every by-resource rule keys on `"/"`, so histories for unrelated origins
    // collide and a validator from one host is reported against another.
    //
    // It is written from the components and not from the `Uri` above, because
    // two of the reconstructions a record has to be able to state are ones a
    // `Uri` cannot hold: an empty authority, and the empty path an asterisk-form
    // target has. A record built from the forwarding URI could state neither,
    // and a request this proxy refuses to forward is still a request that was
    // made.
    let uri_str = match &target {
        None => req.uri().to_string(),
        Some(target) => target.to_target_string(),
    };
    let req_headers = req.headers().clone();

    let client_ip = conn_metadata.remote_addr.ip();
    let user_agent = req_headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    let client_id = crate::state::ClientIdentifier::new(client_ip, user_agent);

    // Capture request version before moving `req` into body.
    let req_version = format_http_version(req.version());

    // Every request allocates exactly one sequence number and produces exactly
    // one transaction record, whichever path ends up writing it — the exchange,
    // the WebSocket handshake, or an error.
    let facts = super::exchange::RequestFacts {
        method,
        uri_str,
        headers: req_headers,
        version: req_version,
        client_id,
        connection_id: conn_metadata.id,
        sequence_number: conn_metadata.next_sequence_number(),
    };

    // A request whose target URI could not be built names no origin to forward
    // it to, and the two ways that happens are two different things to say.
    //
    // **Neither of them used to be said at all.** The reconstruction fell back
    // to `http://localhost/` whenever its string did not parse, so a request
    // carrying a `Host` that is not an authority was forwarded to whatever
    // answers on this machine — an origin the client never named, chosen by a
    // header the client wrote — and the record said that was the request. What
    // came back was a 502, which blames an origin that was never asked.
    let Some(uri) = uri else {
        // cite(RFC 9112 § 3.2): "A server MUST respond with a 400 (Bad Request) status code to any HTTP/1.1 request message that lacks a Host header field and to any request message that contains more than one Host header field line or a Host header field with an invalid field value."
        // cite(RFC 9112 § 3.2.4): "When a client wishes to request OPTIONS for the server as a whole"
        let (status, why) = match &target {
            Some(t) if t.authority.is_none() => (
                400,
                "no Host header field, more than one, or a value that is not an authority: the target URI names no host",
            ),
            _ => (
                501,
                "a server-wide OPTIONS names no resource to forward a request for",
            ),
        };
        record_error_transaction(
            &shared,
            &facts,
            ErrorFacts {
                status,
                duration_ms: started.elapsed().as_millis() as u64,
                ..Default::default()
            },
        )
        .await;
        return Ok(error_resp(status, why));
    };

    // Extract the client OnUpgrade before consuming the request body; for
    // WebSocket upgrades we need it to reach the upgraded client IO later.
    let client_on_upgrade = if is_ws_upgrade {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    // WebSocket handshakes buffer their (tiny) body for the dedicated upgrade
    // path, which builds its own upstream connection over a `Full<Bytes>` body;
    // everything else streams the request body through the exchange core. The
    // WebSocket arm always returns, so the request body is consumed exactly once.
    //
    // Because that upstream body must be buffered, `max_body_bytes` stays a real
    // DoS guard here and over-limit handshakes are rejected with 413 — this is
    // the one remaining path where `request_body_over_limit` keeps its original
    // "rejected, body not captured" sense (cf. #17d). In practice WebSocket
    // handshake requests carry no body, so the limit is near-vacuous.
    if is_ws_upgrade {
        if let Some(client_on_upgrade) = client_on_upgrade {
            let max_body_bytes = shared.cfg.general.max_body_bytes;
            let (body_bytes, req_trailers) =
                match collect_limited(req.into_body(), max_body_bytes).await {
                    Ok((bytes, trailers)) => (bytes, trailers),
                    Err(CollectLimitedError::OverLimit) => {
                        warn!("request body exceeds max_body_bytes ({})", max_body_bytes);
                        record_error_transaction(
                            &shared,
                            &facts,
                            ErrorFacts {
                                status: 413,
                                duration_ms: started.elapsed().as_millis() as u64,
                                request_body_over_limit: true,
                                ..Default::default()
                            },
                        )
                        .await;
                        return Ok(error_resp(413, "request body exceeds max_body_bytes"));
                    }
                    Err(CollectLimitedError::Other(e)) => {
                        error!("failed to collect request body: {}", e);
                        record_error_transaction(
                            &shared,
                            &facts,
                            ErrorFacts {
                                status: 500,
                                duration_ms: started.elapsed().as_millis() as u64,
                                ..Default::default()
                            },
                        )
                        .await;
                        return Ok(error_resp(500, "request body collect error"));
                    }
                };
            return handle_websocket_upgrade(
                WsUpgradeRequest {
                    facts,
                    uri,
                    fallback_scheme: scheme,
                    body: body_bytes,
                    trailers: req_trailers,
                    client_on_upgrade,
                },
                shared,
                started,
            )
            .await;
        }
    }

    // Non-WebSocket: tee the request body — forward it to the upstream while
    // capturing a bounded prefix. The transaction is committed at the response
    // stream-end inside `exchange`, joining both captured halves.
    let prefix_cap = shared.cfg.general.captures_max_body_bytes;
    let inner = req
        .into_body()
        .map_err(|e| -> BoxError { e.into() })
        .boxed_unsync();
    let (body, body_done_rx) = tee_body::tee(inner, prefix_cap);

    let pr = ProxiedRequest {
        facts,
        uri,
        body,
        body_done: body_done_rx,
    };

    let proxied = exchange(pr, &shared, started).await;

    Ok(super::exchange::into_response(proxied))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CertificateAuthority;
    use crate::proxy::test_support::{
        drain_and_read_captures, make_request_with_headers, make_shared_with_cfg,
        read_captures_after_stream,
    };
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::Request;
    use std::sync::Arc as StdArc;
    use tokio::fs;

    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The whole point of keeping the components apart: a `Host` carrying a URI
    /// delimiter used to change what the request was *for*.
    ///
    /// Every row here is a request whose target is `/x` and whose `Host` the
    /// client wrote. Under the string reconstruction each one named a different
    /// resource than the client asked for — `/evil/x`, `/a/../../etc/x`, a
    /// query where the path went, and, for the two that did not parse at all, a
    /// target of `http://localhost/` naming a host nobody mentioned and a path
    /// the client never wrote. The origin was sent the rewritten request-line
    /// and the capture recorded it as though the client had.
    #[rstest::rstest]
    // The four delimiters, each of which re-splits a concatenation somewhere
    // other than where it was pasted.
    #[case::path_injected("127.0.0.1:8599/evil")]
    #[case::traversal_injected("127.0.0.1:8599/a/../../etc")]
    #[case::query_injected("127.0.0.1:8599?q=1")]
    #[case::fragment_truncates("127.0.0.1:8599#f")]
    // A value that is no authority under any reading.
    #[case::not_an_authority("not a host")]
    // OWS around the value does not make it one, and `Host` is not a list.
    #[case::padded("  127.0.0.1:8599  x")]
    fn a_host_that_is_not_an_authority_names_no_origin(#[case] host: &str) {
        let req = hyper::Request::builder()
            .uri("/x")
            .header("host", host)
            .body(())
            .expect("a test request");
        let target = TargetUri::reconstruct(&req, &hyper::http::uri::Scheme::HTTP);

        // §3.3's empty authority, which is what "empty or invalid" leaves. There
        // is nowhere to forward such a request, and the fallback that used to
        // stand in for one picked an origin out of the air.
        assert!(target.authority.is_none(), "{host}");
        assert_eq!(target.to_uri(), None, "{host}");

        // And the record still says what the client asked for. This is the half
        // that was lost twice over: the path survived the two cases that parsed
        // only by being pasted somewhere it did not belong, and did not survive
        // the two that did not parse at all.
        assert_eq!(target.to_target_string(), "http:///x", "{host}");
    }

    /// A `Host` that *is* an authority reconstructs exactly, and the path is the
    /// request-target's own.
    #[rstest::rstest]
    #[case::host_and_port("127.0.0.1:8599", "/x", "http://127.0.0.1:8599/x")]
    #[case::no_port("example.com", "/x?a=1", "http://example.com/x?a=1")]
    // The case a `Host` is preserved in: §6.2.2.1's normalisation is the
    // reader's, and a record that lowercased it would be stating something the
    // sender did not write.
    #[case::case_preserved("Example.COM", "/x", "http://Example.COM/x")]
    // An IP-literal is bracketed and holds colons of its own; nothing here may
    // read the first of them as the port delimiter.
    #[case::ip_literal("[2001:db8::1]:8080", "/", "http://[2001:db8::1]:8080/")]
    // OWS around a field value is not part of it.
    #[case::trimmed("  example.com:80  ", "/x", "http://example.com:80/x")]
    fn a_host_that_is_an_authority_reconstructs_exactly(
        #[case] host: &str,
        #[case] target_str: &str,
        #[case] expected: &str,
    ) {
        let req = hyper::Request::builder()
            .uri(target_str)
            .header("host", host)
            .body(())
            .expect("a test request");
        let target = TargetUri::reconstruct(&req, &hyper::http::uri::Scheme::HTTP);
        assert_eq!(target.to_target_string(), expected);
        assert_eq!(
            target.to_uri().map(|u| u.to_string()),
            Some(expected.to_string()),
            "the forwarded URI and the recorded one are one reconstruction",
        );
    }

    /// `Host` is a singleton, and two lines are not two candidates: §3.2 makes
    /// the message one a server answers with a 400, and taking the first would
    /// choose a host by position. Two *identical* lines are the same message.
    #[rstest::rstest]
    #[case::two_hosts(&["a.example", "b.example"])]
    #[case::two_identical(&["a.example", "a.example"])]
    #[case::none(&[])]
    #[case::empty(&[""])]
    #[case::blank(&["   "])]
    fn a_host_that_is_not_exactly_one_value_names_no_origin(#[case] hosts: &[&str]) {
        let mut b = hyper::Request::builder().uri("/x");
        for h in hosts {
            b = b.header("host", *h);
        }
        let req = b.body(()).expect("a test request");
        let target = TargetUri::reconstruct(&req, &hyper::http::uri::Scheme::HTTP);
        assert!(target.authority.is_none(), "{hosts:?}");
        assert_eq!(target.to_target_string(), "http:///x", "{hosts:?}");
    }

    /// The asterisk-form's combined path and query component is empty, and
    /// empty is a thing a record has to be able to state. Gluing the character
    /// onto the authority gave `http://127.0.0.1:8599*/` — an authority no
    /// `uri-host` admits, which then read as an origin disagreeing with `Host`
    /// and drew a cross-origin finding about a conforming server-wide OPTIONS.
    #[test]
    fn an_asterisk_target_names_the_server_and_no_path() {
        let req = hyper::Request::builder()
            .uri("*")
            .header("host", "127.0.0.1:8599")
            .body(())
            .expect("a test request");
        let target = TargetUri::reconstruct(&req, &hyper::http::uri::Scheme::HTTP);
        assert_eq!(target.to_target_string(), "http://127.0.0.1:8599");
        assert!(!target.to_target_string().contains('*'));
        // No `Uri` to forward: an empty path normalises to `/`, which is a
        // request for the root and not the request that was made.
        assert_eq!(target.to_uri(), None);
    }

    /// A target already in absolute-form *is* the target URI. Nothing is
    /// reconstructed, so a disagreeing `Host` cannot move it — which is the
    /// order §3.3 states and the reason a `Host` naming another authority is a
    /// finding rather than an input.
    #[tokio::test]
    async fn an_absolute_form_target_is_recorded_as_the_client_wrote_it() -> anyhow::Result<()> {
        let mock = MockServer::start().await;
        Mock::given(wiremock::matchers::method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock)
            .await;

        let cfg = StdArc::new(crate::config::Config::default());
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, &mut temp).await?;

        let uri = format!("{}/absolute", mock.uri());
        let req = hyper::Request::builder()
            .method("GET")
            .uri(&uri)
            .header("host", "someone.else.example/injected")
            .body(crate::proxy::boxed_full(Bytes::new()))?;
        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 200);

        let entries = drain_and_read_captures(resp, &_cw, &tmp).await?;
        assert_eq!(entries[0]["request"]["uri"].as_str(), Some(uri.as_str()));

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    /// The end-to-end half: a request this proxy cannot resolve an origin for
    /// is refused, and the refusal is its own answer rather than a 502 blaming
    /// an origin that was never asked. The upstream is a mock that fails the
    /// test if anything reaches it — under the string reconstruction it was
    /// reached, with a request-line the client did not write.
    #[tokio::test]
    async fn a_request_naming_no_origin_is_refused_and_nothing_is_forwarded() -> anyhow::Result<()>
    {
        let mock = MockServer::start().await;
        Mock::given(wiremock::matchers::any())
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&mock)
            .await;

        let cfg = StdArc::new(crate::config::Config::default());
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, &mut temp).await?;

        let authority = mock.uri().replace("http://", "");
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/asked-for-this")
            .header("host", format!("{authority}/not-this"))
            .body(crate::proxy::boxed_full(Bytes::new()))?;
        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 400);

        let entries = drain_and_read_captures(resp, &_cw, &tmp).await?;
        assert_eq!(
            entries[0]["request"]["uri"].as_str(),
            Some("http:///asked-for-this"),
            "the record says what the client asked for, not what the Host would have made of it",
        );

        // `expect(0)` is checked when the mock server drops; naming it here says
        // what the row is for.
        drop(mock);
        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_forwards_and_captures() -> anyhow::Result<()> {
        let mock = MockServer::start().await;

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock)
            .await;

        use crate::test_helpers::make_proxy_config_with_enabled_rules;
        let cfg_inner = make_proxy_config_with_enabled_rules(&[
            "cache_control_present",
            "etag_or_last_modified_present",
        ]);
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) =
            make_shared_with_cfg(StdArc::new(cfg_inner), None, &mut temp).await?;

        let req = make_request_with_headers("GET", mock.uri(), None)?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 200);

        let entries = drain_and_read_captures(resp, &_cw, &tmp).await?;
        let v = &entries[0];
        assert_eq!(v["response"]["status"].as_u64(), Some(200));
        // Ensure that violations were captured (non-empty)
        assert!(v["violations"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false));

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_upstream_error() -> anyhow::Result<()> {
        let cfg = StdArc::new(crate::config::Config::default());
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, &mut temp).await?;

        // Use a port that is (likely) closed to provoke a client error
        let req = make_request_with_headers("GET", "http://127.0.0.1:9/", None)?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 502);

        _cw.flush().await?;
        let s = fs::read_to_string(&tmp).await?;
        let v: serde_json::Value = serde_json::from_str(s.trim())?;
        assert_eq!(v["response"]["status"].as_u64(), Some(502));

        // The errored exchange is also recorded into history, so stateful rules
        // can see failure traffic (not just successful exchanges).
        let client =
            crate::state::ClientIdentifier::new("127.0.0.1".parse()?, "unknown".to_string());
        let history = shared.state.get_history(&client, "http://127.0.0.1:9/");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].response.as_ref().unwrap().status, 502);

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_with_relative_uri_builds_from_host() -> anyhow::Result<()> {
        let mock = MockServer::start().await;

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/rel"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock)
            .await;

        let cfg = StdArc::new(crate::config::Config::default());
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, &mut temp).await?;

        // Build a relative URI and set Host header so proxy builds absolute URI from Host
        let host = mock.address().to_string();
        let headers = [("host", host.as_str())];
        let req = make_request_with_headers("GET", "/rel", Some(&headers))?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 200);

        let entries = drain_and_read_captures(resp, &_cw, &tmp).await?;
        let v = &entries[0];
        assert_eq!(v["response"]["status"].as_u64(), Some(200));

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_no_violations_does_not_set_header() -> anyhow::Result<()> {
        let mock = MockServer::start().await;

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/ok"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes("ok".as_bytes())
                    .insert_header("cache-control", "max-age=1")
                    .insert_header("etag", "W/\"1\"")
                    .insert_header("x-content-type-options", "nosniff")
                    .insert_header("content-type", "text/plain; charset=utf-8"),
            )
            .mount(&mock)
            .await;

        let cfg = StdArc::new(crate::config::Config::default());
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, &mut temp).await?;

        let uri = format!("{}/ok", mock.uri());
        let req = make_request_with_headers(
            "GET",
            uri,
            Some(&[("user-agent", "test-agent"), ("accept-encoding", "gzip")]),
        )?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 200);

        let entries = drain_and_read_captures(resp, &_cw, &tmp).await?;
        let v = &entries[0];
        assert_eq!(v["response"]["status"].as_u64(), Some(200));
        // Ensure that there are no violations recorded
        assert!(v["violations"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(true));

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_serves_ca_cert() -> anyhow::Result<()> {
        let mut cfg = crate::config::Config::default();
        cfg.tls.enabled = true;
        let cfg = StdArc::new(cfg);

        // Create a temporary CA for the test
        let mut temp = crate::temp_files::TempFiles::new();
        let ca_dir = temp.dir("lint_http_test_ca");
        let cert_path = ca_dir.join("ca.crt");
        let key_path = ca_dir.join("ca.key");
        let ca = CertificateAuthority::load_or_generate(&cert_path, &key_path).await?;

        let (shared, tmp, _cw) =
            make_shared_with_cfg(cfg.clone(), Some(ca.clone()), &mut temp).await?;

        let req = Request::builder()
            .method("GET")
            .uri("http://localhost/_lint_http/cert")
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/x-x509-ca-cert")
        );

        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("collect body: {}", e))?;
        let body_str = String::from_utf8(body_bytes.to_bytes().to_vec())?;
        assert!(body_str.contains("BEGIN CERTIFICATE"));

        fs::remove_file(&tmp).await?;
        fs::remove_dir_all(&ca_dir).await?;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_connect_without_tls_returns_405() -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(
            StdArc::new(crate::config::Config::default()),
            None,
            &mut temp,
        )
        .await?;

        // Try to use CONNECT method
        let req = Request::builder()
            .method("CONNECT")
            .uri("example.com:443")
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        // Should return 405 because TLS is disabled
        assert_eq!(resp.status().as_u16(), 405);

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    // Replaced by parameterized `connect_cases` test to reduce duplication.

    #[tokio::test]
    async fn handle_request_filters_hop_by_hop_headers() -> anyhow::Result<()> {
        let mock = MockServer::start().await;

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/hop"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("ok")
                    .insert_header("connection", "keep-alive, foo")
                    .insert_header("foo", "bar"),
            )
            .mount(&mock)
            .await;

        let cfg = StdArc::new(crate::config::Config::default());
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, &mut temp).await?;

        let req = make_request_with_headers("GET", format!("{}/hop", mock.uri()), None)?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        // 'connection' and 'foo' should be filtered out
        assert!(resp.headers().get("connection").is_none());
        assert!(resp.headers().get("foo").is_none());

        // Also verify that parse_connection_tokens handles various token formats
        use hyper::header::HeaderValue;
        let parsed = crate::proxy::hop_by_hop::parse_connection_tokens(Some(
            &HeaderValue::from_static("keep-alive, Foo ,"),
        ));
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains("foo"));
        assert!(crate::proxy::hop_by_hop::parse_connection_tokens(Some(
            &HeaderValue::from_static(" , ,a,b")
        ))
        .contains("a"));

        // Now ensure a static hop-by-hop header like 'transfer-encoding' is removed
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/hop2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("ok")
                    .insert_header("transfer-encoding", "chunked"),
            )
            .mount(&mock)
            .await;

        let uri2: Uri = format!("{}/hop2", mock.uri()).parse()?;
        let req2 = Request::builder()
            .method("GET")
            .uri(uri2)
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata2 = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp2 = handle_request(
            req2,
            shared.clone(),
            conn_metadata2,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        assert!(resp2.headers().get("transfer-encoding").is_none());

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    /// An origin that answers one request with `head` and `body` exactly as
    /// given, octet for octet, so the framing under test is the origin's and
    /// not a server library's.
    async fn raw_origin(head: &'static str, body: &'static [u8]) -> anyhow::Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut read = Vec::new();
            let mut buf = [0u8; 1024];
            while !read.windows(4).any(|w| w == b"\r\n\r\n") {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => read.extend_from_slice(&buf[..n]),
                }
            }
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.shutdown().await;
        });
        Ok(format!("http://{addr}/coded"))
    }

    /// The upstream connection undoes `chunked` and nothing beneath it, so a
    /// `gzip` transfer coding is still on the octets relayed. They were relayed
    /// with the field gone, and the client read a gzip member as the plain text
    /// its `Content-Type` named. The codings nobody undid are forwarded now,
    /// and the client connection frames them with its own `chunked`. A
    /// `Content-Length` beside a `Transfer-Encoding` goes whichever codings
    /// it names, since the transfer coding framed the message.
    #[rstest::rstest]
    #[case::gzip_under_chunked(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        b"4\r\n\x1f\x8b\x08\x00\r\n0\r\n\r\n",
        Some("gzip"),
        b"\x1f\x8b\x08\x00"
    )]
    #[case::gzip_to_the_close(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\n",
        b"\x1f\x8b\x08\x00",
        Some("gzip"),
        b"\x1f\x8b\x08\x00"
    )]
    #[case::chunked_beside_a_length(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 99\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"2\r\nok\r\n0\r\n\r\n",
        None,
        b"ok"
    )]
    #[tokio::test]
    async fn handle_request_forwards_the_transfer_codings_it_did_not_undo(
        #[case] head: &'static str,
        #[case] wire_body: &'static [u8],
        #[case] forwarded_codings: Option<&str>,
        #[case] content: &'static [u8],
    ) -> anyhow::Result<()> {
        let uri = raw_origin(head, wire_body).await?;
        let cfg = StdArc::new(crate::config::Config::default());
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, &mut temp).await?;
        let req = make_request_with_headers("GET", uri, None)?;
        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp =
            handle_request(req, shared, conn_metadata, hyper::http::uri::Scheme::HTTP).await?;

        assert_eq!(
            resp.headers()
                .get("transfer-encoding")
                .map(|v| v.to_str())
                .transpose()?,
            forwarded_codings
        );
        assert!(resp.headers().get("content-length").is_none());
        let relayed = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .to_bytes();
        assert_eq!(&relayed[..], content);

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_ca_cert_endpoint_without_tls_returns_404() -> anyhow::Result<()> {
        let cfg = StdArc::new(crate::config::Config::default()); // TLS disabled by default
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, &mut temp).await?;

        let req = Request::builder()
            .method("GET")
            .uri("http://localhost/_lint_http/cert")
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        // Should return 404 because TLS is not enabled
        assert_eq!(resp.status().as_u16(), 404);

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    // Replaced by parameterized `connect_cases` test to reduce duplication.

    // A custom Body that returns an error on collection to trigger the body collect error path
    struct FailingBody;

    impl hyper::body::Body for FailingBody {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            // Simulate an immediate body collection error
            std::task::Poll::Ready(Some(Err(std::io::Error::other("simulated body error"))))
        }
    }

    #[tokio::test]
    async fn handle_http_logic_request_body_error_returns_502() -> anyhow::Result<()> {
        // Upstream that accepts the connection so the client begins sending the
        // request body, which then errors mid-stream.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server_task = tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                // Load-bearing: the origin holds the connection open long
                // enough for the client to start sending, then drops it
                // mid-stream. The delay *is* the condition under test, not a
                // wait for one — there is nothing to poll for.
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                drop(socket);
            }
        });

        let cfg = StdArc::new(crate::config::Config::default());
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, &mut temp).await?;

        let uri: Uri = format!("http://127.0.0.1:{}/error", port).parse()?;
        let req = Request::builder()
            .method("POST")
            .uri(uri)
            .body(FailingBody)?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_http_logic(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        // The request body errors while being streamed upstream, so the exchange
        // fails before any response — a 502 (not a synthesized 500).
        assert_eq!(resp.status().as_u16(), 502);
        let _ = server_task.await;
        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn large_request_body_streams_and_truncates_capture() -> anyhow::Result<()> {
        let mock = MockServer::start().await;
        Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/upload"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock)
            .await;

        let mut cfg = crate::config::Config::default();
        cfg.general.captures_max_body_bytes = 8;
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(StdArc::new(cfg), None, &mut temp).await?;

        // The full 64-byte body is streamed to the upstream (no rejection); only
        // the captured copy is bounded to the 8-byte prefix.
        let req = Request::builder()
            .method("POST")
            .uri(format!("{}/upload", mock.uri()))
            .body(Full::new(Bytes::from(vec![b'a'; 64])))?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_http_logic(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 200);

        let entries = drain_and_read_captures(resp, &_cw, &tmp).await?;
        let v = &entries[0];
        assert_eq!(v["response"]["status"].as_u64(), Some(200));
        assert_eq!(v["request_body_over_limit"].as_bool(), Some(true));
        assert_eq!(v["request"]["body_length"].as_u64(), Some(64));

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn response_body_over_limit_streams_full_and_truncates_capture() -> anyhow::Result<()> {
        let mock = MockServer::start().await;
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-upstream", "yes")
                    .set_body_bytes(vec![b'b'; 64]),
            )
            .mount(&mock)
            .await;

        let mut cfg = crate::config::Config::default();
        cfg.general.captures_max_body_bytes = 8;
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(StdArc::new(cfg), None, &mut temp).await?;

        let req = make_request_with_headers("GET", mock.uri(), None)?;
        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        // The full response is streamed to the client (no rejection); only the
        // captured copy is bounded.
        assert_eq!(resp.status().as_u16(), 200);
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("collect body: {}", e))?
            .to_bytes();
        assert_eq!(body.len(), 64);

        // The capture holds only the bounded prefix, marked truncated, while
        // body_length records the real streamed total.
        let entries = read_captures_after_stream(&_cw, &tmp).await?;
        let v = &entries[0];
        assert_eq!(v["response"]["status"].as_u64(), Some(200));
        assert_eq!(v["response_body_over_limit"].as_bool(), Some(true));
        assert_eq!(v["request_body_over_limit"].as_bool(), Some(false));
        assert_eq!(v["response"]["body_length"].as_u64(), Some(64));

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn response_body_exactly_at_limit_passes() -> anyhow::Result<()> {
        let mock = MockServer::start().await;
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'c'; 8]))
            .mount(&mock)
            .await;

        let mut cfg = crate::config::Config::default();
        cfg.general.captures_max_body_bytes = 8;
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(StdArc::new(cfg), None, &mut temp).await?;

        let req = make_request_with_headers("GET", mock.uri(), None)?;
        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 200);

        // Exactly at the prefix cap: captured in full, not marked truncated.
        let entries = drain_and_read_captures(resp, &_cw, &tmp).await?;
        let v = &entries[0];
        assert_eq!(v["response"]["body_length"].as_u64(), Some(8));
        assert_eq!(v["response_body_over_limit"].as_bool(), Some(false));

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_respects_suppress_headers() -> anyhow::Result<()> {
        let mock = MockServer::start().await;

        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&mock)
            .await;

        let mut cfg_inner = crate::config::Config::default();
        cfg_inner.tls.suppress_headers = vec!["user-agent".to_string()];
        let cfg = StdArc::new(cfg_inner);
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, &mut temp).await?;

        let uri: Uri = mock.uri().parse()?;
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("user-agent", "should-be-suppressed")
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;
        assert_eq!(resp.status().as_u16(), 200);

        // Ensure the upstream mock did not receive the suppressed header
        let requests = mock
            .received_requests()
            .await
            .expect("expected one request to be received");
        assert_eq!(requests.len(), 1);
        assert!(requests[0].headers.get("user-agent").is_none());

        let entries = drain_and_read_captures(resp, &_cw, &tmp).await?;
        let v = &entries[0];
        // The capture still records the original request headers (suppression only affects upstream)
        // Headers serialize as an array of [name, value] pairs.
        let header_present = v["request"]["headers"]
            .as_array()
            .map(|pairs| pairs.iter().any(|p| p[0] == "user-agent"))
            .unwrap_or(false);
        assert!(header_present);

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_various_upstream_responses_exercises_rules() -> anyhow::Result<()> {
        use crate::test_helpers::make_proxy_config_with_enabled_rules;

        let mock = MockServer::start().await;

        // 1) 200 with no content-type -> should trigger content_type_present
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/no-content-type"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock)
            .await;

        // 2) 200 with no etag/last-modified -> should trigger etag_or_last_modified_present
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/no-etag"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&mock)
            .await;

        // 3) 405 with no Allow -> should trigger status_405_allow_valid
        Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/405-no-allow"))
            .respond_with(ResponseTemplate::new(405).set_body_string("not allowed"))
            .mount(&mock)
            .await;

        let cfg_inner = make_proxy_config_with_enabled_rules(&[
            "content_type_present",
            "etag_or_last_modified_present",
            "status_405_allow_valid",
        ]);
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) =
            make_shared_with_cfg(StdArc::new(cfg_inner), None, &mut temp).await?;

        let cases = vec!["/no-content-type", "/no-etag", "/405-no-allow"];
        for path in cases {
            let uri: Uri = format!("{}{}", mock.uri(), path).parse()?;
            let req = Request::builder()
                .method("GET")
                .uri(uri)
                .body(Full::new(Bytes::new()).boxed())?;

            let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
                "127.0.0.1:12345".parse()?,
            ));
            let resp = handle_request(
                req,
                shared.clone(),
                conn_metadata,
                hyper::http::uri::Scheme::HTTP,
            )
            .await?;

            assert!(resp.status().as_u16() == 200 || resp.status().as_u16() == 405);
        }

        // Read the capture file and ensure there is at least one violation recorded among the JSONL entries
        _cw.flush().await?;
        let s = tokio::fs::read_to_string(&tmp).await?;
        let mut found_violation = false;
        for line in s.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let v: serde_json::Value = serde_json::from_str(line)?;
            if v["violations"]
                .as_array()
                .map(|a| !a.is_empty())
                .unwrap_or(false)
            {
                found_violation = true;
                break;
            }
        }
        assert!(
            found_violation,
            "expected at least one capture with a violation"
        );

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_request_relative_uri_with_invalid_host_falls_back_and_returns_502(
    ) -> anyhow::Result<()> {
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(
            StdArc::new(crate::config::Config::default()),
            None,
            &mut temp,
        )
        .await?;

        // Relative URI with invalid Host header should fail to parse and fallback to localhost
        let req = Request::builder()
            .method("GET")
            .uri("/willfail")
            .header(hyper::header::HOST, "bad host")
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_request(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        // Expect 502 (or 400 in case of immediate request rejection) because client will fail to connect to localhost
        let status = resp.status().as_u16();
        assert!(
            status == 502 || status == 400,
            "unexpected status: {}",
            status
        );

        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_http_logic_upstream_body_error_streams_partial() -> anyhow::Result<()> {
        // Start a raw TCP server that returns a truncated response body
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let server_task = tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                // Read the request (drain input)
                let mut buf = [0u8; 1024];
                let _ = socket.readable().await;
                let _ = socket.try_read(&mut buf);

                // Write headers with Content-Length 10 but only send 3 bytes, then close
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
                let _ = socket.try_write(resp);
                // Drop socket to close connection prematurely
            }
        });

        let cfg = StdArc::new(crate::config::Config::default());
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, &mut temp).await?;

        let uri: Uri = format!("http://127.0.0.1:{}/", addr.port()).parse()?;
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_http_logic(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        // Streaming: the status line is sent before the body, so an upstream
        // body error surfaces as a failed body read, not a synthesized 500.
        assert_eq!(resp.status().as_u16(), 200);
        let collected = resp.into_body().collect().await;
        assert!(collected.is_err(), "truncated upstream body should error");

        // The partial response is still captured (real status + the bytes that
        // arrived before the error).
        let entries = read_captures_after_stream(&_cw, &tmp).await?;
        let v = &entries[0];
        assert_eq!(v["response"]["status"].as_u64(), Some(200));
        assert_eq!(v["response"]["body_length"].as_u64(), Some(3));

        let _ = server_task.await;
        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    /// Pin the boundary `status_103_early_hints_before_final` publishes: on
    /// this leg an interim response never reaches a capture. hyper's HTTP/1.x
    /// client returns no message head for `100 | 102..=199` and reads on for the
    /// final response, so an origin sending `103` then `200` is recorded as one
    /// transaction whose response is the `200` — the `Link` field the `103`
    /// carried is not in the capture at all. That rule's finding is therefore
    /// reachable only over HTTP/3 (where `h3::client`'s `recv_response` returns
    /// the first HEADERS frame whatever its status) or through `lint-captures` over a
    /// capture written elsewhere; if a hyper upgrade ever surfaces informational
    /// responses here, this test is what says so.
    #[tokio::test]
    async fn an_interim_response_is_not_what_the_capture_records() -> anyhow::Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let server_task = tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.readable().await;
                let _ = socket.try_read(&mut buf);

                // RFC 8297 § 2's own worked exchange, on the wire: the interim
                // response, then the final one.
                let _ = socket.writable().await;
                let _ = socket.try_write(
                    b"HTTP/1.1 103 Early Hints\r\n\
                      Link: </style.css>; rel=preload; as=style\r\n\
                      \r\n\
                      HTTP/1.1 200 OK\r\n\
                      Content-Length: 2\r\n\
                      \r\n\
                      ok",
                );
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        });

        let cfg = StdArc::new(crate::config::Config::default());
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, cw) = make_shared_with_cfg(cfg, None, &mut temp).await?;

        let uri: Uri = format!("http://127.0.0.1:{}/", addr.port()).parse()?;
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_http_logic(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        assert_eq!(
            resp.status().as_u16(),
            200,
            "the interim response is not it"
        );

        let entries = drain_and_read_captures(resp, &cw, &tmp).await?;
        assert_eq!(entries.len(), 1, "one request, one recorded transaction");
        assert_eq!(entries[0]["response"]["status"].as_u64(), Some(200));
        assert!(
            entries[0]["response"]["headers"].get("link").is_none(),
            "the interim response's fields are not recorded either"
        );

        let _ = server_task.await;
        let _ = fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_http_logic_websocket_upgrade_path() -> anyhow::Result<()> {
        // Start a WebSocket echo server
        let ws_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let ws_port = ws_listener.local_addr()?.port();

        tokio::spawn(async move {
            while let Ok((stream, _)) = ws_listener.accept().await {
                tokio::spawn(async move {
                    let ws = tokio_tungstenite::accept_async(stream).await;
                    if let Ok(mut ws) = ws {
                        use futures_util::{SinkExt, StreamExt};
                        while let Some(Ok(msg)) = ws.next().await {
                            if msg.is_close() {
                                let _ = ws.close(None).await;
                                break;
                            }
                            let _ = ws.send(msg).await;
                        }
                    }
                });
            }
        });

        let cfg = StdArc::new(crate::config::Config::default());
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, &mut temp).await?;

        // Build a WebSocket upgrade request with full URI
        let uri: Uri = format!("http://127.0.0.1:{}/ws", ws_port).parse()?;
        let ws_key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            uuid::Uuid::new_v4().as_bytes(),
        );
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", ws_key)
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = handle_http_logic(
            req,
            shared.clone(),
            conn_metadata,
            hyper::http::uri::Scheme::HTTP,
        )
        .await?;

        // Should get a 101 Switching Protocols response
        assert_eq!(resp.status().as_u16(), 101);
        // Verify upgrade headers are forwarded
        assert!(resp.headers().get("upgrade").is_some());

        // The 101's commit is detached, like a streamed body's, so wait for the
        // record rather than for 200ms and hope. The sleep this replaces was
        // followed by a `flush()`, which cannot help: flushing writes what is
        // already queued, and the question here is whether the relay task has
        // queued anything yet.
        let entries = read_captures_after_stream(&_cw, &tmp).await?;
        let v = &entries[0];
        assert_eq!(v["response"]["status"].as_u64(), Some(101));
        assert_eq!(v["was_upgraded"].as_bool(), Some(true));
        assert_eq!(v["upgrade_protocol"].as_str(), Some("websocket"));

        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    #[tokio::test]
    async fn handle_http_logic_non_ws_101_marks_upgrade() -> anyhow::Result<()> {
        // A non-WebSocket request to an upstream that returns 101 should mark
        // the transaction as upgraded with the appropriate protocol.
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();

        let server_task = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = socket.readable().await;
                let _ = socket.try_read(&mut buf);
                let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n";
                let _ = socket.write_all(resp).await;
                // Keep connection open briefly for hyper to process the 101
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        });

        let cfg = StdArc::new(crate::config::Config::default());
        let mut temp = crate::temp_files::TempFiles::new();
        let (shared, tmp, _cw) = make_shared_with_cfg(cfg, None, &mut temp).await?;

        // Regular GET — NOT a WebSocket upgrade request
        let uri: Uri = format!("http://127.0.0.1:{}/upgrade", port).parse()?;
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .body(Full::new(Bytes::new()).boxed())?;

        let conn_metadata = StdArc::new(crate::connection::ConnectionMetadata::new(
            "127.0.0.1:12345".parse()?,
        ));
        let resp = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle_http_logic(
                req,
                shared.clone(),
                conn_metadata,
                hyper::http::uri::Scheme::HTTP,
            ),
        )
        .await??;

        // The LegacyClient should forward the 101 response and the proxy
        // should mark the transaction as upgraded.
        assert_eq!(resp.status().as_u16(), 101);
        // Upgrade and Connection headers must be preserved for 101 responses
        assert_eq!(
            resp.headers().get("upgrade").and_then(|v| v.to_str().ok()),
            Some("h2c")
        );
        assert!(resp.headers().get("connection").is_some());

        let entries = drain_and_read_captures(resp, &_cw, &tmp).await?;
        let v = &entries[0];
        assert_eq!(v["was_upgraded"].as_bool(), Some(true));
        assert_eq!(v["upgrade_protocol"].as_str(), Some("h2c"));

        let _ = server_task.await;
        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }
}
