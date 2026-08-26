<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# No Connection Specific Fields

## Description

Reports a connection-specific header field in a message carried by a version of HTTP that has none.

`Connection`, `Keep-Alive`, `Proxy-Connection`, `Transfer-Encoding` and `Upgrade` supply control information about one hop, and HTTP/2 and HTTP/3 convey that metadata by other means. Both documents say so in the same four sentences: the version does not use the `Connection` field, an endpoint MUST NOT generate a message containing connection-specific fields, any such message MUST be treated as malformed, and an intermediary transforming an HTTP/1.x message MUST remove them or its output will be treated as malformed by other endpoints. **Presence is the whole finding** — no value is read, because a message this rule reports has already been called malformed, and whether the value derives from its field's own production is that field's rule's question.

**The two documents are not copies of each other, and the difference is what the finding may claim.** RFC 9113 §8.2.2 closes the list by name in the sentence after its MUST NOT — *that is, Proxy-Connection, Keep-Alive, Transfer-Encoding, and Upgrade* — so over HTTP/2 these five names are the entire requirement and a name's absence from these findings is a verdict. RFC 9114 §4.2 enumerates nothing at all, deferring to RFC 9110 §7.6.1, whose list opens *This includes but is not limited to* and is a SHOULD addressed to intermediaries. So over HTTP/3 the same five names are a **subset**, and a field this rule passes is not a field it has cleared.

**`TE` is the one exception, and it is an exception for one direction.** Both sections restore it to *an HTTP/2 request* / *an HTTP/3 request header*, and say that when it is present it MUST NOT contain any value other than `trailers`. So in a request the field is permitted and its members are measured; in a **response** no exception applies, and the field is connection-specific like the five above it — RFC 9110 §10.1.4 defines it as describing the capabilities of the *client*, so a server writing one has said nothing a recipient can use. The comparison against `trailers` folds case, and the sentence licensing that is RFC 5234 §2.3's — `t-codings = "trailers" / ( transfer-coding [ weight ] )` writes the keyword as an ABNF string, and ABNF strings are case-insensitive — rather than anything in either version's own document. An empty list element is not a value and is not reported here; that it was generated is §5.6.1.1's MUST NOT and `message_te_header_constraints`'s finding. An empty field value is likewise not reported: `TE:` contains no value, and RFC 9112 §7.4 prints it as one of its three worked examples.

**Each field section is measured against the version that carried it.** A reverse proxy may have received the request over one version and the response over another, so the request's version decides nothing about the response's fields — reading both against the request's, which this rule used to do, let every HTTP/3 response to an HTTP/1.1 request through untouched, and it was the version gate rather than any branch that did it.

**What the transports do to these findings before the linter sees them, and it differs by version.** Over HTTP/3 the `h3` crate this proxy uses filters nothing, so every finding here is live on traffic the proxy captured itself. Over HTTP/2 `h2` 0.4.14 refuses all five names on **both** its paths — on receive in `src/frame/headers.rs`, which fails the HEADERS block as a malformed message before the fields reach hyper, and on send in `src/proto/streams/send.rs` — so those findings are reachable only through `lint` over captures written elsewhere. This is a claim about a dependency and it is deliberately not pinned by a test: `h2` puts its frame layer behind an `unstable` feature, so the check would cost a build flag on a transitive crate. The version is the one in `Cargo.lock`, and a reader wanting to confirm it has the two file names.

The one HTTP/2 finding that survives the library is the **`TE` in a response**: `h2`'s filter tests the field's value and never its direction, so `te: trailers` in a response passes it and reaches the capture. That same filter is byte-exact where the grammar is not, which means `h2` resets a `te: Trailers` that RFC 5234 §2.3 says derives from the production — a deployed reading that **disagrees** with this rule rather than corroborating it, recorded here because a reader comparing the two should not conclude the rule is wrong.

Scope: this rule reads header sections. The word both documents use is *field section*, which includes a trailer section — that half is `message_trailer_fields_validity`'s, whose §6.5.1 table holds `Connection`, `Keep-Alive`, `Upgrade`, `Transfer-Encoding` and `TE`, for every version rather than only these two. **It does not hold `Proxy-Connection`**, so that one field arriving in a trailer section is reported by neither rule: this one does not read trailers, and the other's table omits it. The omission is that rule's to answer and is recorded rather than fixed here, because widening its table changes the verdicts of a rule whose own audit is closed. What a `Connection` value may itself contain is `connection_header_tokens_valid`'s and what an `Upgrade` value may is `message_upgrade_header_syntax_valid`'s — both measure their field on every version, because this rule reads no value; whether an `Upgrade` field is backed by an `upgrade` connection option is `upgrade_and_connection_consistent`'s; the rest of what a `TE` value may hold in a request is `message_te_header_constraints`'s.

## Specifications

- [RFC 9113 §8.2.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2): Connection-Specific Header Fields — HTTP/2's prohibition, and the one sentence of the two that closes the list of names
- [RFC 9114 §4.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2): HTTP Fields — HTTP/3's prohibition, which enumerates nothing and defers to RFC 9110 §7.6.1
- [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1): Connection — the field itself, and the open list of those that carry connection-specific semantics
- [RFC 9110 §10.1.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4): TE — the capabilities of the client, which is why a response carrying the field gets no part of the exception
- [RFC 5234 §2.3](https://www.rfc-editor.org/rfc/rfc5234.html#section-2.3): Terminal Values — an ABNF string is case-insensitive, which is what licenses matching `trailers` without regard to case

## Configuration

```toml
[rules.no_connection_specific_fields]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/3
Host: example.com
Accept: text/html
```

### ✅ Good The exception, in the direction it is written for

```http
GET /resource HTTP/2
Host: example.com
TE: trailers
```

### ❌ Bad

```http
GET /resource HTTP/2
Host: example.com
Connection: keep-alive
```

```http
POST /data HTTP/3
Host: example.com
Transfer-Encoding: chunked
```

```http
GET /resource HTTP/3
Host: example.com
Upgrade: websocket
```

```http
GET /resource HTTP/2
Host: example.com
TE: gzip, trailers
```

### ❌ Bad The exception is for a request; a response gets none of it

```http
HTTP/2 200 OK
Content-Type: text/html
TE: trailers
```
