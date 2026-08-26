<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HTTP/2 Pseudo-Headers Validity

## Description

HTTP/2 carries a request's control data as pseudo-header fields — `:method`, `:scheme`, `:authority` and `:path` — and this rule reads what each of them conveyed. **It runs on HTTP/2 requests only.** It had no version gate at all until this audit, so every finding below was also made of HTTP/1.1 and HTTP/3 messages, described as HTTP/2, alongside the report from whichever rule owns the question on those versions.

**The fields are not in the captured field section.** A transport that carries control data as pseudo-headers hands its library a method and a target URI reassembled from `:scheme`, `:authority` and `:path`, and that is what a capture records. So each check reads the component the pseudo-header conveyed, and the checks are shaped by which of the request-target forms the reassembly produced.

- **A non-CONNECT request sends exactly one `:path`.** `*` is that value for a server-wide OPTIONS request and for no other method (RFC 9110 §7.1: "These forms MUST NOT be used with other methods"). Otherwise a target with no path at all is reported: an `http` or `https` URI without a path component sends `/`.
- **A basic CONNECT's `:authority` is a host and a port.** `authority-form = uri-host ":" port` requires neither — both halves are `*`-quantified — so the prose is what asks for them: RFC 9110 §9.3.6 has no default port, requires the client to send one even when the URI reference elided it, and requires a server to reject an empty or invalid port number.
- **A port above 65535 is reported; `0` is not.** The bound is not the grammar's — `port = *DIGIT` has none, which is why `host_header` reports no port for being out of range. It is that RFC 9113 §8.5 has the proxy open a *TCP* connection to this host and port and TCP's port namespace is sixteen bits wide (RFC 6335 §6). `0` sits inside that namespace as a reserved edge value, and no sentence here makes a reserved port an invalid one.
- **The reassembled `:scheme` and `:authority` are read when the target is in absolute form**: the scheme against `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, the authority against `uri-host [ ":" port ]`, and — for an `http` or `https` target only, because that is how §8.3.1 writes the MUST NOT — a userinfo subcomponent. `:scheme` is deliberately not restricted to `http` and `https`, so nothing here asks whether it is a scheme anybody serves.

**What this rule declines, and why.**

- **Which CONNECT this is, when the target is in absolute form.** RFC 8441's extended CONNECT is marked by a `:protocol` pseudo-header, and on such a request `:scheme` and `:path` MUST be included — exactly what a basic CONNECT MUST omit. A capture records no `:protocol`, so a `CONNECT https://example.com/ws` is a conforming extended CONNECT and a malformed basic one with nothing to choose between them. It is accepted. An *origin-form* CONNECT target is reported when no `Host` field accompanies it, because that is neither CONNECT: it is a `:path` with no `:scheme` and no authority anywhere.
- **The method token itself.** `method = token` admits no whitespace and no empty string, and a value failing it names nothing for the branches above to turn on, so the rule stops. `request_method_token_valid` reports it, on every version. The method is compared as written throughout — `connect` is not CONNECT and `options` is not OPTIONS (RFC 9110 §9.1) — where the case-folding this replaced *suppressed* findings.
- **The characters inside the target.** Whitespace and a malformed percent-encoding triplet were both reported here and by `request_uri_percent_encoding_valid`, which reads the whole target on every version. Both duplicates are gone.
- **Where the pseudo-headers sat, and how many there were.** RFC 9113 §8.3 requires them to precede every regular field line and forbids a repeated name. The capture holds no pseudo-header fields and no field order, so neither has a representation to check.
- **Whether a `Host` field agrees with `:authority`.** §8.3.1 forbids a client from generating a request where they differ. `message_host_and_authority_consistency` asks it, of this version and of HTTP/3, and keeps the two documents apart on what comparing the values means.

**Nothing here reads the response.** RFC 9113 §8.3.2 requires a response to carry exactly one `:status` pseudo-header field, which the canonical transaction model always supplies as a `u16`, so its absence has no representation to check; and the range that value must fall in is RFC 9110 §15's, which is the same for every HTTP version and is reported by `server_status_code_valid_range`.

## Specifications

- [RFC 9113 §8.3](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3): HTTP Control Data — what a pseudo-header field is, and that a request carrying an invalid one is malformed. Its two requirements about the field block itself (ordering before regular field lines, one occurrence per name) are not checked: a capture holds no pseudo-header fields and no field order.
- [RFC 9113 §8.3.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1): Request Pseudo-Header Fields — what each of `:method`, `:scheme`, `:authority` and `:path` conveys, the `'*'` value for asterisk-form OPTIONS, the `:path`-must-not-be-empty MUST, and the userinfo MUST NOT written for `http` and `https` targets
- [RFC 9113 §8.3.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.2): Response Pseudo-Header Fields — `:status` is always present in this model and its range is RFC 9110 §15's, so nothing here reads it
- [RFC 9113 §8.5](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5): The CONNECT Method — `:method` is set to CONNECT, `:scheme` and `:path` are omitted, `:authority` carries the host and port, and the proxy opens a TCP connection to them
- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): Overview of methods — `method = token`, and the token is case-sensitive, which is why CONNECT and OPTIONS are matched exactly
- [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6): CONNECT — the host and port number of the tunnel destination, the absence of a default port, and the server's MUST to reject an empty or invalid one. This is where the port requirements come from; the grammar states none.
- [RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1): Determining the Target Resource — the asterisk is OPTIONS's target and the method-specific forms must not be used with other methods
- [RFC 9112 §3.2.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.3): authority-form — the production RFC 9113 §8.5 points at for what `:authority` carries on a CONNECT, and where both halves turn out to be `*`-quantified
- [RFC 8441 §4](https://www.rfc-editor.org/rfc/rfc8441.html#section-4): The Extended CONNECT Method — `:protocol` is what distinguishes it, and on such a request `:scheme` and `:path` MUST be included. A capture records no `:protocol`, which is why an absolute-form CONNECT target is accepted.
- [RFC 6335 §6](https://www.rfc-editor.org/rfc/rfc6335.html#section-6): Port Number Ranges — the 16-bit namespace that bounds a CONNECT port above, and the reserved edge values that are why `0` is not reported

## Configuration

```toml
[rules.message_http2_pseudo_headers_validity]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
:method: GET
:scheme: https
:authority: example.com
:path: /
```

```http
:method: OPTIONS
:scheme: https
:authority: example.com
:path: *
```

```http
:method: CONNECT
:authority: example.com:443
```

### ✅ Good Extended CONNECT: :protocol is not recorded in a capture, so a CONNECT carrying :scheme and :path is accepted

```http
:method: CONNECT
:protocol: websocket
:scheme: https
:authority: example.com
:path: /ws
```

### ❌ Bad A non-CONNECT request with no :path

```http
:method: GET
:scheme: https
:authority: example.com
```

### ❌ Bad The asterisk is OPTIONS's :path value and no other method's

```http
:method: GET
:scheme: https
:authority: example.com
:path: *
```

### ❌ Bad A CONNECT has no default port, so the port is sent

```http
:method: CONNECT
:authority: example.com
```

### ❌ Bad An 'https' target's authority carries no userinfo

```http
:method: GET
:scheme: https
:authority: user:pass@example.com
:path: /
```
