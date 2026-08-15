<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Redirect To The Request's Own Target

## Description

Reports a redirect whose `Location` resolves to the target URI of the request it answers — a redirection to where the client already is. Following it produces the same request, and following that produces the same response.

**The status set is the statuses whose own definition says the field names another resource.** Five say it in as many words — `301` and `308` a *new permanent* URI (RFC 9110 §15.4.2, §15.4.9), `302` and `307` a *different* URI (§15.4.3, §15.4.8), and `303` adds that the URI in the field *"is not considered equivalent to the target URI"* (§15.4.4) — and a `300`'s `Location` is *"a preferred choice's URI reference"* among representations *"each with its own more specific identifier"* (§15.4.1). An unregistered 3xx is a `300` to every conforming recipient (§15) and is reported the same way.

**`304`, `305`, `306` and `201` are not reported.** A `304` redirects the client to a representation it already holds rather than to another URI; `305` is deprecated and `306` reserved, so neither defines anything to follow. A `201 Created` naming the request's own target is the case §15.3.2 *defines* — a `PUT` that creates the resource where it was addressed — and that response would mean the same thing carrying no field at all.

**The comparison is between absolute forms, not between strings.** The target URI is reconstructed from the request-target and the `Host` field (RFC 9112 §3.3), and the `Location` is resolved against it (§10.2.2, RFC 3986 §5), so `page`, `/dir/page` and `https://host/dir/page` are recognised as one resource, and a value naming a different host is not reported however its path reads. Both sides then get RFC 3986 §6.2.2's syntax-based normalization, so a dot segment and a needlessly percent-encoded `unreserved` character are spellings rather than resources: `/a%2Db` and `/a-b` are one path, and — since §2.3 names the period among the octets a normalizer decodes — so are `/dir/%2E%2E/dir/page` and `/dir/page`. `%2F` is not decoded, because that would move a segment boundary the sender never wrote (§2.4). §6.2.3's scheme-based normalization is **not** applied, so a `Location` writing out the scheme's default port does not compare equal to a target that left it off.

**Two things the capture cannot decide, and the rule declines both.** A request-target in origin-form carries no scheme — RFC 9112 §3.3 takes it from whether the connection was secured, which is not in the message — so a `Location` naming a scheme is not compared; the case that would otherwise be reported is the ordinary HTTP-to-HTTPS redirect. Likewise a reference naming a host is not compared when no `Host` field says which host was addressed.

**This is advice.** No sentence forbids a server from sending it. The status definitions above *declare* what the field names rather than requiring anything of it, and the one requirement in the area — §15.4's *"A client SHOULD detect and intervene in cyclical redirections"* — is addressed to the client, which is the role this rule is performing. What the finding buys is that a redirect no client can resolve becomes visible.

**Longer cycles are not detected, and the rule reads no history.** A cycle spanning two or more resources needs a history that spans resources; the state layer's origin-scoped query derives that origin from the request-target alone, so it is empty for the origin-form target an HTTP/1.1 request carries. Only the one-step cycle is reported.

The field's grammar, an empty value, and a response carrying more than one `Location` field line are `server_location_header_uri_valid`'s findings; a `Location` on a status with no use for one is `server_redirect_status_and_location_validity`'s; a redirect status carrying *no* `Location` is `server_response_location_on_redirect`'s.

## Specifications

- [RFC 9110 §15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4): Redirection 3xx: a client SHOULD detect and intervene in cyclical redirections, and MAY follow a Location even where the specific status code is not understood
- [RFC 9110 §10.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2): Location: a relative reference is resolved against the target URI, and a fragmentless value inherits the target's fragment
- [RFC 9110 §15.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.2): 201 Created: with no Location field the resource created is the target URI, which is why a 201 naming its own target is not reported
- [RFC 9112 §3.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.3): Reconstructing the target URI: the authority comes from Host when the request-target has none, and the scheme from the connection — which the capture does not record
- [RFC 3986 §5](https://www.rfc-editor.org/rfc/rfc3986.html#section-5): Reference resolution: the transform that makes a Location value and a request-target comparable
- [RFC 3986 §6.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2): Syntax-Based Normalization: all three of its normalizations are applied to both sides after resolution — the percent-encoding decoded where the octet is unreserved, the dot segments removed, and the case of the path and query left alone. §6.2.3's scheme-based normalization is not applied

## Configuration

```toml
[rules.stateful_redirect_chain_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (the field names somewhere else)

```http
GET /old HTTP/1.1
Host: example.com

HTTP/1.1 301 Moved Permanently
Location: /new
```

### ✅ Good (canonicalizing to another host: same path, different authority)

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 301 Moved Permanently
Location: https://www.example.com/a
```

### ✅ Good (the created resource is the target — RFC 9110 §15.3.2)

```http
PUT /widgets/123 HTTP/1.1
Host: example.com

HTTP/1.1 201 Created
Location: /widgets/123
```

### ❌ Bad (the field names the request's own target)

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 301 Moved Permanently
Location: /a
```

### ❌ Bad (a relative-path reference resolving to the same resource)

```http
GET /dir/page HTTP/1.1
Host: example.com

HTTP/1.1 302 Found
Location: page
```

### ❌ Bad (same authority, same path, written out in full)

```http
GET http://example.com/a HTTP/1.1
Host: example.com

HTTP/1.1 303 See Other
Location: http://example.com/a
```
