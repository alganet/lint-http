<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Accept-Encoding Present

## Description

Advice, not conformance: nothing in HTTP requires a client to send `Accept-Encoding`. The rule reports the two request shapes that will not receive compressed content, and they are different findings.

**No `Accept-Encoding` at all.** RFC 9110 §12.5.3 is explicit that this is the *most permissive* state, not the least: "If no Accept-Encoding header field is in the request, any content coding is considered acceptable by the user agent." A server that compresses anyway is conforming. It is still worth reporting, but on honest ground — in practice most deployed servers will not compress without an explicit signal, and that is a fact about servers rather than about the protocol. This rule used to say the opposite, describing absence as meaning "identity only".

**An empty `Accept-Encoding`.** This is the value that means what absence was being blamed for: "An Accept-Encoding header field with a field value that is empty implies that the user agent does not want any content coding in response." It used to pass without a word. A value listing no members — `,` — reads the same way, since an empty element is not an element (§5.6.1.2).

**`identity` is a preference, not a silence.** §12.5.3 calls it "a synonym for 'no encoding'", so a client that sends it has expressed exactly what this field is for and is not reported.

**`CONNECT` is skipped.** It asks for a tunnel rather than a representation (§9.3.6), so no content coding applies to what comes back.

## Specifications

- [RFC 9110 §12.5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3): Accept-Encoding — the grammar, and the two sentences this rule had backwards: absence means every coding is acceptable, while an empty value means none is wanted
- [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6): CONNECT — a tunnel rather than a representation, so nothing comes back for a content coding to apply to
- [RFC 9110 §5.6.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2): Why a field value of `,` lists no codings and reads as empty

## Configuration

```toml
[rules.accept_encoding_present]
enabled = true
severity = "info"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
Host: example.com
Accept-Encoding: gzip, deflate, br
```

### ✅ Good (identity is a stated preference)

```http
GET /resource HTTP/1.1
Host: example.com
Accept-Encoding: identity
```

### ✅ Good (a tunnel has no representation to encode)

```http
CONNECT server.example.com:443 HTTP/1.1
Host: server.example.com
```

### ❌ Bad (no preference expressed)

```http
GET /resource HTTP/1.1
Host: example.com
User-Agent: my-script/1.0
```

### ❌ Bad (every content coding declined)

```http
GET /resource HTTP/1.1
Host: example.com
Accept-Encoding: 
```
