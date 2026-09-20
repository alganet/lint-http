<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Alt-Svc H3 Advertisement Valid

## Description

Reads the `Alt-Svc` response header field and asks one thing of it: that an HTTP/3 endpoint is advertised under a name a current client answers to.

RFC 9114 §3.1.1: *"An HTTP origin can advertise the availability of an equivalent HTTP/3 endpoint via the Alt-Svc HTTP response header field or the HTTP/2 ALTSVC frame ([ALTSVC]) using the "h3" ALPN token."* A draft-era token — `h3-29`, `h3-Q050`, `h3-27` — is a different ALPN protocol name, so a client that speaks HTTP/3 and not that draft finds nothing it can use at the alternative. **It is reported only where the field names no `h3` at all**, because that sentence asks an origin to advertise an equivalent HTTP/3 endpoint using `h3`, and a field carrying `h3` has done so — the draft alternative beside it is one a client that knows only `h3` never looks at. `Alt-Svc: h3=":443", h3-29=":443"` is the shape almost every draft advertisement on the web is written in and draws nothing; `Alt-Svc: h3-29=":443"` is the whole HTTP/3 offer written under a name nothing current negotiates, and draws the finding.

**The `h3` is looked for byte-exactly** where the draft scan folds case, and the asymmetry runs the right way in both places: the fold only widens what is reported, and `H3` is not `h3` to a recipient doing §3's *"simple string comparison"*, so `H3=":443", h3-29=":443"` still offers HTTP/3 under the draft name alone.

**Everything else about the field is `alt_svc_header_syntax`'s**, on every protocol rather than on `h3` alone: the shape of a member and of a parameter, and — since the lifetime RFC 7838 §3.1 defines belongs to an `alt-value` and not to an HTTP/3 one — the `ma` parameter, which this rule used to read behind the `h3` gate and no longer does. Whether the ALPN name is registered is `alt_svc_protocol_registered`'s.

The field lines are joined before they are read (RFC 9110 §5.3), because `1#alt-value` is the list that licenses the join, and the value is read one `char` per octet so that an `obs-text` octet is measured rather than hiding the line it is written on.

## Violations

- [alpn_protocol_name_obsolete](../violations/alpn_protocol_name_obsolete.md) — ALPN protocol name identifies a draft of a shipped protocol

## Specifications

- [RFC 9114 §3.1.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1.1): HTTP Alternative Services — advertising HTTP/3 via Alt-Svc using the "h3" ALPN token
- [RFC 7838 §3](https://www.rfc-editor.org/rfc/rfc7838.html#section-3): Alt-Svc — the field's grammar, the `parameter` production, and the requirement that a recipient ignore a parameter name it does not know

## Configuration

```toml
[rules.alt_svc_h3_advertisement_valid]
enabled = true
```

## Examples

### ✅ Good The shipped ALPN token

```http
Alt-Svc: h3=":443"; ma=2592000
```

### ✅ Good An `h3` entry beside another protocol's

```http
Alt-Svc: h2=":443", h3=":443"; ma=3600
```

### ✅ Good A draft token beside the final one: the client takes `h3`

```http
Alt-Svc: h3=":443"; ma=86400, h3-29=":443"; ma=86400
```

### ❌ Bad A draft protocol identifier, and the whole HTTP/3 offer

```http
Alt-Svc: h3-29=":443"
```

### ❌ Bad Two draft tokens, and no final one beside them

```http
Alt-Svc: h3-29=":443", h3-27=":443"
```
