<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Response 426 Upgrade

## Description

Reports a `426 (Upgrade Required)` response that carries no `Upgrade` header field, and one whose `Upgrade` names no protocol.

**The requirement is stated twice, in the two sections that own the halves of it.** RFC 9110 §15.5.22: *The server MUST send an Upgrade header field in a 426 response to indicate the required protocol(s) (Section 7.8).* And §7.8, from the field's side: *A server that sends a 426 (Upgrade Required) response MUST send an Upgrade header field to indicate the acceptable protocols, in order of descending preference.* The status itself is what makes the field load-bearing — it says the server *refuses to perform the request using the current protocol but might be willing to do so after the client upgrades to a different protocol*, so a 426 with no `Upgrade` asks for a change it does not describe.

**The second finding is the clause after "to indicate".** `Upgrade` is `#protocol`, so `Upgrade:` is a well-formed list of no protocols and no grammar rule reports it — `message_upgrade_header_syntax_valid` says so explicitly. What this rule reports is not the grammar but the purpose: on a 426 the field is sent to name what to upgrade to, and a list of none names nothing. On every other response that same value draws nothing from anybody, which is what makes this the *status's* requirement rather than the field's. (Contrast `Allow` on a 405, where §10.2.1 gives the empty value a documented meaning — *the resource allows no methods* — and `server_response_405_allow` therefore accepts it.)

**Two versions are declined, and each has its own sentence.** Over HTTP/2 an endpoint MUST NOT generate a message containing connection-specific header fields (RFC 9113 §8.2.2), and over HTTP/3 the Upgrade mechanism does not exist at all (RFC 9114 §4.5) — so on those versions this MUST cannot be obeyed, and asking for the field would be advice a server must not follow. That is the defect `client_sec_websocket_headers_consistency` was once reported for: a rule demanding a field on versions that forbid it. A 426 that *does* carry `Upgrade` there is reported by `message_no_connection_specific_fields`, with the version's own sentence, so nothing is unreported by this decline. The **response's** version decides it, not the request's: a reverse proxy may have taken the request over one version and answered from an origin speaking another, and the field would have been written in the section this response carries. The test is *not one of the two that forbid it* rather than *is this HTTP/1.x*, so a version deriving from no `HTTP-version` production is still measured.

**A trailer does not answer it.** The requirement names a header field, and §6.5.1 forbids a trailer field unless the field's own definition permits one, which §7.8 does not. A 426 carrying `Upgrade` only in its trailer section is reported here as carrying none, and the finding says the trailer was seen; that the placement is itself a defect is `message_trailer_fields_validity`'s finding, whose §6.5.1 table names this field.

**Not reported: the order.** §7.8 asks for the protocols *in order of descending preference*, which is what a sender meant by the order it wrote — no field records a preference for the order to disagree with. Nor is any name checked against the Upgrade Token Registry: §16.7's policy is First Come First Served and §7.8's *ought to be registered* is not a requirement.

**What the neighbours own.** Whether the value derives from `protocol = protocol-name ["/" protocol-version]` is `message_upgrade_header_syntax_valid`'s. Whether the field is named by an `upgrade` connection option — which §7.8 asks of every sender of `Upgrade`, including this one — is `message_connection_upgrade`'s. The mirror requirement on a `101` response, and the rule that the chosen protocol was one the client offered, is `stateful_101_switching_protocols`'s.

Scope: this rule reads a response's header section, and its subject is *the server* — whatever answered, which for a capture taken at a proxy is the party that wrote this response. Where the field appears on several lines they are one value (§5.2), and the value is read as written rather than through a UTF-8 decode, so a field carrying `obs-text` counts as a field that is there.

## Specifications

- [RFC 9110 §15.5.22](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.22): 426 Upgrade Required — the MUST, its object clause (to indicate the required protocol(s)), and what the status itself says the server is asking the client to do
- [RFC 9110 §7.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8): Upgrade — the same MUST from the field's side, worded with the ordering clause; also the MAY that licenses the field's absence on every other response
- [RFC 9113 §8.2.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2): Connection-Specific Header Fields — why an HTTP/2 response is not asked for a field it must not generate
- [RFC 9114 §4.5](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.5): HTTP Upgrade — HTTP/3 does not have the mechanism this field belongs to, which is a stronger reason than the field being forbidden
- [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5): A field value excludes the whitespace around it, so a value that is only whitespace is the empty value
- [RFC 9110 §5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2): Several `Upgrade` lines in one field section are one field value, so the field is there if any line carries it
- [RFC 9110 §6.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1): Why an `Upgrade` in the trailer section does not answer this requirement — a trailer field needs its own definition's permission, and §7.8 gives none

## Configuration

```toml
[rules.server_response_426_upgrade]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good §15.5.22's own worked example

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 426 Upgrade Required
Upgrade: HTTP/3.0
Connection: Upgrade
Content-Type: text/plain
```

### ✅ Good Every other response MAY carry the field, so its absence says nothing

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/plain
```

### ❌ Bad The MUST's own subject — a 426 carrying no Upgrade at all

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 426 Upgrade Required
Content-Type: text/plain
```

### ❌ Bad The clause after "to indicate" — a list of no protocols names none

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 426 Upgrade Required
Upgrade:
Connection: Upgrade
```
