<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Upgrade And Connection Consistent

## Description

Reports a message that carries an `Upgrade` header field without naming the `upgrade` connection-option in `Connection`.

RFC 9110 §7.8 states the pairing in one direction: *A sender of Upgrade MUST also send an "Upgrade" connection option in the Connection header field (Section 7.6.1) to inform intermediaries not to forward this field.* §7.6.1 states the same obligation in general, for any field supplying control information about the current connection. The option is the only thing that makes the field hop-by-hop: without it an intermediary relays a field meant for one connection, and the recipient of a relayed one is told to ignore it — so the upgrade is lost in both directions rather than merely mis-declared.

**The converse is not reported, and this rule used to report only the converse.** A `Connection: upgrade` with no `Upgrade` field beside it is not a defect: §7.6.1 says that connection options do not always correspond to a field present in the message, since a connection-specific field might not be needed when there are no parameters associated with the option. No sentence in RFC 9110 or RFC 9112 makes the missing field a violation. A `101` response that omits `Upgrade` **is** one, by §15.2.2, and `status_101_switching_protocols` is the rule that reports it, and `status_426_upgrade_valid` reports the same obligation on a `426 (Upgrade Required)` response.

**One protocol already had this requirement, and only in one direction of one method.** RFC 6455 §4.1 asks a WebSocket opening handshake for a `Connection` header field whose value includes the `Upgrade` token, and `sec_websocket_headers_consistent` measures that alongside the rest of §4.1's list — so a `GET` whose `Upgrade` names `websocket` is reported by both rules, each from its own document. Everything else the general sentence covers was reported by neither: `Upgrade: h2c`, a `POST` offering `websocket`, and any response carrying the field at all.

The field's presence is what the sentence turns on, not what it holds. `Upgrade` is `#protocol`, so `Upgrade:` with no protocol named is still a field the sender generated and still owes the option. Whether the value derives from `protocol = protocol-name ["/" protocol-version]` is `upgrade_header_syntax`'s question, in both directions and on every version; `status_101_switching_protocols` reads the names in a `101` exchange only, to compare what was offered against what was chosen.

**Only the versions that have a `Connection` field are measured.** HTTP/2 and HTTP/3 convey connection-specific metadata by other means and an endpoint MUST NOT generate a message carrying either of these fields (RFC 9113 §8.2.2, RFC 9114 §4.2), so demanding the option there would be advice a sender must not follow. That those fields are present at all is reported by `no_connection_specific_fields`, on both versions and with each field section measured against the version that carried *it* — so an HTTP/3 response to an HTTP/1.1 request is read there even though this rule declines it.

Scope: this rule reads header sections — a request's and a response's, each against its own protocol version, since a reverse proxy may have received the two over different ones. Where either field appears on several lines in one section they are one value (§5.2), so an `upgrade` option written on a second `Connection` line is listed. A value carrying an octet outside US-ASCII is measured rather than skipped: reading it back through a UTF-8 decoder would turn a field the sender wrote into a message that has no such field, and the obligation would go with it. Whether `Upgrade` may appear in a *trailer* section is §6.5.1's question and `trailer_fields_valid`'s, which holds the table `Upgrade` is listed in.

## Specifications

- [RFC 9110 §7.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8): Upgrade — the sender's obligation to name the field as a connection-option beside it, and the `#protocol` grammar that makes the field's presence the thing the obligation turns on
- [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1): Connection — the same obligation stated generally, what a recipient does with a connection-specific field that arrives without its option, the sentence permitting an option that names no present field, and the note that some versions do not allow the field at all
- [RFC 9113 §8.2.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2): Connection-specific header fields — why an HTTP/2 message is not asked for an option it must not send
- [RFC 9114 §4.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2): HTTP fields — the same prohibition for HTTP/3

## Configuration

```toml
[rules.upgrade_and_connection_consistent]
enabled = true
severity = "warn"

# Server Rules
```

## Examples

### ✅ Good

```http
Connection: upgrade
Upgrade: websocket
```

### ✅ Good (an option needs no field)

```http
Connection: upgrade
```

### ❌ Bad

```http
Connection: keep-alive
Upgrade: websocket
```
