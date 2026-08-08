<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Connection Header Tokens Valid

## Description

Validates the `Connection` header field's own value — the list of control options a sender declares for the current connection.

The field is `Connection = [ connection-option *( OWS "," OWS connection-option ) ]` (RFC 9110 §A), and a `connection-option` is a `token` (§7.6.1). So every member must be `1*tchar`: `Connection: a/b` names no option, because `/` is one of the delimiters a token excludes (§5.6.2). No member may be empty — `Connection: keep-alive,,close` is a list a sender MUST NOT generate (§5.6.1.1) — while an **empty value** is a different thing and is not reported: the production's outer brackets make a list of no options a list, so `Connection:` declares nothing rather than declaring badly.

Where the field appears on several lines in one section, the lines are one value (§5.2), so an empty member written at a line boundary is an empty member. A value carrying an octet outside US-ASCII is measured rather than skipped; `obs-text` is an octet `field-content` admits and `token` does not, so the member is reported for not being a token, which is what is wrong with it.

One name is reported as a name. RFC 9110 §7.6.1 says a sender MUST NOT send a connection option corresponding to a field that is intended for all recipients of the content, and gives `Cache-Control` as a field that is never appropriate as one. **That example is the whole of what this rule decides about that sentence.** Whether some other field is intended for all recipients of the content is a property of that field's definition, not of anything the message carries, so a rule reading a `Connection` value cannot answer it in general — and a name's absence from this rule's findings is therefore not a verdict that listing it is permitted. Connection options are case-insensitive, and the comparison is too.

An option is not required to name a field that is present: §7.6.1 says a connection-specific field might not be needed when no parameter is associated with an option, and `close` names no field at all. The converse — a connection-specific field arriving without an option naming it — is not asked here either.

Scope: this rule reads header sections, and measures the value wherever it appears. Some versions of HTTP do not allow the field at all (§7.6.1); `message_http3_no_connection_header` is the rule that reports its presence over HTTP/3. Whether `Connection` may appear in a *trailer* section is §6.5.1's question and `message_trailer_fields_validity`'s. Whether an `upgrade` option is backed by an `Upgrade` field is `message_connection_upgrade`'s.

## Specifications

- [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1): The field itself: its grammar, the case-insensitivity of its options, the note that an option need not correspond to a field present in the message, and the MUST NOT this rule implements for the one field the section names
- [RFC 9110 §A](https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A): The collected grammar, where the list construct is expanded for a sender — the form that shows both that the whole value may be empty and that a member may not
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The sender's half of the list construct. The recipient's half (§5.6.1.2, ignore empty elements) is a different party's requirement, which is why the shared list reader is not used here
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): `token` and `tchar`: what a connection-option is made of, and the delimiters it excludes
- [RFC 9110 §5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2): Several `Connection` lines in one field section are one field value, so the members are counted after the lines are joined

## Configuration

```toml
[rules.message_connection_header_tokens_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good Two options; neither has to name a field that is present

```http
GET / HTTP/1.1
Host: example.com
Connection: keep-alive, close
```

### ✅ Good An option that does name a field, and the field it names

```http
GET / HTTP/1.1
Host: example.com
Connection: upgrade
Upgrade: websocket
```

### ✅ Good A list of no options is a list; the field is `#connection-option`, not `1#connection-option`

```http
GET / HTTP/1.1
Host: example.com
Connection:
```

### ❌ Bad An empty member — the list construct's sender requirement

```http
GET / HTTP/1.1
Host: example.com
Connection: keep-alive,,close
```

### ❌ Bad `/` is a delimiter, so the member is not a token

```http
GET / HTTP/1.1
Host: example.com
Connection: a/b
```

### ❌ Bad A field intended for all recipients of the content

```http
GET / HTTP/1.1
Host: example.com
Connection: Cache-Control
```
