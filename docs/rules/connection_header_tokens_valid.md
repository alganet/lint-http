<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Connection Header Tokens Valid

## Description

Validates the `Connection` header field's own value — the list of control options a sender declares for the current connection.

The field is `Connection = [ connection-option *( OWS "," OWS connection-option ) ]` (RFC 9110 §A), and a `connection-option` is a `token` (§7.6.1). So every member must be `1*tchar`: `Connection: a/b` names no option, because `/` is one of the delimiters a token excludes (§5.6.2). No member may be empty — `Connection: keep-alive,,close` is a list a sender MUST NOT generate (§5.6.1.1) — while an **empty value** is a different thing and is not reported: the production's outer brackets make a list of no options a list, so `Connection:` declares nothing rather than declaring badly.

Where the field appears on several lines in one section, the lines are one value (§5.2), so an empty member written at a line boundary is an empty member. A value carrying an octet outside US-ASCII is measured rather than skipped; `obs-text` is an octet `field-content` admits and `token` does not, so the member is reported for not being a token, which is what is wrong with it.

One name is reported as a name. RFC 9110 §7.6.1 says a sender MUST NOT send a connection option corresponding to a field that is intended for all recipients of the content, and gives `Cache-Control` as a field that is never appropriate as one. **That example is the whole of what this rule decides about that sentence.** Whether some other field is intended for all recipients of the content is a property of that field's definition, not of anything the message carries, so a rule reading a `Connection` value cannot answer it in general — and a name's absence from this rule's findings is therefore not a verdict that listing it is permitted. Connection options are case-insensitive, and the comparison is too.

An option is not required to name a field that is present: §7.6.1 says a connection-specific field might not be needed when no parameter is associated with an option, and `close` names no field at all. The converse — a connection-specific field arriving without an option naming it — is the direction §7.6.1 does state a requirement in, and it is not asked here: it is asked of `Upgrade` by `upgrade_and_connection_consistent`, of `TE` by `te_header_valid`, and of `Keep-Alive` by `keep_alive_header_valid`, each with the sentence its own field's section writes — the last of them out of RFC 2068 §19.7.1.1, which is the section §7.6.1 itself names for that field. **Those are the three of §7.6.1's five connection-specific fields that have such a sentence, and the silence about the other two is a decision rather than an omission.** Across RFC 9110 and RFC 9112 the *a sender of X MUST also send an X connection option* form is written for `Upgrade` (§7.8) and `TE` (§10.1.4, restated in RFC 9112 §7.4) and for nothing else; `Keep-Alive`'s comes out of RFC 2068 §19.7.1.1. Neither `Transfer-Encoding` nor `Proxy-Connection` is named by any such sentence.

What is *not* claimed here is that they fall outside §7.6.1's general MUST, which names no field at all: it asks the option of any field *used to supply control information for or about the current connection*. **Whether a given field is one of those is a property of that field's definition, not of anything the message carries** — the same reason this rule cannot decide the converse sentence, one paragraph up. For `Transfer-Encoding` no document answers it, so the antecedent is not decidable from a capture and the question is left open rather than guessed in either direction. Membership in §7.6.1's bullet list does not settle it either: that list belongs to the *removal* sentence, which asks intermediaries to strip these fields *whether or not they appear as a connection-option* — so it is a list of fields to remove, and being on it is neither a source of the option requirement nor an exemption from it. `Proxy-Connection` has a sentence of its own instead: RFC 9112 Appendix C.2.2 encourages clients not to send it at all, which `proxy_connection_discouraged` reports as the advice it is.

Scope: this rule reads header sections — a request's and a response's — and measures the value whatever protocol version carried it. Some versions of HTTP do not allow the field at all (§7.6.1); `no_connection_specific_fields` is the rule that reports its presence over HTTP/2 and HTTP/3. Whether `Connection` may appear in a *trailer* section is §6.5.1's question and `trailer_fields_valid`'s. Whether an `Upgrade` field is backed by an `upgrade` option is `upgrade_and_connection_consistent`'s.

## Specifications

- [RFC 9110 §7.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.1): The field itself: its grammar, the case-insensitivity of its options, the note that an option need not correspond to a field present in the message, and the MUST NOT this rule implements for the one field the section names
- [RFC 9110 §A](https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A): The collected grammar, where the list construct is expanded for a sender — the form that shows both that the whole value may be empty and that a member may not
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The sender's half of the list construct. The recipient's half (§5.6.1.2, ignore empty elements) is a different party's requirement, which is why the shared list reader is not used here
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): `token` and `tchar`: what a connection-option is made of, and the delimiters it excludes
- [RFC 9110 §5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2): Several `Connection` lines in one field section are one field value, so the members are counted after the lines are joined

## Configuration

```toml
[rules.connection_header_tokens_valid]
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
