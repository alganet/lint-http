<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message From Header Email Syntax

## Description

This rule measures the `From` request header against the one production RFC 9110 §10.1.2 gives it: `From = mailbox`, imported by reference from RFC 5322 §3.4. It is a single mailbox and not a list — `mailbox-list` is defined two lines below it in the same section and is not what the field imports — so a comma outside every `quoted-string`, `comment` and `angle-addr` is reported, and so is a second `From` field line, which a recipient recombines into exactly that comma-separated shape (RFC 9110 §5.3). The value is read one `char` per octet, so an octet above %x7E is named at the character class that excludes it rather than folded into a claim about UTF-8; RFC 5322 writes `atext`, `qtext`, `ctext` and `dtext` as ranges that all stop at %x7E. Parenthesised comments and folding whitespace are part of the grammar and are accepted wherever `CFWS` may appear — `alice@example.com (Alice)` is one conforming mailbox. Only §3's grammar is accepted: §4's obsolete alternatives must be accepted by a receiver and must not be generated, and this rule reports on senders. One finding is weaker than the rest and says so in its own text: a `dot-atom` domain outside RFC 1035 §2.3.1's preferred name syntax (an `_`, a label opening or closing on `-`, a label over 63 characters) is a conforming `dot-atom` and is reported as advice. §10.1.2's three other requirements are declined and none of them is about syntax: the user agent SHOULD NOT that turns on whether the user configured the field, the SHOULD on a *robotic* user agent, and the SHOULD NOT on a server *using* the field for access control are each about a party or an intent no captured message states. RFC 5322's own advice to its generators — prefer a `dot-atom` local-part over a quoted one (§3.4.1), keep comments out of address fields (§3.4) — is likewise not enforced: RFC 9110 imports a production, not the document's style guidance.

## Specifications

- [RFC 9110 §10.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.2): `From = mailbox` — one address, imported by reference from RFC 5322 §3.4; the section's three other requirements are about parties and intents a capture does not state
- [RFC 9110 §10.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1): Request context fields — the sentence behind the scope, since there is no response half of this field
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): A sender MUST NOT write a second field line for a field whose value is not a comma-separated list
- [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5): Singleton fields, and the `OWS` a parser must exclude before evaluating a field value
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The MUST NOT that makes a value outside the field's ABNF a finding
- [RFC 5322 §3.4](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.4): `mailbox = name-addr / addr-spec`, and `mailbox-list` beside it — the production this field does *not* import
- [RFC 5322 §3.4.1](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.4.1): `addr-spec = local-part "@" domain`, `domain-literal`, and the sentence handing a `dot-atom` domain to the host-name documents
- [RFC 5322 §3.2.2](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.2): `CFWS` — folding whitespace and nested parenthesised comments, admitted around nearly every token of a mailbox
- [RFC 5322 §3.2.3](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.3): `atext`, `atom` and `dot-atom-text` — the `1*atext` floors either side of every dot
- [RFC 5322 §3.2.4](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.4): `quoted-string` and `qtext`, the alternative a local-part or a display-name word may take
- [RFC 5322 §4](https://www.rfc-editor.org/rfc/rfc5322.html#section-4): Obsolete syntax: MUST NOT be generated, MUST be accepted by a receiver — this rule reports on the generator
- [RFC 1035 §2.3.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.1): Preferred name syntax for the `dot-atom` form of a domain — advisory, and the one finding here that is reported as advice
- [RFC 1123 §2.1](https://www.rfc-editor.org/rfc/rfc1123.html): Relaxes RFC 1035's first-character rule to a letter or a digit

## Configuration

```toml
[rules.message_from_header_email_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (the section's own example)

```http
GET / HTTP/1.1
From: spider-admin@example.org
```

### ✅ Good (display-name and angle-addr)

```http
GET / HTTP/1.1
From: Alice <alice@example.com>
```

### ✅ Good (a comma inside a quoted display-name is data)

```http
GET / HTTP/1.1
From: "Doe, John" <john@example.com>
```

### ✅ Good (a parenthesized comment is part of the grammar)

```http
GET / HTTP/1.1
From: alice@example.com (Alice)
```

### ✅ Good (domain-literal)

```http
GET / HTTP/1.1
From: alice@[192.0.2.1]
```

### ❌ Bad (two addresses — the field holds one mailbox, not a mailbox-list)

```http
GET / HTTP/1.1
From: Alice <alice@example.com>, bob@example.org
```

### ❌ Bad (two field lines, which a recipient recombines with a comma)

```http
GET / HTTP/1.1
From: alice@example.com
From: bob@example.org
```

### ❌ Bad (no at-sign)

```http
GET / HTTP/1.1
From: not-an-email
```

### ❌ Bad (empty domain)

```http
GET / HTTP/1.1
From: alice@
```

### ❌ Bad (unbalanced angle-brackets)

```http
GET / HTTP/1.1
From: Alice <alice@example.com
```

### ❌ Bad (obs-phrase — a bare dot in a display-name)

```http
GET / HTTP/1.1
From: John Q. Public <jqp@example.com>
```

### ❌ Bad (a dot-atom domain outside the preferred name syntax)

```http
GET / HTTP/1.1
From: alice@my_host.example
```
