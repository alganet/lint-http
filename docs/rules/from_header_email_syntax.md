<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# From Header Email Syntax

## Description

This rule measures the `From` request header against the one production RFC 9110 §10.1.2 gives it: `From = mailbox`, imported by reference from RFC 5322 §3.4. It is a single mailbox and not a list — `mailbox-list` is defined two lines below it in the same section and is not what the field imports — so a comma outside every `quoted-string`, `comment` and `angle-addr` is reported, and so is a second `From` field line, which a recipient recombines into exactly that comma-separated shape (RFC 9110 §5.3). The value is read one `char` per octet, so an octet above %x7E is named at the character class that excludes it rather than folded into a claim about UTF-8; RFC 5322 writes `atext`, `qtext`, `ctext` and `dtext` as ranges that all stop at %x7E. Parenthesised comments and folding whitespace are part of the grammar and are accepted wherever `CFWS` may appear — `alice@example.com (Alice)` is one conforming mailbox. Only §3's grammar is accepted: §4's obsolete alternatives must be accepted by a receiver and must not be generated, and this rule reports on senders. One finding is weaker than the rest and says so in its own text: a `dot-atom` domain outside RFC 1035 §2.3.1's preferred name syntax (an `_`, a label opening or closing on `-`, a label over 63 characters) is a conforming `dot-atom` and is reported as advice. §10.1.2's three other requirements are declined and none of them is about syntax: the user agent SHOULD NOT that turns on whether the user configured the field, the SHOULD on a *robotic* user agent, and the SHOULD NOT on a server *using* the field for access control are each about a party or an intent no captured message states. RFC 5322's own advice to its generators — prefer a `dot-atom` local-part over a quoted one (§3.4.1), keep comments out of address fields (§3.4) — is likewise not enforced: RFC 9110 imports a production, not the document's style guidance.

## Violations

- [domain_label_character_forbidden](../violations/domain_label_character_forbidden.md) — Domain label holds a character outside letters, digits and hyphen
- [domain_label_edge_hyphen_forbidden](../violations/domain_label_edge_hyphen_forbidden.md) — Domain label starts or ends with a hyphen
- [domain_label_empty](../violations/domain_label_empty.md) — Domain name has an empty label
- [domain_label_length_invalid](../violations/domain_label_length_invalid.md) — Domain label is longer than 63 characters
- [domain_name_length_invalid](../violations/domain_name_length_invalid.md) — Domain name is longer than 255 octets
- [field_line_duplicated](../violations/field_line_duplicated.md) — A field is written on more lines than its definition allows
- [mailbox_angle_addr_missing](../violations/mailbox_angle_addr_missing.md) — Mailbox has no angle-addr where the name-addr wants one
- [mailbox_angle_addr_terminator_missing](../violations/mailbox_angle_addr_terminator_missing.md) — Mailbox angle-addr is never closed
- [mailbox_at_sign_missing](../violations/mailbox_at_sign_missing.md) — Mailbox has no at-sign
- [mailbox_atom_character_forbidden](../violations/mailbox_atom_character_forbidden.md) — Mailbox atom holds a character outside atext
- [mailbox_atom_empty](../violations/mailbox_atom_empty.md) — Mailbox atom is empty beside a dot
- [mailbox_comment_character_forbidden](../violations/mailbox_comment_character_forbidden.md) — Mailbox comment holds a character outside ctext
- [mailbox_comment_terminator_missing](../violations/mailbox_comment_terminator_missing.md) — Mailbox comment is never closed
- [mailbox_display_name_word_missing](../violations/mailbox_display_name_word_missing.md) — Mailbox display-name holds no word
- [mailbox_domain_literal_character_forbidden](../violations/mailbox_domain_literal_character_forbidden.md) — Mailbox domain-literal holds a character outside dtext
- [mailbox_domain_literal_terminator_missing](../violations/mailbox_domain_literal_terminator_missing.md) — Mailbox domain-literal is never closed
- [mailbox_domain_missing](../violations/mailbox_domain_missing.md) — Mailbox has no domain
- [mailbox_empty](../violations/mailbox_empty.md) — Mailbox field is present with an empty value
- [mailbox_list_separator_forbidden](../violations/mailbox_list_separator_forbidden.md) — Mailbox holds a comma where one address goes
- [mailbox_local_part_missing](../violations/mailbox_local_part_missing.md) — Mailbox has no local-part
- [mailbox_quoted_pair_malformed](../violations/mailbox_quoted_pair_malformed.md) — Mailbox escape is not a quoted-pair
- [mailbox_quoted_string_character_forbidden](../violations/mailbox_quoted_string_character_forbidden.md) — Mailbox quoted-string holds a character outside qtext
- [mailbox_quoted_string_terminator_missing](../violations/mailbox_quoted_string_terminator_missing.md) — Mailbox quoted-string is never closed
- [mailbox_trailing_character_forbidden](../violations/mailbox_trailing_character_forbidden.md) — Mailbox is followed by something else

## Specifications

- [RFC 9110 §10.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.2): `From = mailbox` — one address, imported by reference from RFC 5322 §3.4; the section's three other requirements are about parties and intents a capture does not state
- [RFC 9110 §10.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1): Request context fields — the sentence behind the scope, since there is no response half of this field
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list
- [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5): Singleton fields, and the `OWS` a parser must exclude before evaluating a field value
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The MUST NOT that makes a value outside the field's ABNF a finding
- [RFC 5322 §3.2.1](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.1): `quoted-pair` — the backslash and the one `VCHAR` or `WSP` it owes
- [RFC 5322 §3.2.2](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.2): `CFWS`, `comment` and `ctext` — the comment names itself, so what it holds is balanced and its character class stops at %x7E
- [RFC 5322 §3.2.3](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.3): `atext`, `atom` and `dot-atom-text` — the printable US-ASCII an atom is made of, and the floor a dot may not leave empty
- [RFC 5322 §3.2.4](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.4): `quoted-string` and `qtext` — the quoted alternative, and the class it admits between the two DQUOTEs
- [RFC 5322 §3.2.5](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.5): `phrase = 1*word` — a display-name holds at least one atom or quoted-string, and `obs-phrase`'s bare `.` is not one
- [RFC 5322 §3.4](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.4): `mailbox = name-addr / addr-spec`, `angle-addr` beside it, and `mailbox-list` — the neighbouring production a top-level comma derives from
- [RFC 5322 §3.4.1](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.4.1): `addr-spec = local-part "@" domain`, and the `domain-literal` alternative with the `dtext` inside it
- [RFC 5322 §4](https://www.rfc-editor.org/rfc/rfc5322.html#section-4): Obsolete syntax: MUST NOT be generated, MUST be accepted by a receiver — this rule reports on the generator
- [RFC 1035 §2.3.1](https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.1): Preferred name syntax — labels start with a letter, end with a letter or digit, hold only letters, digits and hyphen, and run to 63 characters
- [RFC 1035 §2.3.4](https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4): Size limits — a name is 255 octets or less
- [RFC 1123 §2.1](https://www.rfc-editor.org/rfc/rfc1123.html): Relaxes RFC 1035's first-character rule to a letter or a digit

## Configuration

```toml
[rules.from_header_email_syntax]
enabled = true
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
