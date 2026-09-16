<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Permissions Policy Directives Valid

## Description

Reports a `Permissions-Policy` response header carrying something a browser will not enforce. Neither specification calls any of this "invalid" — both define **ignore** semantics — so the finding is always that the server wrote a policy that will not take effect, at one of two scopes.

**The whole field, or one directive.** A Structured Fields parse failure discards everything: RFC 9651 §4.2, "If parsing fails, either the entire field value MUST be ignored … or alternatively the complete HTTP message MUST be treated as malformed", and field specifications are explicitly not allowed to loosen that. So one uppercase letter in a member name costs every directive in the header. A value that parses but is not an allowlist costs only its own directive — §5.2, "Member Values of any other form will cause the entire Dictionary Member to be ignored". The messages say which, and so does their number: a parse failure is reported alone because nothing else in the field survived it, while every directive that parsed and will be ignored is reported beside the others like it. A member with no `=` at all belongs to the second group — §4.2.2 reads a bare key as the Boolean true, which parses, so the cost is that one directive.

**Member names are SF keys, not §5.1 feature-identifiers.** The Permissions Policy spec serializes a policy directive twice: §5.1 for the HTML `allow` attribute, where `feature-identifier = 1*( ALPHA / DIGIT / "-" )`, and §5.2 for this header, where the value is an `sf-dictionary`. This rule reads the header, so a member name is an SF key: lowercase only, beginning with a letter or `*`, and permitting `_`, `.` and `*`. It used to apply §5.1's production here, which accepted `Geolocation=(self)` and rejected `a_b=(self)`.

**Allowlist values are a closed list.** §5.2 permits a String, the Token `*`, the Token `self`, or an Inner List of those — nothing else. Tokens keep their case, so `SELF` is not `self`. Items *inside* an inner list are deliberately not policed: §5.2 says unknown ones are ignored and the member is processed without them, which costs one origin rather than the directive.

**Field lines are joined before parsing**, as RFC 9651 §4.2 requires — a Dictionary may have its members spread across lines, so judging a line on its own describes a message nobody sent. A member repeated across the joined value loses all but its last allowlist (§4.2.2), which is not an error and not visible in the header, so it is reported.

**Unknown feature names are not reported.** §5.2 says a member naming no supported feature is ignored, and RFC 9651 §3.2 says recipients MUST ignore members with unknown keys — so a name this rule does not recognise is not a defect, and there is no allowlist of features here.

## Specifications

- [Permissions Policy](https://w3c.github.io/webappsec-permissions-policy/#structured-header-serialization): §5.2 Structured header serialization — the production this subject answers for. Not §5.1, which is the HTML attribute and has a feature-identifier grammar of its own
- [RFC 9651 §3.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-3.2): Dictionaries — keys cannot contain uppercase, unknown members are ignored by recipients, members may be spread across field lines, and an empty Dictionary is spelled by leaving the field out
- [RFC 9651 §4.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2): Parsing — the algorithm a recipient runs over a joined field value, the `field_type` it is given, the ASCII conversion it does before choosing one, and the two answers it offers when parsing fails
- [RFC 9651 §4.2.1.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.1.2): Parsing an Inner List — space-separated Items between a `(` and a `)`, and the failure when the closing parenthesis never arrives
- [RFC 9651 §4.2.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.2): Parsing a Dictionary: a member is a key and, optionally, an `=` and a value — a bare key carries the Boolean true rather than being a member without one — and the loop fails on a comma with nothing after it
- [RFC 9651 §4.2.3.1](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.3.1): Parsing a Bare Item — seven types chosen by the value's first character, and a single step for a value that is none of them
- [RFC 9651 §4.2.3.3](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.3.3): Parsing a Key: a `key` opens with `lcalpha` or `*` and continues with `lcalpha`, DIGIT, `_`, `-`, `.` or `*` — the production every Dictionary member name and every parameter name is written in, and the one an uppercase letter fails

## Configuration

```toml
[rules.permissions_policy_directives_valid]
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Permissions-Policy: geolocation=(self "https://example.com"), fullscreen=(), payment=("https://pay.example");report-to="endpoint"
```

### ✅ Good (underscores and dots are ordinary SF key characters)

```http
HTTP/1.1 200 OK
Permissions-Policy: ch-ua_full.version=*
```

### ❌ Bad (uppercase in a member name discards the whole field)

```http
HTTP/1.1 200 OK
Permissions-Policy: Geolocation=(self), camera=()
```

### ❌ Bad (a bare token is not an allowlist)

```http
HTTP/1.1 200 OK
Permissions-Policy: geolocation=SELF
```

### ❌ Bad (a bare member name has no allowlist at all)

```http
HTTP/1.1 200 OK
Permissions-Policy: geolocation
```

### ❌ Bad (report-to must be a String)

```http
HTTP/1.1 200 OK
Permissions-Policy: geolocation=(self);report-to=endpoint
```
