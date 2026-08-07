<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Extension Headers Registered

## Description

Reports field names this deployment has not listed in the rule's `allowed` array. All four field sections a transaction can carry are walked — the request and response header sections, and their trailer sections when the message framing carried one — and names are compared case-insensitively, which is what RFC 9110 §5.1 says a field name is.

**The `allowed` array is the rule's only authority.** It does not consult the IANA HTTP Field Name Registry: a permanently registered field is reported exactly like a typo when the array omits it, and registering a name with IANA changes nothing about what this rule says. Neither is a finding a protocol error. RFC 9110 §5.1 asks only that field names "ought to be" registered — weaker than SHOULD — and the same paragraph requires a proxy to forward unrecognized header fields and tells other recipients they SHOULD ignore them. A finding means "this deployment did not expect this field", which is worth a look for typos, forgotten debug headers and injected fields, and is not a claim that the sender did anything wrong.

Because the array has to name every field the deployment sees, no useful list is deployment-independent and `config_example.toml` ships the rule disabled with an illustrative one. For a private field prefer a short name scoped to its use and no `X-` prefix: RFC 9110 §16.3.2.1 says field names ought not be prefixed with `X-`.

## Specifications

- [RFC 9110 §5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1): Field Names (case-insensitive, and registration is an "ought to"; the same paragraph makes a proxy forward what it does not recognize)
- [RFC 9110 §6.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5): Trailer Fields (a trailer field name is a field name, so the array reaches it)
- [RFC 9110 §16.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-16.3.1): Field Name Registry (what registration is; this rule does not consult it)
- [RFC 9110 §16.3.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-16.3.2.1): Considerations for New Field Names (no "X-" prefix)
- [IANA HTTP Field Name Registry](https://www.iana.org/assignments/http-fields/http-fields.xhtml): The registry § 5.1 points at, for deciding what belongs in the array

## Configuration

```toml
[rules.message_extension_headers_registered]
# The 'allowed' array is this rule's only authority: it is not the IANA field
# name registry, so every field name the deployment expects has to be listed
# here, including the ones RFC 9110 itself defines. No such list is
# deployment-independent, so the example below is an illustration and the rule
# ships disabled -- turned on against this array it would report ordinary
# traffic, since Date, Content-Length and Connection are not in it either.
# Name a private field for its use and without an "X-" prefix (RFC 9110
# 16.3.2.1).
enabled = false
severity = "warn"
allowed = ["host", "user-agent", "accept", "content-type", "acme-request-id"]
```

## Examples

### ✅ Good

```http
Host: example.com
Accept: text/plain
Acme-Request-Id: 7c1f2b
```

### ❌ Bad A typo is a field name of its own

```http
Host: example.com
Acme-Request-Idd: 7c1f2b
```

### ❌ Bad Registered with IANA and still reported: the array does not name it

```http
Host: example.com
Content-Language: en
```

### ❌ Bad Trailer section, walked on the same terms

```http
Acme-Checksum: 9f2a
```
