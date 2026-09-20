<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Digest Challenge Valid

## Description

Reports a `Digest` challenge that writes one of its parameters in the syntax RFC 7616 §3.3 refuses for it. The section closes with two sentences: "For historical reasons, a sender MUST only generate the quoted string syntax values for the following parameters: realm, domain, nonce, opaque, and qop", and "For historical reasons, a sender MUST NOT generate the quoted string syntax values for the following parameters: stale and algorithm".

**The lists are the challenge's, not the credential's.** §3.4 writes the same pair of sentences about what a client sends back, over a different set of names — and `qop` is on the opposite side of each: a server must quote it, a client must not. `digest_auth_valid` enforces §3.4 over `Authorization` and `Proxy-Authorization`; this rule enforces §3.3 over `WWW-Authenticate` and `Proxy-Authenticate`, and neither answers for the other.

**Both spellings derive from the grammar**, which is why this is a rule and not a parse error: §11.2's `auth-param` offers `token / quoted-string` for every value, and RFC 7616 removes the choice per parameter for reasons it states outright. What it costs a sender is that recipients of these parameters were deployed against one spelling each.

**Only the quoting is read here.** §3.3 also says `charset`'s only allowed value is "UTF-8", that `userhash` is "true" or "false", and that `domain` is a space-separated list of URIs. None of that is checked by this rule, and its silence about them is not a claim that they hold.

## Violations

- [digest_challenge_quoting_invalid](../violations/digest_challenge_quoting_invalid.md) — A Digest challenge parameter is written in the syntax its definition refuses

## Specifications

- [RFC 7616 §3.3](https://www.rfc-editor.org/rfc/rfc7616.html#section-3.3): The WWW-Authenticate Response Header Field — the parameters a Digest challenge may carry, and the two lists saying which of them must and must not be written as a quoted-string

## Configuration

```toml
[rules.digest_challenge_valid]
enabled = true
```

## Examples

### ✅ Good (every parameter on the side its own list puts it)

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="users", nonce="abc", qop="auth", stale=false, algorithm=SHA-256
```

### ❌ Bad (a nonce the section admits only as a quoted-string)

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="users", nonce=abc
```

### ❌ Bad (qop is quoted in a challenge and unquoted in credentials)

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="users", nonce="abc", qop=auth
```

### ❌ Bad (and the list pointing the other way)

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Digest realm="users", nonce="abc", stale="true"
```
