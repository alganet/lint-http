<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Authentication Failure Loop

## Description

Reports a client that keeps presenting credentials one challenge keeps refusing. It could imply a broken client, misconfigured credentials, or a flawed authentication handshake, and the rule declines to choose between the three.

**The sentence behind it states two conditions and both are read.** RFC 9110 §15.5.2: *"If the 401 response contains the same challenge as the prior response, and the user agent has already attempted authentication at least once, then the user agent SHOULD present the enclosed representation to the user"*. So a link in the run is a `401` that **refused an attempt** — the request carried an `Authorization` field — and **handed back the same challenge** as the one in front of the rule. Anything else ends the run: another status, an exchange with no answer, a request that carried no credentials, a different challenge.

**Four is this rule's number and not the catalogue's.** No sentence fixes one — §15.5.2 says *"at least once"* and stops — so the threshold sits with the rule that chose it: four consecutive refusals, which is comfortably past the single retry-and-re-present the section sanctions.

**Presence is the whole of the credentials test.** `Authorization = credentials`, and what is inside the field is `authorization_credentials_valid`'s question; a client that wrote the field attempted authentication however badly, so a value this rule cannot decode still counts as an attempt.

**The challenge is compared as written, byte for byte.** `challenge` folds case in its scheme and its parameter names, but §11.5 makes a `realm` *"a free-form string that can only be compared for equality"* — so folding the value would fold the one part that must not be. What the exactness costs is a server that respells its challenge between two responses, which reads here as a different challenge and is not reported; that is the safe direction for a finding about a client that will not stop, and it is also why a `Digest` challenge with a fresh `nonce` each round is silent, since that client is being handed something new to answer.

**Two 401s carrying no challenge at all do not match each other.** *"Contains the same challenge as the prior response"* is not satisfied by two responses that contain none, and a 401 without the field is its own MUST violation rather than evidence for this one.

**History is scoped to the origin**, which is where the question can be asked and not the protection space itself: §11.5 makes a `realm` in combination with the canonical root URI the protection space, and the challenge comparison above is what narrows an origin's run to one of them.

## Violations

- [status_401_ignored](../violations/status_401_ignored.md) — A client replays credentials a 401 keeps refusing

## Specifications

- [RFC 9110 §15.5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.2): 401 (Unauthorized) — the server generating one MUST send a `WWW-Authenticate` containing at least one challenge applicable to the target resource, and a user agent that has already attempted authentication and gets the same challenge back SHOULD show the representation to the user

## Configuration

```toml
[rules.authentication_failure_loop]
enabled = true
```

## Examples

### ✅ Good — the challenge answered once, and accepted

```http
> GET /protected HTTP/1.1
> Host: example.com

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Basic realm="Access"

> GET /protected HTTP/1.1
> Host: example.com
> Authorization: Basic ...

< 200 OK HTTP/1.1
```

### ✅ Good — a client that has attempted nothing

```http
> GET /protected HTTP/1.1
> Host: example.com

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Basic realm="Access"

> GET /protected HTTP/1.1
> Host: example.com

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Basic realm="Access"

> GET /protected HTTP/1.1
> Host: example.com

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Basic realm="Access"

> GET /protected HTTP/1.1
> Host: example.com

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Basic realm="Access"

# no request carried credentials, so nothing has been replayed: this is the
# first four rounds of an authentication that has not started
```

### ✅ Good — a different challenge each time

```http
> GET /a HTTP/1.1
> Host: example.com
> Authorization: Basic ...

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Basic realm="one"

> GET /b HTTP/1.1
> Host: example.com
> Authorization: Basic ...

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Basic realm="two"

> GET /c HTTP/1.1
> Host: example.com
> Authorization: Basic ...

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Basic realm="three"

> GET /d HTTP/1.1
> Host: example.com
> Authorization: Basic ...

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Basic realm="four"

# four protection spaces, each answered for the first time
```

### ❌ Bad — the same credential refused by the same challenge, four times

```http
> GET /api/v1/data HTTP/1.1
> Host: example.com
> Authorization: Bearer INVALID

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Bearer realm="API"

> GET /api/v1/data HTTP/1.1
> Host: example.com
> Authorization: Bearer INVALID

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Bearer realm="API"

> GET /api/v1/data HTTP/1.1
> Host: example.com
> Authorization: Bearer INVALID

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Bearer realm="API"

> GET /api/v1/data HTTP/1.1
> Host: example.com
> Authorization: Bearer INVALID

< 401 Unauthorized HTTP/1.1
< WWW-Authenticate: Bearer realm="API"
```
