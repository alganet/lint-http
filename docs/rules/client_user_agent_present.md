<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client User-Agent Present

## Description

Report a request that carries no `User-Agent` header field. RFC 9110 §10.1.5 makes sending one a `SHOULD`, in each request, and it asks it of a *user agent* — which in that specification is any client program that initiates a request, so a command-line tool or a firmware update script is inside the requirement and not only a browser.

The requirement ends in an exception: *unless specifically configured not to do so*. That condition is a property of the client's configuration, and a request that omits the field on purpose is indistinguishable from one that omits it by oversight, so both are reported. A deployment that suppresses the field deliberately — §17.13 describes what a `User-Agent` can contribute to identifying a specific device — is conforming, and should turn this rule off rather than read the finding as a defect.

Only the header section is examined. A `User-Agent` field line that is present but empty is not reported here: it is a field that fails the field's own grammar, and `message_user_agent_token_valid` owns and reports that.

## Specifications

- [RFC 9110 §10.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5): `A user agent SHOULD send a User-Agent header field in each request unless specifically configured not to do so.` The exception is a fact about the sender's configuration rather than about the request, so a conforming suppression and a plain omission are the same absence here and both are reported
- [RFC 9110 §3.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-3.5): a user agent is any client program that initiates a request — browsers, spiders, command-line tools, appliances, firmware update scripts — so the requirement is not a browser requirement
- [RFC 9110 §17.13](https://www.rfc-editor.org/rfc/rfc9110.html#section-17.13): why a client is configured not to send the field: a `User-Agent` can hold enough detail to identify a specific device, and reducing that fingerprint is a deliberate choice this rule cannot see

## Configuration

```toml
[rules.client_user_agent_present]
enabled = true
severity = "info"
```

## Examples

### ✅ Good a product identifier, with a comment after it

```http
GET /api/data HTTP/1.1
Host: example.com
User-Agent: MyClient/1.0 (Linux; x64)
```

### ✅ Good the value RFC 9110 prints for the field

```http
GET /api/data HTTP/1.1
Host: example.com
User-Agent: CERN-LineMode/2.15 libwww/2.17b3
```

### ❌ Bad no User-Agent field line

```http
GET /api/data HTTP/1.1
Host: example.com
Accept: application/json
```
