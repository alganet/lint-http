<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# user_agent_missing

A request does not say what sent it

## Message

Request missing User-Agent header

## Specifications

- [RFC 9110 §10.1.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5): `A user agent SHOULD send a User-Agent header field in each request unless specifically configured not to do so.` The exception is a fact about the sender's configuration rather than about the request, so a conforming suppression and a plain omission are the same absence here and both are reported

## Configuration

```toml
[violations.user_agent_missing]
# A request does not say what sent it
severity = "info"
```

## Reported By

- [user_agent_present](../rules/user_agent_present.md)
