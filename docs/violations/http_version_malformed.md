<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# http_version_malformed

A protocol version derives from no reading of HTTP-version

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9112 §2.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-2.3): The production, the sentence saying it is case-sensitive, and the sentence saying only an HTTP/1.x message carries it in a start-line

## Configuration

```toml
[violations.http_version_malformed]
# A protocol version derives from no reading of HTTP-version
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [http_version_syntax](../rules/http_version_syntax.md)
