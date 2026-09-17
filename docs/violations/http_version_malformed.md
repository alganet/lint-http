<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# http_version_malformed

A protocol version derives from no reading of HTTP-version

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9112 §2.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-2.3): The production, the sentence saying it is case-sensitive, and the sentence saying only an HTTP/1.x message carries it in a start-line

## Configuration

```toml
[violations.http_version_malformed]
# A protocol version derives from no reading of HTTP-version
severity = "warn"
```

## Reported By

- [http_version_syntax](../rules/http_version_syntax.md)
