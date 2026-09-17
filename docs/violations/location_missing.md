<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# location_missing

A status that asks for Location carries none

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §15.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.2): 301 Moved Permanently: the server SHOULD generate a Location header field containing a preferred URI reference for the new permanent URI
- [RFC 9110 §15.4.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.3): 302 Found: the server SHOULD generate a Location header field containing a URI reference for the different URI
- [RFC 9110 §15.4.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.4): 303 See Other: the status is defined as a redirection to the resource indicated by a URI in the Location header field
- [RFC 9110 §15.4.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.8): 307 Temporary Redirect: the server SHOULD generate a Location header field containing a URI reference for the different URI
- [RFC 9110 §15.4.9](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.9): 308 Permanent Redirect: the server SHOULD generate a Location header field containing a preferred URI reference for the new permanent URI

## Configuration

```toml
[violations.location_missing]
# A status that asks for Location carries none
severity = "warn"
```

## Reported By

- [location_on_redirect_present](../rules/location_on_redirect_present.md)
