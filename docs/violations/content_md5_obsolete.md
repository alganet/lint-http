<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_md5_obsolete

Content-MD5 is a field HTTP removed

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7231 §Appendix B](https://www.rfc-editor.org/rfc/rfc7231.html#appendix-B): Where `Content-MD5` was removed from HTTP — RFC 9530 does not mention the field at all

## Configuration

```toml
[violations.content_md5_obsolete]
# Content-MD5 is a field HTTP removed
severity = "warn"
```

## Reported By

- [digest_header_syntax](../rules/digest_header_syntax.md)
