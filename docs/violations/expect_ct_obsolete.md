<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# expect_ct_obsolete

A response asks for Certificate Transparency in a field no browser reads

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [MDN Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Expect-CT): Expect-CT — marked Deprecated, and the page that says why: Chromium was the only engine that implemented the header and removed it in version 107 because it now enforces Certificate Transparency by default, while the certificates that predated universal SCT support expired in June 2021, leaving nothing for the check to catch
- [RFC 9163 §1](https://www.rfc-editor.org/rfc/rfc9163.html#section-1): Expect-CT: the response header by which a host declares that it expects Signed Certificate Timestamps in subsequent TLS connections — the definition this catalogue reads the field's presence against, and the reason a finding names a live document rather than only a third party's account of it

## Configuration

```toml
[violations.expect_ct_obsolete]
# A response asks for Certificate Transparency in a field no browser reads
severity = "info"
```

## Reported By

- [expect_ct_field_obsolete](../rules/expect_ct_field_obsolete.md)
