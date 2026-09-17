<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sec_fetch_value_malformed

A Sec-Fetch-* value holds a character no token admits

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Configuration

```toml
[violations.sec_fetch_value_malformed]
# A Sec-Fetch-* value holds a character no token admits
severity = "warn"
```

## Reported By

- [sec_fetch_dest_value_valid](../rules/sec_fetch_dest_value_valid.md)
- [sec_fetch_mode_value_valid](../rules/sec_fetch_mode_value_valid.md)
- [sec_fetch_site_value_valid](../rules/sec_fetch_site_value_valid.md)
