<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# sec_fetch_storage_access_value_invalid

Sec-Fetch-Storage-Access names no storage access status the document defines

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [Storage Access Headers §4.1](https://privacycg.github.io/storage-access-headers/#sec-fetch-storage-access-header): Storage Access Headers (Privacy CG) — `Sec-Fetch-Storage-Access`: an sf-token whose valid values are the three storage access statuses

## Configuration

```toml
[violations.sec_fetch_storage_access_value_invalid]
# Sec-Fetch-Storage-Access names no storage access status the document defines
severity = "warn"
```

## Reported By

- [sec_fetch_storage_access_value_valid](../rules/sec_fetch_storage_access_value_valid.md)
