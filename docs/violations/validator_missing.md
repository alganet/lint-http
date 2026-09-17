<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# validator_missing

A response gives a later request nothing to validate against

## Message

Response 200 without ETag or Last-Modified validator

## Specifications

- [RFC 9110 §8.8.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2.1): Generation: an origin server SHOULD send Last-Modified for any selected representation whose last modification date can be reasonably and consistently determined
- [RFC 9110 §8.8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3.1): Generation: an origin server SHOULD send an ETag for any selected representation for which detection of changes can be reasonably and consistently determined

## Configuration

```toml
[violations.validator_missing]
# A response gives a later request nothing to validate against
severity = "info"
```

## Reported By

- [etag_or_last_modified_present](../rules/etag_or_last_modified_present.md)
