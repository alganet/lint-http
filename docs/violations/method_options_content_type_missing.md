<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# method_options_content_type_missing

An OPTIONS request carries content without saying what it is

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §9.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.7): OPTIONS — the client `MUST` about `Content-Type`, and the `SHOULD` to advertise, which names a class ending "including potential extensions not defined by this specification" rather than a field

## Configuration

```toml
[violations.method_options_content_type_missing]
# An OPTIONS request carries content without saying what it is
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [options_method_capabilities](../rules/options_method_capabilities.md)
