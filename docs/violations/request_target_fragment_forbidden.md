<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# request_target_fragment_forbidden

A request target carries a fragment identifier

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 3986 §3.5](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.5): Fragment: indicated by a number sign and terminated by the end of the URI; separated from the rest of the URI before a dereference and resolved solely by the user agent

## Configuration

```toml
[violations.request_target_fragment_forbidden]
# A request target carries a fragment identifier
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [request_target_no_fragment](../rules/request_target_no_fragment.md)
