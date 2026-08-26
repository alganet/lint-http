<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Origin Isolated Header Valid

## Description

Checks the `Origin-Agent-Cluster` response header and ensures it uses the structured-header boolean value `?1` to request an origin-keyed agent cluster. The header must be a single value and must not contain comma-separated lists or multiple header fields. `?1` requests that documents from the origin be placed in an origin-keyed agent cluster; the specification ignores any other value, but this rule reports it because a non-`?1` value is almost always a server misconfiguration.

(The `Origin-Isolation` name used by the original proposal never shipped; the header that browsers actually honour is `Origin-Agent-Cluster`.)

## Specifications

- [HTML §7.1.2](https://html.spec.whatwg.org/multipage/browsers.html#origin-keyed-agent-clusters): `Origin-Agent-Cluster` — a structured-header boolean; only the `?1` true value requests an origin-keyed agent cluster
- [RFC 9651 §3](https://www.rfc-editor.org/rfc/rfc9651.html#section-3): Structured Headers boolean values (§3–§4)

## Configuration

```toml
[rules.origin_isolated_header_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Origin-Agent-Cluster: ?1
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Origin-Agent-Cluster: ?0
```

```http
HTTP/1.1 200 OK
Origin-Agent-Cluster: ?1, ?1
```

```http
HTTP/1.1 200 OK
Origin-Agent-Cluster: unsafe-none
```
