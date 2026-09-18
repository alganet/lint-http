<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Origin Isolated Header Valid

## Description

Checks the `Origin-Agent-Cluster` response header, whose value is one structured-field boolean. `?1` requests that documents from the origin be placed in an origin-keyed agent cluster. A value that is not a boolean at all — a comma-separated list, a bare token such as `unsafe-none`, or nothing — breaks the grammar and leaves a recipient with a field it cannot read. `?0` does not: it is the field's other value, well-formed, and it asks for what an absent header already gives, which the specification ignores and this rule reports as advice. The header must also appear on one field line only.

(The `Origin-Isolation` name used by the original proposal never shipped; the header that browsers actually honour is `Origin-Agent-Cluster`.)

## Violations

- [field_line_duplicated](../violations/field_line_duplicated.md) — A field is written on more lines than its definition allows
- [origin_agent_cluster_empty](../violations/origin_agent_cluster_empty.md) — Origin-Agent-Cluster is written with no boolean on it
- [origin_agent_cluster_invalid](../violations/origin_agent_cluster_invalid.md) — Origin-Agent-Cluster states the boolean's false value
- [origin_agent_cluster_malformed](../violations/origin_agent_cluster_malformed.md) — Origin-Agent-Cluster carries something that is not a boolean

## Specifications

- [HTML §7.1.2](https://html.spec.whatwg.org/multipage/browsers.html#origin-keyed-agent-clusters): `Origin-Agent-Cluster` — a structured-header boolean; only the `?1` true value requests an origin-keyed agent cluster
- [RFC 9651 §3](https://www.rfc-editor.org/rfc/rfc9651.html#section-3): Structured Headers boolean values (§3–§4)
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list

## Configuration

```toml
[rules.origin_isolated_header_valid]
enabled = true
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Origin-Agent-Cluster: ?1
```

### ❌ Bad (the boolean, written false)

```http
HTTP/1.1 200 OK
Origin-Agent-Cluster: ?0
```

### ❌ Bad (a list where a boolean is due)

```http
HTTP/1.1 200 OK
Origin-Agent-Cluster: ?1, ?1
```

### ❌ Bad (a token, which no boolean admits)

```http
HTTP/1.1 200 OK
Origin-Agent-Cluster: unsafe-none
```
