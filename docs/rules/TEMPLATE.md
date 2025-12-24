<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# <Rule Title>

## Description

Short (1–3 paragraphs) description of what the rule checks and why it matters.

## Specifications

- Reference authoritative sources, e.g. `RFC 9110 §5.2` with a canonical link:
  - [RFC 9110 §5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2)
  - Prefer rfc-editor.org or other canonical docs (w3.org, MDN) and include section anchors when relevant.

## Configuration

```toml
[rules.<rule_id>]
enabled = true
severity = "warn"
# add additional keys here if the rule supports configuration
```

## Examples

### ✅ Good

```http
# Minimal request/response that should pass the rule
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
```

### ❌ Bad

```http
# Minimal request/response that should fail the rule
HTTP/1.1 200 OK
Content-Type: application/json
# Missing Cache-Control header
```

---

Notes
- Keep the doc concise and focused; do not include long protocol digressions.
- Use fenced code blocks with language markers (`toml`, `http`).
- Use this file as the canonical structure for new rule docs so tooling and tests can rely on consistent layout.
- Titles should be human-readable (e.g., "Server Cache-Control Present" not "server_cache_control_present").
- RFC references should use modern HTTP specifications (RFC 9110, RFC 9111, RFC 9112) instead of obsoleted ones (RFC 7230-7234).
