<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# <Rule Title or rule_id>

## Description

Short (1–3 paragraphs) description of what the rule checks and why it matters.

## Specifications

- Reference authoritative sources, e.g. `RFC 7234 §5.2` with a canonical link:
  - https://www.rfc-editor.org/rfc/rfc7234.html#section-5.2
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
