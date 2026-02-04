<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Problem Details Structure

## Description

When a server expresses an error using the Problem Details media type (`application/problem+json`), the response body SHOULD be a JSON object carrying problem details (see RFC 7807). This rule performs conservative, syntactic checks on such responses: it verifies the response is an error (4xx/5xx) and that `application/problem+json` responses include a non-empty body. Captured bodies are available to rules in memory; the `captures_include_body` setting only controls whether bodies are persisted to the captures file. When body bytes are present, the rule will attempt to parse the body and ensure it is a non-empty JSON object. If body bytes are not present, the rule conservatively flags when a captured or indicated Content-Length of zero is present.

## Specifications

- [RFC 7807 §3.1 — Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc7807.html#section-3.1)

## Rationale

Problem Details responses are intended to carry machine-readable information about an error. An empty response with `application/problem+json` is almost certainly a mistake (servers should include at least `type`/`title`/`detail` or an informative body). Because transaction captures may not include the full body content, this rule conservatively only flags responses where the captured body length or explicit `Content-Length` indicates zero bytes.

## Configuration

Minimal example to enable the rule in your config (add to `config_example.toml`):

```toml
[rules.message_problem_details_structure]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 400 Bad Request
Content-Type: application/problem+json
Content-Length: 123

{"type":"about:blank","title":"Bad Request","detail":"invalid input"}
```

### ❌ Bad

```http
HTTP/1.1 500 Internal Server Error
Content-Type: application/problem+json
Content-Length: 0

```
