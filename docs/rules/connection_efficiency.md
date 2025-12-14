<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Connection Efficiency

## Description
This rule analyzes the ratio of requests per connection to detect inefficient connection usage.

Establishing a TCP connection (and TLS handshake) is expensive. Clients should use persistent connections (`Connection: keep-alive`) to send multiple requests over a single connection. This rule triggers a warning if a client establishes many connections but performs very few requests per connection (e.g., close to 1:1 ratio).

## Specifications
- [RFC 7230 §6.3](https://www.rfc-editor.org/rfc/rfc7230.html#section-6.3): Persistence of connections

## Configuration

This rule is disabled by default. To enable and configure it, add a table under `[rules]` in your TOML config:

```toml
[rules.connection_efficiency]
enabled = true
min_connections = 5
min_reuse_ratio = 1.1
```

- `min_connections` (integer, default: 5): Minimum number of unique connections observed for a client before the rule evaluates efficiency.
- `min_reuse_ratio` (float, default: 1.1): The minimum requests-per-connection ratio considered acceptable. Values below this indicate poor connection reuse.
