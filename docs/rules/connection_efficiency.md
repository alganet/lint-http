<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Connection Efficiency

## Description
This rule analyzes the ratio of requests per connection to detect inefficient connection usage.

Establishing a TCP connection (and TLS handshake) is expensive. Clients should use persistent connections (`Connection: keep-alive`) to send multiple requests over a single connection. This rule triggers a warning if a client establishes many connections but performs very few requests per connection (e.g., close to 1:1 ratio).

## Specifications
- [RFC 7230, Section 6.3: Persistence](https://tools.ietf.org/html/rfc7230#section-6.3)

## Examples

### ✅ Good Behavior
- Client opens 1 connection.
- Client sends 50 requests over that single connection.
- Efficiency: 50 requests / 1 connection = 50.0.

### ❌ Bad Behavior
- Client opens 50 separate connections.
- Client sends 1 request over each connection.
- Efficiency: 50 requests / 50 connections = 1.0.

**Note:** This rule typically triggers after a minimum threshold of connections (e.g., > 5) to avoid false positives during initial startup.
