<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# origin_agent_cluster_malformed

Origin-Agent-Cluster carries a list where a boolean is due

## Message

Origin-Agent-Cluster must be a single value

## Specifications

- [HTML §7.1.2](https://html.spec.whatwg.org/multipage/browsers.html#origin-keyed-agent-clusters): `Origin-Agent-Cluster` — a structured-header boolean; only the `?1` true value requests an origin-keyed agent cluster

## Configuration

```toml
[violations.origin_agent_cluster_malformed]
# Origin-Agent-Cluster carries a list where a boolean is due
severity = "warn"
```

## Reported By

- [origin_isolated_header_valid](../rules/origin_isolated_header_valid.md)
