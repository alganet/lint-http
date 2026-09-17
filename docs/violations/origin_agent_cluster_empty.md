<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# origin_agent_cluster_empty

Origin-Agent-Cluster is written with no boolean on it

## Message

Origin-Agent-Cluster is written with no value

## Specifications

- [HTML §7.1.2](https://html.spec.whatwg.org/multipage/browsers.html#origin-keyed-agent-clusters): `Origin-Agent-Cluster` — a structured-header boolean; only the `?1` true value requests an origin-keyed agent cluster

## Configuration

```toml
[violations.origin_agent_cluster_empty]
# Origin-Agent-Cluster is written with no boolean on it
severity = "warn"
```

## Reported By

- [origin_isolated_header_valid](../rules/origin_isolated_header_valid.md)
