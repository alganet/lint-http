<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# server_clear_site_data

**Severity**: warn

## Description

This rule checks that logout/signout endpoints include the `Clear-Site-Data` header to properly clear client-side storage (cookies, cache, storage) when a user logs out.

## Why It Matters

When a user logs out, it's important to clear all client-side data to prevent:
- Session token leakage if the device is shared
- Sensitive cached data remaining accessible
- Potential security vulnerabilities from stale authentication data

The `Clear-Site-Data` header is a standard way to instruct the browser to clear various types of data.

## Configuration

This rule is **configurable** and allows you to specify which paths should be considered logout endpoints.

### Default Configuration

If not configured, the rule checks these default paths:
- `/logout`
- `/signout`

### Custom Configuration

You can configure custom paths in your `config.toml`:

```toml
[rules.server_clear_site_data]
paths = ["/logout", "/signout", "/auth/logout", "/api/logout"]
```

### Disabling the Rule

To disable this rule completely:

```toml
[rules]
server_clear_site_data = false
```

## Violation Example

```http
POST /logout HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: application/json
```

This will trigger a violation because the logout endpoint doesn't include the `Clear-Site-Data` header.

## Compliant Example

```http
POST /logout HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: application/json
Clear-Site-Data: "*"
```

or more specifically:

```http
POST /logout HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: application/json
Clear-Site-Data: "cache", "cookies", "storage"
```

## Best Practices

1. **Use `"*"` for complete cleanup**: `Clear-Site-Data: "*"` clears all types of data
2. **Be specific if needed**: You can target specific data types: `"cache"`, `"cookies"`, `"storage"`, `"executionContexts"`
3. **Consider all logout paths**: Configure all paths where users can log out (web UI, API endpoints, etc.)
4. **Test thoroughly**: Some browsers have varying support for this header

## References

- [MDN: Clear-Site-Data](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data)
- [W3C Clear Site Data Specification](https://www.w3.org/TR/clear-site-data/)

## Rule Category

Server Response Header
