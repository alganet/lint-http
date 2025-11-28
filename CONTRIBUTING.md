<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Contributing

## Development

```bash
cargo build
cargo test
cargo fmt
cargo clippy
```

## Testing

Run tests:
```bash
cargo test
```

Coverage:
```bash
cargo tarpaulin --out Xml
```

## Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## Code Style

- Follow Rust standard style (`cargo fmt`)
- Address all clippy warnings
- Add tests for new features
- Update CHANGELOG.md
