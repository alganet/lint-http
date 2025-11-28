<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- HTTP forward proxy with request/response capture
- JSONL capture format with metadata
- Configurable lint rules for HTTP responses
- Three built-in rules: cache-control-present, etag-or-last-modified, x-content-type-options
- TOML configuration support
- Comprehensive test suite
- Unit tests for all lint rules

### Changed
- Fixed crate namespaces for `src/rules` (moved from `lint::rules` to `crate::rules`)
- Rewrote `README.md` to accurately reflect project functionality
