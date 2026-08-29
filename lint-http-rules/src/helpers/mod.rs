// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Helper utilities shared across multiple lint rules.
//!
//! This module groups reusable helpers for validating HTTP common structures.
//!
//! **Every module below is named for a question, and none for a document.**
//! Read the list: each name is something a value can *be*, never the
//! specification that defines it — which is why one module holds productions
//! from several documents, and why two productions printed on the same page can
//! live apart. That is the shelving rule, and it is the answer to the periodic
//! suggestion of a module named for a publisher: a `microsyntax.rs` collecting
//! the WHATWG transcriptions would be the first module here named for a table of
//! contents.
//!
//! **`headers` is the one module named for a data structure, and it is the
//! standing example of what the rule prevents.** "Arrives in a `HeaderMap`" is
//! true of every field in HTTP, so it shelved nothing and accumulated seventy
//! items across eleven questions — cache freshness, quoted strings, media types,
//! entity tags — each findable only by someone who already knew it was there.
//! Eleven modules were lifted out of it: `list`, `quoted_string`, `word`,
//! `parameter`, `media_type`, `qvalue`, `validator`, `vary`, `content_length`,
//! `field_placement`, `shown`. What remains is genuinely about the map.
//!
//! Two lessons from doing it, because both cut against the obvious move. A
//! function that transcribes *two* alternatives of a grammar belongs with
//! neither alone: `token_or_quoted_string` cites both `token` and
//! `quoted-string`, and filing it under `token` would have named it for half
//! its own production — `word` is what the specification calls the pair. And
//! the busiest caller is not the owner: `parameters` is read almost always
//! beside `parse_media_type`, but it takes any `;`-separated tail and
//! `Content-Disposition` and `Expect` carry it too, so it is its own module and
//! `media_type` depends on it. Count what a function *asks*, never who asks it
//! most.
//!
//! Counted by *what transcribes a production into code* — not by what cites a
//! WHATWG document, which `link_header_valid` also does, for three
//! algorithm steps that license a gate and transcribe nothing — the tree holds
//! **six** such transcriptions, in two rules, from four documents: the URL
//! Standard's *URL code points* and *URL units*, Infra's *ASCII whitespace*,
//! HTML's *valid non-negative integer* and its two-form authoring requirement
//! for `Refresh`, and HTML's *valid floating-point number* in
//! `server_timing_header_syntax`. Two character-class sets, a whitespace
//! set, two number productions and a prose shape; not one is a subroutine of
//! another, and each has exactly one caller. **The rule for arriving here is
//! unchanged and is what decides it: a shared answer moves on the second caller,
//! and that caller has to be asking the same question, not merely reading the
//! same publisher.**
//!
//! **And the second caller can be a caller of one *ingredient* rather than of
//! the function.** `first_non_pchar` in `well_known_uri_syntax` had one
//! caller and stayed there, while the two sets it is composed of —
//! `uri::is_unreserved` and `uri::is_sub_delim` — had five readers and four,
//! written out character for character each time. A grammar that builds its component rules
//! by naming one set and adding to it will produce that shape every time, so the
//! count that decides the move is the count of the *smallest thing two sites
//! share*, not of the function one of them happens to have wrapped it in.

pub mod accept_ranges;
pub mod auth;
pub mod cache_control;
pub mod comment;
pub mod content_length;
pub mod content_range;
pub mod cookie;
pub mod domain;
pub mod field_placement;
pub mod forwarded_node;
pub mod headers;
pub mod ipv6;
pub mod language;
pub mod list;
pub mod mailbox;
pub mod media_type;
pub mod parameter;
pub mod product;
pub mod quoted_string;
pub mod qvalue;
pub mod rule_config;
pub mod shown;
pub mod status;
pub mod structured_fields;
pub mod token;
pub mod uri;
pub mod validator;
pub mod vary;
pub mod websocket;
pub mod word;
