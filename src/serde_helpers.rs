// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Reusable serde helpers for common serialization patterns.
//!
//! This module contains helpers to (de)serialize `HeaderMap` as a simple
//! `Map<String, String>` for JSON output. It's kept small and focused so other
//! modules can reuse the same behavior.

use hyper::header::HeaderValue;
use hyper::HeaderMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap as StdHashMap;

/// Serialize a `HeaderMap` to a `Map<String,String>` by including only header
/// values that successfully convert to UTF-8 strings.
pub fn serialize_headers<S>(hm: &HeaderMap, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map: StdHashMap<String, String> = StdHashMap::with_capacity(hm.len());
    for (k, v) in hm.iter() {
        if let Ok(s) = v.to_str() {
            map.insert(k.as_str().to_string(), s.to_string());
        }
    }
    map.serialize(serializer)
}

/// Deserialize a `Map<String,String>` into a `HeaderMap`.
pub fn deserialize_headers<'de, D>(deserializer: D) -> Result<HeaderMap, D::Error>
where
    D: Deserializer<'de>,
{
    let map = StdHashMap::<String, String>::deserialize(deserializer)?;
    let mut hm = HeaderMap::new();
    for (k, v) in map {
        let name = k
            .parse::<hyper::header::HeaderName>()
            .map_err(serde::de::Error::custom)?;
        let val = v.parse::<HeaderValue>().map_err(serde::de::Error::custom)?;
        hm.insert(name, val);
    }
    Ok(hm)
}
