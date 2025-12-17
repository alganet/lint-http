// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Serde helpers for HeaderMap (de)serialization.

use hyper::header::HeaderValue;
use hyper::HeaderMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

pub fn serialize_headers<S>(hm: &HeaderMap, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut map: HashMap<String, String> = HashMap::with_capacity(hm.len());
    for (k, v) in hm.iter() {
        if let Ok(s) = v.to_str() {
            map.insert(k.as_str().to_string(), s.to_string());
        }
    }
    map.serialize(serializer)
}

pub fn deserialize_headers<'de, D>(deserializer: D) -> Result<HeaderMap, D::Error>
where
    D: Deserializer<'de>,
{
    let map = HashMap::<String, String>::deserialize(deserializer)?;
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
