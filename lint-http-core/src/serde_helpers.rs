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

pub fn serialize_optional_headers<S>(
    hm: &Option<HeaderMap>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match hm {
        Some(h) => serialize_headers(h, serializer),
        None => serializer.serialize_none(),
    }
}

pub fn deserialize_optional_headers<'de, D>(deserializer: D) -> Result<Option<HeaderMap>, D::Error>
where
    D: Deserializer<'de>,
{
    let maybe: Option<HashMap<String, String>> = Option::deserialize(deserializer)?;
    match maybe {
        None => Ok(None),
        Some(map) => {
            let mut hm = HeaderMap::new();
            for (k, v) in map {
                let name = k
                    .parse::<hyper::header::HeaderName>()
                    .map_err(serde::de::Error::custom)?;
                let val = v.parse::<HeaderValue>().map_err(serde::de::Error::custom)?;
                hm.insert(name, val);
            }
            Ok(Some(hm))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct WithOptionalHeaders {
        #[serde(
            serialize_with = "serialize_optional_headers",
            deserialize_with = "deserialize_optional_headers",
            default
        )]
        headers: Option<HeaderMap>,
    }

    #[test]
    fn optional_headers_some_roundtrip() {
        let mut hm = HeaderMap::new();
        hm.insert("x-foo", HeaderValue::from_static("bar"));
        let val = WithOptionalHeaders { headers: Some(hm) };
        let json = serde_json::to_string(&val).unwrap();
        assert!(json.contains("x-foo"));
        let parsed: WithOptionalHeaders = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.headers.as_ref().unwrap().get("x-foo").unwrap(),
            "bar"
        );
    }

    #[test]
    fn optional_headers_none_roundtrip() {
        let val = WithOptionalHeaders { headers: None };
        let json = serde_json::to_string(&val).unwrap();
        assert!(json.contains("null"));
        let parsed: WithOptionalHeaders = serde_json::from_str(&json).unwrap();
        assert!(parsed.headers.is_none());
    }

    #[test]
    fn optional_headers_multiple_entries() {
        let mut hm = HeaderMap::new();
        hm.insert("content-type", HeaderValue::from_static("text/plain"));
        hm.insert("x-custom", HeaderValue::from_static("value"));
        let val = WithOptionalHeaders { headers: Some(hm) };
        let json = serde_json::to_string(&val).unwrap();
        let parsed: WithOptionalHeaders = serde_json::from_str(&json).unwrap();
        let h = parsed.headers.unwrap();
        assert_eq!(h.get("content-type").unwrap(), "text/plain");
        assert_eq!(h.get("x-custom").unwrap(), "value");
    }
}
