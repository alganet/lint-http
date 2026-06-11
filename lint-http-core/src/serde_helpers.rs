// SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
//
// SPDX-License-Identifier: ISC

//! Serde helpers for HeaderMap (de)serialization.
//!
//! Headers serialize as an **ordered array of `[name, value]` pairs** rather
//! than a map, so that multi-value headers (`Set-Cookie`, `Vary`, `Link`, …)
//! and the exact on-wire ordering survive a capture round-trip. Each value is
//! a plain JSON string when the bytes are valid UTF-8, or a `{"b64": "…"}`
//! object carrying the base64 of the raw bytes when they are not — so no
//! header value is ever silently dropped.

use base64::Engine;
use hyper::header::{HeaderName, HeaderValue};
use hyper::HeaderMap;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Serializes a single `HeaderValue` as a UTF-8 string or a `{"b64": …}` map.
struct ValueWrap<'a>(&'a HeaderValue);

impl Serialize for ValueWrap<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0.to_str() {
            Ok(text) => serializer.serialize_str(text),
            Err(_) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("b64", &B64.encode(self.0.as_bytes()))?;
                map.end()
            }
        }
    }
}

/// Serializes one `(name, value)` pair as a 2-element JSON array.
struct Pair<'a>(&'a HeaderName, &'a HeaderValue);

impl Serialize for Pair<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(self.0.as_str())?;
        seq.serialize_element(&ValueWrap(self.1))?;
        seq.end()
    }
}

pub fn serialize_headers<S>(hm: &HeaderMap, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(hm.len()))?;
    for (k, v) in hm.iter() {
        seq.serialize_element(&Pair(k, v))?;
    }
    seq.end()
}

/// Raw header value bytes deserialized from a string or a `{"b64": …}` object.
struct ValueBytes(Vec<u8>);

impl<'de> Deserialize<'de> for ValueBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a header value string or a {\"b64\": \"…\"} object")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
                Ok(v.as_bytes().to_vec())
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Vec<u8>, M::Error> {
                let mut bytes: Option<Vec<u8>> = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "b64" {
                        let encoded: String = map.next_value()?;
                        bytes = Some(B64.decode(encoded.as_bytes()).map_err(de::Error::custom)?);
                    } else {
                        let _: de::IgnoredAny = map.next_value()?;
                    }
                }
                bytes.ok_or_else(|| de::Error::custom("missing \"b64\" key in header value object"))
            }
        }

        deserializer.deserialize_any(ValueVisitor).map(ValueBytes)
    }
}

pub fn deserialize_headers<'de, D>(deserializer: D) -> Result<HeaderMap, D::Error>
where
    D: Deserializer<'de>,
{
    let pairs: Vec<(String, ValueBytes)> = Vec::deserialize(deserializer)?;
    let mut hm = HeaderMap::with_capacity(pairs.len());
    for (k, ValueBytes(bytes)) in pairs {
        let name = k.parse::<HeaderName>().map_err(de::Error::custom)?;
        let val = HeaderValue::from_bytes(&bytes).map_err(de::Error::custom)?;
        // append (not insert) so repeated header names accumulate.
        hm.append(name, val);
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
    let maybe: Option<Vec<(String, ValueBytes)>> = Option::deserialize(deserializer)?;
    match maybe {
        None => Ok(None),
        Some(pairs) => {
            let mut hm = HeaderMap::with_capacity(pairs.len());
            for (k, ValueBytes(bytes)) in pairs {
                let name = k.parse::<HeaderName>().map_err(de::Error::custom)?;
                let val = HeaderValue::from_bytes(&bytes).map_err(de::Error::custom)?;
                hm.append(name, val);
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

    #[derive(Serialize, Deserialize)]
    struct WithHeaders {
        #[serde(
            serialize_with = "serialize_headers",
            deserialize_with = "deserialize_headers"
        )]
        headers: HeaderMap,
    }

    #[test]
    fn headers_serialize_as_array_of_pairs() {
        let mut hm = HeaderMap::new();
        hm.insert("x-foo", HeaderValue::from_static("bar"));
        let json = serde_json::to_value(WithHeaders { headers: hm }).unwrap();
        assert_eq!(json["headers"], serde_json::json!([["x-foo", "bar"]]));
    }

    #[test]
    fn multi_value_headers_roundtrip_losslessly() {
        let mut hm = HeaderMap::new();
        hm.append("set-cookie", HeaderValue::from_static("a=1"));
        hm.append("set-cookie", HeaderValue::from_static("b=2"));
        let json = serde_json::to_string(&WithHeaders { headers: hm }).unwrap();
        let parsed: WithHeaders = serde_json::from_str(&json).unwrap();
        let cookies: Vec<&str> = parsed
            .headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookies, vec!["a=1", "b=2"]);
    }

    #[test]
    fn non_utf8_header_value_roundtrips_via_base64() {
        let mut hm = HeaderMap::new();
        hm.insert("x-bad", HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap());
        let json = serde_json::to_value(WithHeaders { headers: hm }).unwrap();
        // Non-UTF-8 value is encoded as a {"b64": ...} object, not dropped.
        assert_eq!(json["headers"][0][0], "x-bad");
        assert!(json["headers"][0][1].get("b64").is_some());

        let parsed: WithHeaders = serde_json::from_value(json).unwrap();
        assert_eq!(
            parsed.headers.get("x-bad").unwrap().as_bytes(),
            &[0xff, 0xfe]
        );
    }
}
