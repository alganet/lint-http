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
//!
//! **What a `HeaderMap` cannot hold, this cannot read**, and the two are not
//! the same boundary as UTF-8. `HeaderValue` admits HTAB and %x20-%xFF except
//! %x7F — the field-value grammar — so it refuses exactly the CTLs, which are
//! valid UTF-8 and so never reach the `{"b64": …}` form. A capture line
//! carrying one is refused whole, and that is deliberate: dropping the field
//! and keeping the record would hand the rules a message the file does not
//! describe, and a rule reading a field's absence would report a defect the
//! sender did not commit.
//!
//! Refusing it says what happened only if the refusal says *which* field and
//! *which* octet. The error these functions produce is read by an operator who
//! did not write the file and cannot see it: `serde` reports a byte offset into
//! a JSON line, and `http`'s own error is the five words "failed to parse
//! header value" for any of thirty fields.

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

/// The first octet in a captured value that no field value admits, and where
/// it sits.
///
/// The predicate is `HeaderValue`'s: HTAB, or %x20 and above except %x7F. It is
/// restated rather than borrowed because `http` exposes the answer only as a
/// unit error, and the offset is the whole point — an operator holding a line
/// of JSON needs to be told which octet of which field to go and look at.
///
/// `None` when every octet is admissible, which is the case where the value was
/// refused for a reason this function does not know about. The caller says so
/// in those words rather than guessing.
// cite(RFC 9110 § 5.5): "field-value    = *field-content"
// cite(RFC 9110 § 5.5): "field-vchar    = VCHAR / obs-text"
fn octet_no_field_value_admits(bytes: &[u8]) -> Option<(usize, u8)> {
    bytes
        .iter()
        .position(|&b| !(b == b'\t' || (0x20..0x7f).contains(&b) || b >= 0x80))
        .map(|at| (at, bytes[at]))
}

/// Build the map, naming the field that stopped it.
///
/// Shared by the two deserializers below, which had the same loop twice and so
/// could have gained this message in one of them only.
fn headers_from_pairs<E: de::Error>(pairs: Vec<(String, ValueBytes)>) -> Result<HeaderMap, E> {
    let mut hm = HeaderMap::with_capacity(pairs.len());
    for (k, ValueBytes(bytes)) in pairs {
        // `{k:?}` and never `{k}`: the name comes out of a file this process
        // did not write, and the reason a value is being refused here is that
        // captured field text can hold control octets. Writing one unescaped
        // into a diagnostic line is how a capture file forges a log entry.
        let name = k.parse::<HeaderName>().map_err(|_| {
            E::custom(format!(
                "field name {k:?} is not a token, so the record naming it cannot be read"
            ))
        })?;
        let val =
            HeaderValue::from_bytes(&bytes).map_err(|_| {
                match octet_no_field_value_admits(&bytes) {
                    Some((at, octet)) => E::custom(format!(
                "field {k:?} holds octet {octet:#04x} at index {at}, which no field value admits, \
                 so the record carrying it cannot be read"
            )),
                    None => E::custom(format!(
                        "field {k:?} holds a value that cannot be represented, \
                 so the record carrying it cannot be read"
                    )),
                }
            })?;
        // append (not insert) so repeated header names accumulate.
        hm.append(name, val);
    }
    Ok(hm)
}

pub fn deserialize_headers<'de, D>(deserializer: D) -> Result<HeaderMap, D::Error>
where
    D: Deserializer<'de>,
{
    headers_from_pairs(Vec::deserialize(deserializer)?)
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
    maybe.map(headers_from_pairs).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
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

    #[derive(Serialize, Deserialize, Debug)]
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

    /// A control octet is valid UTF-8, so it never takes the `{"b64": …}` road
    /// and arrives as a plain string that `HeaderValue` refuses. The record is
    /// refused with it — and the refusal has to name the field and the octet,
    /// because the operator reading it is holding a file another process wrote.
    #[rstest]
    #[case("\u{7f}", 0x7f, 0)]
    #[case("probe/1.0 (bad\u{7f}char)", 0x7f, 14)]
    #[case("a\u{1}b", 0x01, 1)]
    #[case("line\u{0}end", 0x00, 4)]
    fn a_control_octet_names_its_field_and_its_place(
        #[case] value: &str,
        #[case] octet: u8,
        #[case] at: usize,
    ) {
        let json = serde_json::json!({ "headers": [["user-agent", value]] });
        let err = serde_json::from_value::<WithHeaders>(json)
            .expect_err("a control octet is not a field value");
        let text = err.to_string();
        assert!(text.contains("\"user-agent\""), "{text}");
        assert!(text.contains(&format!("{octet:#04x}")), "{text}");
        assert!(text.contains(&format!("index {at}")), "{text}");
    }

    /// HTAB and `obs-text` are field-value octets, and refusing them would lose
    /// records this tool is meant to read. The boundary is the CTLs and nothing
    /// wider.
    #[rstest]
    #[case(b"a\tb")]
    #[case(&[0x20, 0x7e])]
    #[case(&[0x80, 0xff])]
    fn a_field_value_octet_is_not_refused(#[case] bytes: &[u8]) {
        assert_eq!(octet_no_field_value_admits(bytes), None);
    }

    /// The trailers take the same road, and had the same loop written out a
    /// second time — which is how one of the two could have kept the old
    /// five-word message.
    #[test]
    fn trailers_name_the_field_that_stopped_them() {
        let json = serde_json::json!({ "headers": [["x-trailer", "a\u{7f}b"]] });
        let err = serde_json::from_value::<WithOptionalHeaders>(json)
            .expect_err("a control octet is not a field value");
        assert!(err.to_string().contains("\"x-trailer\""), "{err}");
    }

    /// A field *name* outside `token` stops the record too, and says so by name
    /// rather than by `http`'s unit error.
    #[test]
    fn a_field_name_outside_token_names_itself() {
        let json = serde_json::json!({ "headers": [["not a name", "v"]] });
        let err = serde_json::from_value::<WithHeaders>(json).expect_err("a space is not a tchar");
        let text = err.to_string();
        assert!(text.contains("\"not a name\""), "{text}");
        assert!(text.contains("is not a token"), "{text}");
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
