// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use ::base64::{engine::general_purpose, Engine as _};
use serde::de::{self, Deserialize, Visitor};
use serde::ser::{Serialize, SerializeSeq as _, Serializer};

use crate::base64::Bytes;
use crate::error::Error;

/// The encoding rules come from RFC 9711, Section 4.1, as referenced by
/// draft-ietf-rats-ear-04, Sections 3 and 3.1:
/// <https://www.rfc-editor.org/rfc/rfc9711.html#section-4.1>.
///
/// Keep the decoded bytes internally so the same nonce can be serialized as base64url text in
/// JSON and as a byte string in CBOR.
#[derive(Debug, PartialEq)]
struct OneNonce(Bytes);

impl TryFrom<&[u8]> for OneNonce {
    type Error = Error;

    fn try_from(v: &[u8]) -> Result<Self, Error> {
        if v.len() >= 8 && v.len() <= 64 {
            Ok(OneNonce(Bytes::from(v)))
        } else {
            Err(Error::ParseError(
                "nonce must be between 8 and 64 bytes".to_string(),
            ))
        }
    }
}

impl TryFrom<&Vec<u8>> for OneNonce {
    type Error = Error;

    fn try_from(v: &Vec<u8>) -> Result<Self, Error> {
        OneNonce::try_from(v.as_slice())
    }
}

impl TryFrom<&str> for OneNonce {
    type Error = Error;

    fn try_from(v: &str) -> Result<Self, Error> {
        let bytes = Bytes::try_from(v)
            .map_err(|_| Error::ParseError("nonce must be base64url encoded".to_string()))?;
        OneNonce::try_from(bytes.as_slice())
    }
}

impl TryFrom<String> for OneNonce {
    type Error = Error;

    fn try_from(v: String) -> Result<Self, Error> {
        OneNonce::try_from(v.as_str())
    }
}

impl fmt::Display for OneNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&general_purpose::URL_SAFE_NO_PAD.encode(self.0.as_slice()))
    }
}

impl PartialEq<&str> for OneNonce {
    fn eq(&self, other: &&str) -> bool {
        Bytes::try_from(*other)
            .map(|bytes| self.0 == bytes)
            .unwrap_or(false)
    }
}

impl PartialEq<&[u8]> for OneNonce {
    fn eq(&self, other: &&[u8]) -> bool {
        self.0.as_slice() == *other
    }
}

impl Serialize for OneNonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for OneNonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(OneNonceVisitor {})
    }
}

struct OneNonceVisitor;

impl Visitor<'_> for OneNonceVisitor {
    type Value = OneNonce;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a text string or a byte string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        OneNonce::try_from(v).map_err(|e| E::custom(e))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        OneNonce::try_from(v).map_err(|e| E::custom(e))
    }
}

/// Echoed back by the verifier to provide freshness.
///
/// JSON uses base64url text and CBOR uses byte strings, as defined by [RFC 9711, Section 4.1] and
/// referenced by [draft-ietf-rats-ear-04, Sections 3 and 3.1].
///
/// [RFC 9711, Section 4.1]: https://www.rfc-editor.org/rfc/rfc9711.html#section-4.1
/// [draft-ietf-rats-ear-04, Sections 3 and 3.1]: https://www.ietf.org/archive/id/draft-ietf-rats-ear-04.html#section-3
#[derive(Debug, PartialEq)]
pub struct Nonce(Vec<OneNonce>);

impl Nonce {
    pub fn is_empty(&self) -> bool {
        self.0.len() == 0
    }
}

impl TryFrom<&[u8]> for Nonce {
    type Error = Error;

    fn try_from(v: &[u8]) -> Result<Self, Error> {
        Ok(Nonce(vec![OneNonce::try_from(v)?]))
    }
}

impl TryFrom<&str> for Nonce {
    type Error = Error;

    fn try_from(v: &str) -> Result<Self, Error> {
        Ok(Nonce(vec![OneNonce::try_from(v)?]))
    }
}

impl TryFrom<String> for Nonce {
    type Error = Error;

    fn try_from(v: String) -> Result<Self, Error> {
        Ok(Nonce(vec![OneNonce::try_from(v)?]))
    }
}

impl TryFrom<&[&str]> for Nonce {
    type Error = Error;

    fn try_from(vals: &[&str]) -> Result<Self, Error> {
        let mut res: Nonce = Nonce(vec![]);
        for (i, v) in vals.iter().enumerate() {
            res.0.push(OneNonce::try_from(*v).map_err(|e| {
                let msg = match e {
                    Error::ParseError(s) => s,
                    _ => e.to_string(),
                };
                Error::ParseError(format!("item {i}: {msg}"))
            })?);
        }
        Ok(res)
    }
}

impl TryFrom<&[String]> for Nonce {
    type Error = Error;

    fn try_from(vals: &[String]) -> Result<Self, Error> {
        let mut res: Nonce = Nonce(vec![]);
        for (i, v) in vals.iter().enumerate() {
            res.0.push(OneNonce::try_from(v.as_str()).map_err(|e| {
                let msg = match e {
                    Error::ParseError(s) => s,
                    _ => e.to_string(),
                };
                Error::ParseError(format!("item {i}: {msg}"))
            })?);
        }
        Ok(res)
    }
}

impl TryFrom<&[Vec<u8>]> for Nonce {
    type Error = Error;

    fn try_from(vals: &[Vec<u8>]) -> Result<Self, Error> {
        let mut res: Nonce = Nonce(vec![]);
        for (i, v) in vals.iter().enumerate() {
            res.0.push(OneNonce::try_from(v).map_err(|e| {
                let msg = match e {
                    Error::ParseError(s) => s,
                    _ => e.to_string(),
                };
                Error::ParseError(format!("item {i}: {msg}"))
            })?);
        }
        Ok(res)
    }
}

impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self.0.len();
        let mut enc: String;

        f.write_str(match len {
            0 => "",
            1 => {
                enc = self.0[0].to_string();
                &enc
            }
            _ => {
                enc = "[".to_owned();

                for (i, on) in self.0.iter().enumerate() {
                    enc.push_str(on.to_string().as_str());
                    if i < (len - 1) {
                        enc.push_str(", ");
                    }
                }
                enc.push(']');

                &enc
            }
        })
    }
}

impl PartialEq<&str> for Nonce {
    fn eq(&self, other: &&str) -> bool {
        match self.0.len() {
            1 => self.0[0] == *other,
            _ => false,
        }
    }
}

impl PartialEq<&[u8]> for Nonce {
    fn eq(&self, other: &&[u8]) -> bool {
        match self.0.len() {
            1 => self.0[0] == *other,
            _ => false,
        }
    }
}

impl Serialize for Nonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0.len() {
            0 => serializer.serialize_none(),
            1 => self.0[0].serialize(serializer),
            _ => {
                let mut sa = serializer.serialize_seq(Some(self.0.len()))?;
                for on in self.0.iter() {
                    sa.serialize_element(&on)?;
                }
                sa.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(NonceVisitor {})
    }
}

struct NonceVisitor;

impl<'de> Visitor<'de> for NonceVisitor {
    type Value = Nonce;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a text string, a byte string, or an array of text/byte strings")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Nonce::try_from(v).map_err(|e| E::custom(e))
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Nonce::try_from(v).map_err(|e| E::custom(e))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: de::SeqAccess<'de>,
    {
        let mut n = Nonce(Vec::new());

        while let Some(v) = seq.next_element::<OneNonce>()? {
            n.0.push(v);
        }

        Ok(n)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ciborium::{de::from_reader, ser::into_writer};

    #[test]
    fn from_str() {
        let n = Nonce::try_from("3q2-796tvu8").unwrap();
        assert_eq!(n.to_string(), "3q2-796tvu8");

        let e = Nonce::try_from("AQIDBA").unwrap_err();
        assert_eq!(
            e.to_string(),
            "parse error: nonce must be between 8 and 64 bytes"
        );

        let e = Nonce::try_from("not base64url!").unwrap_err();
        assert_eq!(
            e.to_string(),
            "parse error: nonce must be base64url encoded"
        );
    }

    #[test]
    fn from_bytes() {
        let n =
            Nonce::try_from([0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef].as_slice()).unwrap();
        assert_eq!(n.to_string(), "3q2-796tvu8");

        let e = Nonce::try_from([0xde, 0xad, 0xbe, 0xef].as_slice()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "parse error: nonce must be between 8 and 64 bytes"
        );

        let e = Nonce::try_from(
            [
                0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
                0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
                0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde,
            ]
            .as_slice(),
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            "parse error: nonce must be between 8 and 64 bytes"
        );
    }

    #[test]
    fn from_str_slice() {
        let n = Nonce::try_from(["3q2-796tvu8", "q63K_qutyv4"].as_slice()).unwrap();
        assert_eq!(n.to_string(), "[3q2-796tvu8, q63K_qutyv4]");

        let e = Nonce::try_from(["3q2-796tvu8", "AQIDBA"].as_slice()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "parse error: item 1: nonce must be between 8 and 64 bytes"
        );
    }

    #[test]
    fn from_bytes_slice() {
        let n = Nonce::try_from(
            [
                vec![0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef],
                vec![0xab, 0xad, 0xca, 0xfe, 0xab, 0xad, 0xca, 0xfe],
            ]
            .as_slice(),
        )
        .unwrap();
        assert_eq!(n.to_string(), "[3q2-796tvu8, q63K_qutyv4]");

        let e = Nonce::try_from(
            [
                vec![0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef],
                vec![0xab, 0xad, 0xca, 0xfe],
            ]
            .as_slice(),
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            "parse error: item 1: nonce must be between 8 and 64 bytes"
        );
    }

    #[test]
    fn equality() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef];
        let n = Nonce::try_from(bytes.as_slice()).unwrap();
        assert_eq!(n, bytes.as_slice());
        assert_ne!(n, &[0xde, 0xad][..]);
        assert_eq!(n, "3q2-796tvu8");

        let n = Nonce::try_from("3q2-796tvu8").unwrap();
        assert_eq!(n, "3q2-796tvu8");
        assert_ne!(n, "AQIDBA");
        assert_eq!(n, bytes.as_slice());

        let n = Nonce(Vec::new());
        assert_ne!(n, "test");
        assert_ne!(n, bytes.as_slice());
        assert_eq!(n.to_string(), "");
    }

    #[test]
    fn is_empty() {
        let n = Nonce(Vec::new());
        assert!(n.is_empty());

        let n = Nonce::try_from("3q2-796tvu8").unwrap();
        assert!(!n.is_empty());
    }

    #[test]
    fn serde() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef];
        let n = Nonce::try_from(bytes.as_slice()).unwrap();

        let val = serde_json::to_string(&n).unwrap();
        assert_eq!(val, r#""3q2-796tvu8""#);
        let json_nonce: Nonce = serde_json::from_str(&val).unwrap();
        assert_eq!(json_nonce, n);

        let mut buf: Vec<u8> = Vec::new();
        into_writer(&n, &mut buf).unwrap();
        assert_eq!(
            buf,
            vec![
                0x48, // byte string (8)
                0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
            ]
        );
        let cbor_nonce: Nonce = from_reader(buf.as_slice()).unwrap();
        assert_eq!(cbor_nonce, n);

        let from_json: Nonce = serde_json::from_str(r#""3q2-796tvu8""#).unwrap();
        let mut cross_format = Vec::new();
        into_writer(&from_json, &mut cross_format).unwrap();
        assert_eq!(cross_format, buf);

        let n = Nonce(Vec::new());
        let val = serde_json::to_string(&n).unwrap();
        assert_eq!(val, r#"null"#);

        let mut buf: Vec<u8> = Vec::new();
        into_writer(&n, &mut buf).unwrap();
        assert_eq!(
            buf,
            vec![
            0xf6, // null
        ]
        );

        let n = Nonce::try_from(["3q2-796tvu8", "q63K_qutyv4"].as_slice()).unwrap();
        let val = serde_json::to_string(&n).unwrap();
        assert_eq!(val, r#"["3q2-796tvu8","q63K_qutyv4"]"#);

        let mut buf: Vec<u8> = Vec::new();
        into_writer(&n, &mut buf).unwrap();
        assert_eq!(
            buf,
            vec![
                0x82, // array (2)
                0x48, // byte string (8)
                0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0x48, // byte string (8)
                0xab, 0xad, 0xca, 0xfe, 0xab, 0xad, 0xca, 0xfe,
            ]
        );

        let n2: Nonce = from_reader(buf.as_slice()).unwrap();
        assert_eq!(n, n2);
    }
}
