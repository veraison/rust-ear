// SPDX-License-Identifier: Apache-2.0

use crate::base64::Bytes;
use crate::error::Error;
use serde::de::{self, Deserialize, Visitor};
use serde::ser::{Error as _, Serialize, SerializeSeq as _, Serializer};

#[derive(Debug, PartialEq)]
enum OneNonce {
    String(String),
    Bytes(Bytes),
}

impl TryFrom<&[u8]> for OneNonce {
    type Error = Error;

    fn try_from(v: &[u8]) -> Result<Self, Error> {
        if v.len() >= 8 && v.len() <= 64 {
            Ok(OneNonce::Bytes(Bytes::from(v)))
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
        if v.len() >= 8 && v.len() <= 64 {
            Ok(OneNonce::Bytes(Bytes::from(v.as_slice())))
        } else {
            Err(Error::ParseError(
                "nonce must be between 8 and 64 bytes".to_string(),
            ))
        }
    }
}

impl TryFrom<&str> for OneNonce {
    type Error = Error;

    fn try_from(v: &str) -> Result<Self, Error> {
        if v.len() >= 8 && v.len() <= 88 {
            Ok(OneNonce::String(v.to_string()))
        } else {
            Err(Error::ParseError(
                "nonce must be between 8 and 88 characters".to_string(),
            ))
        }
    }
}

impl ToString for OneNonce {
    fn to_string(&self) -> String {
        match self {
            OneNonce::Bytes(v) => hex::encode(v.as_slice()),
            OneNonce::String(v) => v.to_owned(),
        }
    }
}

impl PartialEq<&str> for OneNonce {
    fn eq(&self, other: &&str) -> bool {
        match self {
            OneNonce::String(s) => s == *other,
            _ => false,
        }
    }
}

impl PartialEq<&[u8]> for OneNonce {
    fn eq(&self, other: &&[u8]) -> bool {
        match self {
            OneNonce::Bytes(b) => b.as_slice() == *other,
            _ => false,
        }
    }
}

impl Serialize for OneNonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            OneNonce::Bytes(v) => {
                if !serializer.is_human_readable() {
                    v.serialize(serializer)
                } else {
                    Err(S::Error::custom("cannot write byte nonce to JSON"))
                }
            }
            OneNonce::String(v) => {
                if serializer.is_human_readable() {
                    serializer.serialize_str(v)
                } else {
                    Err(S::Error::custom("cannot write string nonce to CBOR"))
                }
            }
        }
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

impl<'de> Visitor<'de> for OneNonceVisitor {
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

/// echoed back by the verifier to provide freshness
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

impl ToString for Nonce {
    fn to_string(&self) -> String {
        let len = self.0.len();
        match len {
            0 => "".to_string(),
            1 => self.0[0].to_string(),
            _ => {
                let mut s = "[".to_owned();

                for (i, on) in self.0.iter().enumerate() {
                    s.push_str(on.to_string().as_str());
                    if i < (len - 1) {
                        s.push_str(", ");
                    }
                }
                s.push(']');

                s
            }
        }
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
        let n = Nonce::try_from("test value").unwrap();
        assert_eq!(n.to_string(), "test value");

        let e = Nonce::try_from("foo").unwrap_err();
        assert_eq!(
            e.to_string(),
            "parse error: nonce must be between 8 and 88 characters"
        );

        let e = Nonce::try_from(
            "this is a very long nonce value that goes on, and on and on and on, seemingly without end...",
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            "parse error: nonce must be between 8 and 88 characters"
        );
    }

    #[test]
    fn from_bytes() {
        let n =
            Nonce::try_from([0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef].as_slice()).unwrap();
        assert_eq!(n.to_string(), "deadbeefdeadbeef");

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
        let n = Nonce::try_from(["test value one", "test value two"].as_slice()).unwrap();
        assert_eq!(n.to_string(), "[test value one, test value two]");

        let e = Nonce::try_from(["test value one", "foo"].as_slice()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "parse error: item 1: nonce must be between 8 and 88 characters"
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
        assert_eq!(n.to_string(), "[deadbeefdeadbeef, abadcafeabadcafe]");

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
        assert_ne!(n, "deadbeefdeadbeef");

        let n = Nonce::try_from("test value").unwrap();
        assert_eq!(n, "test value");
        assert_ne!(n, "test");
        assert_ne!(n, bytes.as_slice());

        let n = Nonce(Vec::new());
        assert_ne!(n, "test");
        assert_ne!(n, bytes.as_slice());
        assert_eq!(n.to_string(), "");
    }

    #[test]
    fn is_empty() {
        let n = Nonce(Vec::new());
        assert!(n.is_empty());

        let n = Nonce::try_from("test value").unwrap();
        assert!(!n.is_empty());
    }

    #[test]
    fn serde() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef];
        let n = Nonce::try_from(bytes.as_slice()).unwrap();

        let val = serde_json::to_string(&n).unwrap_err();
        assert_eq!(val.to_string(), "cannot write byte nonce to JSON");

        let mut buf: Vec<u8> = Vec::new();
        into_writer(&n, &mut buf).unwrap();
        assert_eq!(
            buf,
            vec![
                0x48, // byte string (8)
                0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
            ]
        );

        let n = Nonce::try_from("test value").unwrap();

        let val = serde_json::to_string(&n).unwrap();
        assert_eq!(val, r#""test value""#);

        let mut buf: Vec<u8> = Vec::new();
        let val = into_writer(&n, &mut buf).unwrap_err();
        assert_eq!(
            val.to_string(),
            r#"Value("cannot write string nonce to CBOR")"#
        );

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

        let n = Nonce::try_from(["test value one", "test value two"].as_slice()).unwrap();
        let val = serde_json::to_string(&n).unwrap();
        assert_eq!(val, r#"["test value one","test value two"]"#);

        let mut buf: Vec<u8> = Vec::new();
        let val = into_writer(&n, &mut buf).unwrap_err();
        assert_eq!(
            val.to_string(),
            r#"Value("cannot write string nonce to CBOR")"#
        );

        let n = Nonce::try_from(
            [
                vec![0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef],
                vec![0xab, 0xad, 0xca, 0xfe, 0xab, 0xad, 0xca, 0xfe],
            ]
            .as_slice(),
        )
        .unwrap();

        let val = serde_json::to_string(&n).unwrap_err();
        assert_eq!(val.to_string(), "cannot write byte nonce to JSON");

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
