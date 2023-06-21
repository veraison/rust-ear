// SPDX-License-Identifier: Apache-2.0

// Limitations of this implementation:
// - null values not supported
// - tags are stripped when serializing to JSON
// - byte strings are written as base64-encoded strings to JSON (meaning they deserialize as
//   text strings, losing their original type).
use serde::de::{self, Deserialize, EnumAccess, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, Serializer};
use serde::ser::{SerializeMap as _, SerializeSeq as _, SerializeTupleVariant as _};

use crate::base64::Bytes;

/// deserialized raw JSON object or CBOR map
#[derive(Debug, PartialEq)]
pub enum RawValue {
    Integer(i64),
    Bytes(Bytes),
    Float(f64),
    Text(String),
    Bool(bool),
    Array(Vec<RawValue>),
    Map(Vec<(RawValue, RawValue)>),
    Tagged(u64, Box<RawValue>),
}

impl Serialize for RawValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Integer(i) => serializer.serialize_i64(*i),
            Self::Bytes(b) => b.serialize(serializer),
            Self::Float(f) => serializer.serialize_f64(*f),
            Self::Text(s) => serializer.serialize_str(s),
            Self::Bool(b) => serializer.serialize_bool(*b),
            Self::Array(vs) => {
                let mut seq = serializer.serialize_seq(Some(vs.len()))?;
                for v in vs.iter() {
                    seq.serialize_element(v)?;
                }
                seq.end()
            }
            Self::Map(vs) => {
                let mut map = serializer.serialize_map(Some(vs.len()))?;
                for (k, v) in vs.iter() {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
            Self::Tagged(t, v) => {
                if serializer.is_human_readable() {
                    // NOTE: since JSON does not have a concept of tagging, we've no choice but to
                    // drop the tag here. This means that a lossless JSON<->CBOR round trip is not
                    // possible if tags are used.
                    v.serialize(serializer)
                } else {
                    let mut acc =
                        serializer.serialize_tuple_variant("@@TAG@@", 0, "@@TAGGED@@", 2)?;
                    acc.serialize_field(t)?;
                    acc.serialize_field(v)?;
                    acc.end()
                }
            }
        }
    }
}

impl<'de> Deserialize<'de> for RawValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(RawValueVisitor {})
    }
}

struct RawValueVisitor;

impl<'de> Visitor<'de> for RawValueVisitor {
    type Value = RawValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("an arbitrary JSON or CBOR structure")
    }

    fn visit_i8<E: de::Error>(self, v: i8) -> Result<Self::Value, E> {
        Ok(RawValue::Integer(v.into()))
    }

    fn visit_i16<E: de::Error>(self, v: i16) -> Result<Self::Value, E> {
        Ok(RawValue::Integer(v.into()))
    }

    fn visit_i32<E: de::Error>(self, v: i32) -> Result<Self::Value, E> {
        Ok(RawValue::Integer(v.into()))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        Ok(RawValue::Integer(v))
    }

    fn visit_u8<E: de::Error>(self, v: u8) -> Result<Self::Value, E> {
        Ok(RawValue::Integer(v.into()))
    }

    fn visit_u16<E: de::Error>(self, v: u16) -> Result<Self::Value, E> {
        Ok(RawValue::Integer(v.into()))
    }

    fn visit_u32<E: de::Error>(self, v: u32) -> Result<Self::Value, E> {
        Ok(RawValue::Integer(v.into()))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        Ok(RawValue::Integer(v.try_into().map_err(E::custom)?))
    }

    fn visit_f32<E: de::Error>(self, v: f32) -> Result<Self::Value, E> {
        Ok(RawValue::Float(v.into()))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
        Ok(RawValue::Float(v))
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Ok(RawValue::Bool(v))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(RawValue::Text(v.to_string()))
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        Ok(RawValue::Bytes(Bytes::from(v)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut ret = Vec::new();

        while let Some(v) = seq.next_element::<RawValue>()? {
            ret.push(v);
        }

        Ok(RawValue::Array(ret))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut ret = Vec::new();

        while let Some((key, val)) = map.next_entry::<RawValue, RawValue>()? {
            ret.push((key, val));
        }

        Ok(RawValue::Map(ret))
    }

    // adapted from ciborium implementation of Value::Tag.
    fn visit_enum<A: EnumAccess<'de>>(self, acc: A) -> Result<Self::Value, A::Error> {
        use serde::de::VariantAccess;

        struct Inner;

        impl<'de> serde::de::Visitor<'de> for Inner {
            type Value = RawValue;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(formatter, "a CBOR tagged value")
            }

            #[inline]
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut acc: A) -> Result<Self::Value, A::Error> {
                let tag: u64 = acc
                    .next_element()?
                    .ok_or_else(|| de::Error::custom("expected tag"))?;
                let val = acc
                    .next_element()?
                    .ok_or_else(|| de::Error::custom("expected val"))?;
                Ok(RawValue::Tagged(tag, Box::new(val)))
            }
        }

        let (name, data): (String, _) = acc.variant()?;
        assert_eq!("@@TAGGED@@", name);
        data.tuple_variant(2, Inner)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ciborium::{de::from_reader, ser::into_writer};

    #[test]
    fn serde() {
        let rv = RawValue::Integer(7);

        let val = serde_json::to_string(&rv).unwrap();
        assert_eq!("7", val);

        let rv2: RawValue = serde_json::from_str(&val).unwrap();
        assert_eq!(rv2, rv);

        let mut buf: Vec<u8> = Vec::new();
        into_writer(&rv, &mut buf).unwrap();
        assert_eq!(vec![0x07], buf);

        let rv2: RawValue = from_reader(buf.as_slice()).unwrap();
        assert_eq!(rv2, rv);

        let rv = RawValue::Bytes(Bytes::from(vec![0xde, 0xad, 0xbe, 0xef].as_slice()));

        let val = serde_json::to_string(&rv).unwrap();
        assert_eq!(r#""3q2-7w""#, val);

        let rv2: RawValue = serde_json::from_str(&val).unwrap();
        assert_eq!(rv2, RawValue::Text("3q2-7w".to_string()));

        let mut buf: Vec<u8> = Vec::new();
        into_writer(&rv, &mut buf).unwrap();
        assert_eq!(
            vec![
                0x44, // byte string (4)
                0xde, 0xad, 0xbe, 0xef,
            ],
            buf
        );

        let rv2: RawValue = from_reader(buf.as_slice()).unwrap();
        assert_eq!(rv2, rv);

        let rv = RawValue::Map(vec![
            (
                RawValue::Text("field one".to_string()),
                RawValue::Float(7.0),
            ),
            (
                RawValue::Text("field two".to_string()),
                RawValue::Bool(true),
            ),
        ]);

        let val = serde_json::to_string(&rv).unwrap();
        assert_eq!(r#"{"field one":7.0,"field two":true}"#, val);

        let rv2: RawValue = serde_json::from_str(&val).unwrap();
        assert_eq!(rv2, rv);

        let mut buf: Vec<u8> = Vec::new();
        into_writer(&rv, &mut buf).unwrap();
        assert_eq!(
            vec![
                0xa2, // map (2)
                0x69, // text string (9)
                0x66, 0x69, 0x65, 0x6c, 0x64, 0x20, 0x6f, 0x6e, 0x65, // "field one"
                0xf9, // IEEE 754 half-precision float
                0x47, 0x00, // 7.0f16
                0x69, // text string (9)
                0x66, 0x69, 0x65, 0x6c, 0x64, 0x20, 0x74, 0x77, 0x6f, // "field two"
                0xf5, // true
            ],
            buf
        );

        let rv2: RawValue = from_reader(buf.as_slice()).unwrap();
        assert_eq!(rv2, rv);

        let rv = RawValue::Array(vec![
            RawValue::Text("foo".to_string()),
            RawValue::Integer(-1337),
        ]);

        let val = serde_json::to_string(&rv).unwrap();
        assert_eq!(r#"["foo",-1337]"#, val);

        let rv2: RawValue = serde_json::from_str(&val).unwrap();
        assert_eq!(rv2, rv);

        let mut buf: Vec<u8> = Vec::new();
        into_writer(&rv, &mut buf).unwrap();
        assert_eq!(
            vec![
                0x82, // array (2)
                0x63, // text string (3)
                0x66, 0x6f, 0x6f, 0x39, // negative int in the  following 2 bytes
                0x05, 0x38, // 1336 (-1 - 1337)
            ],
            buf
        );

        let rv2: RawValue = from_reader(buf.as_slice()).unwrap();
        assert_eq!(rv2, rv);

        let rv = RawValue::Tagged(1, Box::new(RawValue::Text("foo".to_string())));

        let val = serde_json::to_string(&rv).unwrap();
        assert_eq!(r#""foo""#, val);

        let rv2: RawValue = serde_json::from_str(&val).unwrap();
        assert_eq!(rv2, RawValue::Text("foo".to_string())); // tag stripped

        let mut buf: Vec<u8> = Vec::new();
        into_writer(&rv, &mut buf).unwrap();
        assert_eq!(
            vec![
                0xc1, // tag 1
                0x63, // text string (3)
                0x66, 0x6f, 0x6f,
            ],
            buf
        );

        let rv2: RawValue = from_reader(buf.as_slice()).unwrap();
        assert_eq!(rv2, rv);
    }
}
