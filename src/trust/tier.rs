// SPDX-License-Identifier: Apache-2.0

use serde::{
    de::{self, Visitor},
    ser::{Serialize, Serializer},
    Deserialize,
};
use std::fmt;

/// Tier of a trustworthiness claim's value
///
/// This is a categorisation of the levels of trustworthiness based on the values assigned to
/// trustworthiness claims.
#[derive(Debug, PartialEq, PartialOrd)]
pub enum TrustTier {
    None,
    Affirming,
    Warning,
    Contraindicated,
}

impl Serialize for TrustTier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            match self {
                TrustTier::None => serializer.serialize_str("none"),
                TrustTier::Affirming => serializer.serialize_str("affirming"),
                TrustTier::Warning => serializer.serialize_str("warning"),
                TrustTier::Contraindicated => serializer.serialize_str("contraindicated"),
            }
        } else {
            match self {
                TrustTier::None => serializer.serialize_i8(0),
                TrustTier::Affirming => serializer.serialize_i8(2),
                TrustTier::Warning => serializer.serialize_i8(32),
                TrustTier::Contraindicated => serializer.serialize_i8(96),
            }
        }
    }
}

impl<'de> Deserialize<'de> for TrustTier {
    fn deserialize<D>(deserializer: D) -> Result<TrustTier, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(TrustTierVisitor)
    }
}

struct TrustTierVisitor;

impl<'de> Visitor<'de> for TrustTierVisitor {
    type Value = TrustTier;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string or an integer between -128 and 127")
    }

    fn visit_i8<E>(self, value: i8) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match value {
            0 => Ok(TrustTier::None),
            2 => Ok(TrustTier::Affirming),
            32 => Ok(TrustTier::Warning),
            96 => Ok(TrustTier::Contraindicated),
            _ => Err(E::custom(format!("Unexpected TrustTier value: {value}"))),
        }
    }

    fn visit_i16<E>(self, value: i16) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value < i16::from(i8::MIN) || value > i16::from(i8::MAX) {
            return Err(E::custom(format!("Unexpected TrustTier value: {value}")));
        }
        self.visit_i8(value as i8)
    }

    fn visit_i32<E>(self, value: i32) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value < i32::from(i8::MIN) || value > i32::from(i8::MAX) {
            return Err(E::custom(format!("Unexpected TrustTier value: {value}")));
        }
        self.visit_i8(value as i8)
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value < i64::from(i8::MIN) || value > i64::from(i8::MAX) {
            return Err(E::custom(format!("Unexpected TrustTier value: {value}")));
        }
        self.visit_i8(value as i8)
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value > u64::try_from(i8::MAX).ok().unwrap() {
            return Err(E::custom(format!("Unexpected TrustTier value: {value}")));
        }
        self.visit_i8(value as i8)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match value {
            "none" => Ok(TrustTier::None),
            "affirming" => Ok(TrustTier::Affirming),
            "warning" => Ok(TrustTier::Warning),
            "contraindicated" => Ok(TrustTier::Contraindicated),
            _ => Err(E::custom(format!("Unexpected TrustTier value: {value}"))),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ciborium::de::Error as CborError;
    use ciborium::{de::from_reader, ser::into_writer};

    #[test]
    fn serde() {
        let tier = TrustTier::Affirming;

        let val = serde_json::to_string(&tier).unwrap();
        assert_eq!(val, "\"affirming\"");

        let tier2: TrustTier = serde_json::from_str(val.as_str()).unwrap();
        assert_eq!(tier, tier2);

        let mut buf: Vec<u8> = Vec::new();
        into_writer(&tier, &mut buf).unwrap();
        assert_eq!(buf, vec![0x2]);

        let tier2: TrustTier = from_reader(buf.as_slice()).unwrap();
        assert_eq!(tier, tier2);

        let buf2: Vec<u8> = vec![0x21];
        let res: Result<TrustTier, CborError<std::io::Error>> = from_reader(buf2.as_slice());
        assert_eq!(
            res.unwrap_err().to_string().as_str(),
            "Semantic(None, \"Unexpected TrustTier value: -2\")"
        );
    }
}
