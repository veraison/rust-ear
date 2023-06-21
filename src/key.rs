// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use crate::base64::Bytes;
use crate::error::Error;
use serde::{
    de::{self, Deserialize, Visitor},
    ser::{Serialize, SerializeMap},
};

/// public key that is being attested
#[derive(Debug, PartialEq)]
pub struct KeyAttestation {
    pub pub_key: Bytes,
}

impl KeyAttestation {
    pub fn new() -> KeyAttestation {
        KeyAttestation {
            pub_key: Bytes::new(),
        }
    }
}

impl Default for KeyAttestation {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for KeyAttestation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("akpub", &self.pub_key)?;
        } else {
            map.serialize_entry(&0, &self.pub_key)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for KeyAttestation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let is_hr = deserializer.is_human_readable();

        deserializer.deserialize_map(KeyAttestationVisitor {
            is_human_readable: is_hr,
        })
    }
}

struct KeyAttestationVisitor {
    pub is_human_readable: bool,
}

impl<'de> Visitor<'de> for KeyAttestationVisitor {
    type Value = KeyAttestation;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a CBOR map or JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut key_attest = KeyAttestation::new();

        loop {
            if self.is_human_readable {
                match map.next_key::<&str>()? {
                    Some("akpub") => key_attest.pub_key = map.next_value::<Bytes>()?,
                    Some(s) => return Err(de::Error::custom(Error::InvalidName(s.to_string()))),
                    None => break,
                }
            } else {
                // !is_human_readable
                match map.next_key::<i32>()? {
                    Some(0) => key_attest.pub_key = map.next_value::<Bytes>()?,
                    Some(x) => return Err(de::Error::custom(Error::InvalidKey(x))),
                    None => break,
                }
            }
        }

        Ok(key_attest)
    }
}
