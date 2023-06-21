// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use serde::{
    de::{self, Deserialize, Visitor},
    ser::{Serialize, SerializeMap},
};

use crate::error::Error;

/// identifies the verifier that produced the EAR
#[derive(Debug, PartialEq)]
pub struct VerifierID {
    /// uniquely identifies the software build running the verifier
    pub build: String,
    /// uniquely identifies the organizational unit responsible for this build
    pub developer: String,
}

impl VerifierID {
    pub fn new() -> VerifierID {
        VerifierID {
            build: "".to_string(),
            developer: "".to_string(),
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.build.as_str() == "" {
            return Err(Error::ValidationError("empty build".to_string()));
        }

        if self.developer.as_str() == "" {
            return Err(Error::ValidationError("empty build".to_string()));
        }

        Ok(())
    }
}

impl Default for VerifierID {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for VerifierID {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(Some(2))?;

        if is_human_readable {
            map.serialize_entry("developer", &self.developer)?;
            map.serialize_entry("build", &self.build)?;
        } else {
            map.serialize_entry(&0, &self.developer)?;
            map.serialize_entry(&1, &self.build)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for VerifierID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let is_hr = deserializer.is_human_readable();

        deserializer.deserialize_map(VerifierIDVisitor {
            is_human_readable: is_hr,
        })
    }
}

struct VerifierIDVisitor {
    pub is_human_readable: bool,
}

impl<'de> Visitor<'de> for VerifierIDVisitor {
    type Value = VerifierID;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a CBOR map or JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut vid = VerifierID::new();

        loop {
            if self.is_human_readable {
                match map.next_key::<&str>()? {
                    Some("developer") => vid.developer = map.next_value::<String>()?,
                    Some("build") => vid.build = map.next_value::<String>()?,
                    Some(s) => return Err(de::Error::custom(Error::InvalidName(s.to_string()))),
                    None => break,
                }
            } else {
                // !is_human_readable
                match map.next_key::<i32>()? {
                    Some(0) => vid.developer = map.next_value::<String>()?,
                    Some(1) => vid.build = map.next_value::<String>()?,
                    Some(x) => return Err(de::Error::custom(Error::InvalidKey(x))),
                    None => break,
                }
            }
        }

        Ok(vid)
    }
}
