// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use serde::{
    de::{self, Deserialize, Visitor},
    ser::{Serialize, SerializeMap, Serializer},
};

use super::claim::*;
use crate::error::Error;

/// The set of trustworthiness claims that may be inserted into an attest result by a verifier
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TrustVector {
    pub instance_identity: TrustClaim,
    pub configuration: TrustClaim,
    pub executables: TrustClaim,
    pub file_system: TrustClaim,
    pub hardware: TrustClaim,
    pub runtime_opaque: TrustClaim,
    pub storage_opaque: TrustClaim,
    pub sourced_data: TrustClaim,
}

impl TrustVector {
    /// Create a new trustworthiness vector with all claims unset
    pub fn new() -> TrustVector {
        TrustVector {
            instance_identity: TrustClaim::try_from("instance-identity").unwrap(),
            configuration: TrustClaim::try_from("configuration").unwrap(),
            executables: TrustClaim::try_from("executables").unwrap(),
            file_system: TrustClaim::try_from("file-system").unwrap(),
            hardware: TrustClaim::try_from("hardware").unwrap(),
            runtime_opaque: TrustClaim::try_from("runtime-opaque").unwrap(),
            storage_opaque: TrustClaim::try_from("storage-opaque").unwrap(),
            sourced_data: TrustClaim::try_from("sourced-data").unwrap(),
        }
    }

    /// Set all claims in the vector to the specified value
    ///
    /// This only meaningful for values that have common meaning across all claims, such as `0i8`.
    pub fn set_all(&mut self, v: i8) {
        self.instance_identity.set(v);
        self.configuration.set(v);
        self.executables.set(v);
        self.file_system.set(v);
        self.hardware.set(v);
        self.runtime_opaque.set(v);
        self.storage_opaque.set(v);
        self.sourced_data.set(v);
    }

    /// Return `true` if any of the claims in the vector have been set, and `false` otherwise
    pub fn any_set(&self) -> bool {
        for claim in self.into_iter() {
            if claim.is_set() {
                return true;
            }
        }

        false
    }

    /// Return a reference to a `TrustClaim` associated with the specified name in this vector
    pub fn by_name(&self, name: &str) -> Result<&TrustClaim, Error> {
        match name {
            "instance-identity" => Ok(&self.instance_identity),
            "configuration" => Ok(&self.configuration),
            "executables" => Ok(&self.executables),
            "file-system" => Ok(&self.file_system),
            "hardware" => Ok(&self.hardware),
            "runtime-opaque" => Ok(&self.runtime_opaque),
            "storage-opaque" => Ok(&self.storage_opaque),
            "sourced-data" => Ok(&self.sourced_data),
            _ => Err(Error::InvalidName(name.to_string())),
        }
    }

    /// Return a mutable reference to a `TrustClaim` associated with the specified name in this
    /// vector
    pub fn mut_by_name(&mut self, name: &str) -> Result<&mut TrustClaim, Error> {
        match name {
            "instance-identity" => Ok(&mut self.instance_identity),
            "configuration" => Ok(&mut self.configuration),
            "executables" => Ok(&mut self.executables),
            "file-system" => Ok(&mut self.file_system),
            "hardware" => Ok(&mut self.hardware),
            "runtime-opaque" => Ok(&mut self.runtime_opaque),
            "storage-opaque" => Ok(&mut self.storage_opaque),
            "sourced-data" => Ok(&mut self.sourced_data),
            _ => Err(Error::InvalidName(name.to_string())),
        }
    }

    /// Return a reference to a `TrustClaim` associated with the specified key in this vector
    pub fn by_key(&self, key: i32) -> Result<&TrustClaim, Error> {
        match key {
            0 => Ok(&self.instance_identity),
            1 => Ok(&self.configuration),
            2 => Ok(&self.executables),
            3 => Ok(&self.file_system),
            4 => Ok(&self.hardware),
            5 => Ok(&self.runtime_opaque),
            6 => Ok(&self.storage_opaque),
            7 => Ok(&self.sourced_data),
            _ => Err(Error::InvalidKey(key)),
        }
    }

    /// Return a mutable reference to a `TrustClaim` associated with the specified key in this
    /// vector
    pub fn mut_by_key(&mut self, key: i32) -> Result<&mut TrustClaim, Error> {
        match key {
            0 => Ok(&mut self.instance_identity),
            1 => Ok(&mut self.configuration),
            2 => Ok(&mut self.executables),
            3 => Ok(&mut self.file_system),
            4 => Ok(&mut self.hardware),
            5 => Ok(&mut self.runtime_opaque),
            6 => Ok(&mut self.storage_opaque),
            7 => Ok(&mut self.sourced_data),
            _ => Err(Error::InvalidKey(key)),
        }
    }
}

impl Default for TrustVector {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoIterator for TrustVector {
    type Item = TrustClaim;
    type IntoIter = TrustVectorIterator;

    fn into_iter(self) -> Self::IntoIter {
        TrustVectorIterator { tv: self, index: 0 }
    }
}

pub struct TrustVectorIterator {
    tv: TrustVector,
    index: i32,
}

impl Iterator for TrustVectorIterator {
    type Item = TrustClaim;

    fn next(&mut self) -> Option<TrustClaim> {
        let result = match self.tv.by_key(self.index) {
            Ok(claim) => claim,
            Err(_) => return None,
        };
        self.index += 1;
        Some(*result)
    }
}

impl Serialize for TrustVector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;
        for claim in self.into_iter() {
            if claim.is_set() {
                if is_human_readable {
                    map.serialize_entry(claim.tag(), &claim.value())?;
                } else {
                    map.serialize_entry(&claim.key(), &claim.value())?;
                }
            }
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for TrustVector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let is_hr = deserializer.is_human_readable();

        deserializer.deserialize_map(TrustVectorVisitor {
            is_human_readable: is_hr,
        })
    }
}

struct TrustVectorVisitor {
    pub is_human_readable: bool,
}

impl<'de> Visitor<'de> for TrustVectorVisitor {
    type Value = TrustVector;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a map of claim tags or keys to their values")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut tv = TrustVector::new();

        loop {
            if self.is_human_readable {
                match access.next_entry::<&str, i8>()? {
                    Some((k, val)) => match tv.mut_by_name(k).map_err(de::Error::custom) {
                        Ok(claim) => claim.set(val),
                        Err(e) => return Err(e),
                    },
                    None => break,
                }
            } else {
                // !is_human_readable
                match access.next_entry::<i32, i8>()? {
                    Some((k, val)) => match tv.mut_by_key(k).map_err(de::Error::custom) {
                        Ok(claim) => claim.set(val),
                        Err(e) => return Err(e),
                    },
                    None => break,
                }
            }
        }

        Ok(tv)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use ciborium::{de::from_reader, ser::into_writer};

    #[test]
    fn iter() {
        let tv = TrustVector::new();
        for (i, claim) in tv.into_iter().enumerate() {
            match i {
                0 => assert_eq!(claim.tag(), "instance-identity"),
                1 => assert_eq!(claim.tag(), "configuration"),
                2 => assert_eq!(claim.tag(), "executables"),
                3 => assert_eq!(claim.tag(), "file-system"),
                4 => assert_eq!(claim.tag(), "hardware"),
                5 => assert_eq!(claim.tag(), "runtime-opaque"),
                6 => assert_eq!(claim.tag(), "storage-opaque"),
                7 => assert_eq!(claim.tag(), "sourced-data"),
                _ => panic!("should not get here"),
            }
        }
    }

    #[test]
    fn serde() {
        let mut tv = TrustVector::new();

        let val = serde_json::to_string(&tv).unwrap();
        assert_eq!(val, "{}");

        tv.executables.set(APPROVED_RUNTIME);

        let val = serde_json::to_string(&tv).unwrap();
        assert_eq!(val, r#"{"executables":2}"#);

        tv.sourced_data.set(NO_CLAIM);

        let val = serde_json::to_string(&tv).unwrap();
        assert_eq!(val, r#"{"executables":2,"sourced-data":0}"#);

        let tv2: TrustVector = serde_json::from_str(val.as_str()).unwrap();
        assert_eq!(tv2.executables, APPROVED_RUNTIME);
        assert_eq!(tv2.sourced_data, NO_CLAIM);
        assert!(!tv2.configuration.is_set());

        tv.executables.unset();

        let val = serde_json::to_string(&tv).unwrap();
        assert_eq!(val, r#"{"sourced-data":0}"#);

        let mut buf: Vec<u8> = Vec::new();
        into_writer(&tv, &mut buf).unwrap();
        assert_eq!(buf, vec![191, 7, 0, 255]);

        let tv2: TrustVector = from_reader(buf.as_slice()).unwrap();
        assert_eq!(tv, tv2);
    }
}
