// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{
    de::{self, Deserialize, Visitor},
    ser::{Error as _, Serialize, SerializeMap},
};

use crate::appraisal::Appraisal;
use crate::base64::Bytes;
use crate::error::Error;
use crate::extension::{get_profile, Extensions};
use crate::id::VerifierID;
use crate::nonce::Nonce;
use crate::trust::tier::TrustTier;

#[cfg(feature = "cose")]
pub mod cose;
#[cfg(feature = "jwt")]
pub mod jwt;

/// An EAT Attestation Result
///
/// One or more appraisals associated with meta-data about the verifier and the attestation
/// request.
#[derive(Debug, PartialEq)]
pub struct Ear {
    /// The EAT profile of the associated claim-set
    ///
    /// See <https://datatracker.ietf.org/doc/html/draft-ietf-rats-eat-19#name-eat_profile-eat-profile-cla>
    pub profile: String,
    /// "Issued At" -- the time at which the EAR is issued
    ///
    /// See:
    /// - <https://datatracker.ietf.org/doc/html/draft-ietf-rats-eat-19#section-4.3.1>
    /// - <https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6>
    pub iat: i64,
    /// Identifier of the verifier that created the EAR
    pub vid: VerifierID,
    /// The set of attested environment submodule names and associated Appraisals
    ///
    /// At least one submod must be present (e.g. representing the entire attested environment).
    pub submods: BTreeMap<String, Appraisal>,
    /// A use-supplied nonce echoed by the verifier to provide freshness
    pub nonce: Option<Nonce>,
    /// Raw encoded evidence received by the verifier
    pub raw_evidence: Option<Bytes>,
    /// extension claims
    pub extensions: Extensions,
}

impl Ear {
    /// Create an empty EAR
    pub fn new() -> Ear {
        Ear {
            profile: "".to_string(),
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            vid: VerifierID::new(),
            submods: BTreeMap::new(),
            nonce: None,
            raw_evidence: None,
            extensions: Extensions::new(),
        }
    }

    /// Create an empty EAR, registering extensions associated with the specified profile
    pub fn new_with_profile(profile: &str) -> Result<Ear, Error> {
        let mut ear = Ear {
            profile: profile.to_string(),
            iat: 0,
            vid: VerifierID::new(),
            submods: BTreeMap::new(),
            nonce: None,
            raw_evidence: None,
            extensions: Extensions::new(),
        };

        match get_profile(&ear.profile) {
            Some(profile) => {
                profile.populate_ear_extensions(&mut ear)?;
                Ok(ear)
            }
            None => Err(Error::ProfileError(format!("{profile} is not registered"))),
        }
    }

    /// Ensure that the EAR is valid
    pub fn validate(&self) -> Result<(), Error> {
        if self.profile.as_str() == "" {
            return Err(Error::ValidationError("empty profile".to_string()));
        }

        if self.submods.is_empty() {
            return Err(Error::ValidationError("empty submods".to_string()));
        }

        // do we want to have stronger validation here? e.g. checking that iat is not in the future
        // or impossibly distant past.
        if self.iat == 0 {
            return Err(Error::ValidationError("iat unset".to_string()));
        }

        self.vid.validate().map_err(|e| {
            let msg = match e {
                Error::ValidationError(s) => s,
                _ => e.to_string(),
            };
            Error::ValidationError(format!("verifier-id: {msg}"))
        })?;

        Ok(())
    }

    pub fn update_status_from_trust_vector(&mut self) {
        for submod in self.submods.values_mut() {
            if submod.status == TrustTier::None {
                submod.update_status_from_trust_vector();
            }
        }
    }
}

impl Default for Ear {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for Ear {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(S::Error::custom)?;

        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            map.serialize_entry("eat_profile", &self.profile)?;
            map.serialize_entry("iat", &self.iat)?;
            map.serialize_entry("ear.verifier-id", &self.vid)?;
            map.serialize_entry("submods", &self.submods)?;

            if let Some(n) = &self.nonce {
                map.serialize_entry("eat_nonce", &n)?
            }

            if let Some(r) = &self.raw_evidence {
                map.serialize_entry("ear.raw-evidence", &r)?
            }

            self.extensions.serialize_to_map_by_name(&mut map)?;
        } else {
            // !is_human_readable
            map.serialize_entry(&265, &self.profile)?;
            map.serialize_entry(&6, &self.iat)?;
            map.serialize_entry(&1004, &self.vid)?;
            map.serialize_entry(&266, &self.submods)?;

            if let Some(n) = &self.nonce {
                map.serialize_entry(&10, &n)?
            }

            if let Some(r) = &self.raw_evidence {
                map.serialize_entry(&1002, &r)?
            }

            self.extensions.serialize_to_map_by_key(&mut map)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for Ear {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let is_hr = deserializer.is_human_readable();

        deserializer.deserialize_map(EarVisitor {
            is_human_readable: is_hr,
        })
    }
}

struct EarVisitor {
    pub is_human_readable: bool,
}

impl<'de> Visitor<'de> for EarVisitor {
    type Value = Ear;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a CBOR map or JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut ear = Ear::new();

        loop {
            if self.is_human_readable {
                match map.next_key::<&str>()? {
                    Some("eat_profile") => ear.profile = map.next_value::<String>()?,
                    Some("iat") => ear.iat = map.next_value::<i64>()?,
                    Some("ear.verifier-id") => ear.vid = map.next_value::<VerifierID>()?,
                    Some("submods") => {
                        ear.submods = map.next_value::<BTreeMap<String, Appraisal>>()?
                    }
                    Some("eat_nonce") => ear.nonce = Some(map.next_value::<Nonce>()?),
                    Some("ear.raw-evidence") => ear.raw_evidence = Some(map.next_value::<Bytes>()?),
                    Some(name) => ear.extensions.visit_map_entry_by_name(name, &mut map)?,
                    None => break,
                }
            } else {
                // !is_human_readable
                match map.next_key::<i32>()? {
                    Some(265) => ear.profile = map.next_value::<String>()?,
                    Some(6) => ear.iat = map.next_value::<i64>()?,
                    Some(1004) => ear.vid = map.next_value::<VerifierID>()?,
                    Some(266) => ear.submods = map.next_value::<BTreeMap<String, Appraisal>>()?,
                    Some(10) => ear.nonce = Some(map.next_value::<Nonce>()?),
                    Some(1002) => ear.raw_evidence = Some(map.next_value::<Bytes>()?),
                    Some(key) => ear.extensions.visit_map_entry_by_key(key, &mut map)?,
                    None => break,
                }
            }
        }

        if let Some(profile) = get_profile(&ear.profile) {
            profile
                .populate_ear_extensions(&mut ear)
                .map_err(de::Error::custom)?
        }

        ear.validate().map_err(de::Error::custom)?;

        Ok(ear)
    }
}

#[cfg(test)]
#[rustfmt::skip::macros(vec)]
pub mod test {
    use super::*;
    use crate::extension::*;
    use crate::raw::{RawValue, RawValueKind};
    use ciborium::{de::from_reader, ser::into_writer};

    const EAR_STRING: &str = r#"
    {
        "eat_profile":"tag:github.com,2023:veraison/ear",
        "iat":1666529184,
        "ear.verifier-id":{
            "build":"vsts 0.0.1",
            "developer":"https://veraison-project.org"
        },
        "submods":{
            "test": {"ear.status": "none"}
        },
        "ear.raw-evidence":"NzQ3MjY5NzM2NTYzNzQK"
    }
    "#;

    const EAR_WITH_EXTENSIONS_STRING: &str = r#"
    {
        "eat_profile":"tag:github.com,2023:veraison/ear",
        "iat":1666529184,
        "ear.verifier-id":{
            "build":"vsts 0.0.1",
            "developer":"https://veraison-project.org"
        },
        "submods":{
            "test": {
                "ear.status": "none",
                "ext3": "3q2-7w"
            }
        },
        "ear.raw-evidence":"NzQ3MjY5NzM2NTYzNzQK",
        "ext1": "foo",
        "ext2": 42
    }
    "#;

    #[cfg(any(feature = "cose", feature = "jwt"))]
    pub const SIGNING_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPp4XZRnRHSMhGg0t
6yjQCRV35J4TUY4idLgiCu6EyLqhRANCAAQbx8C533c2AKDwL/RtjVipVnnM2WRv
5w2wZNCJrubSK0StYKJ71CikDgkhw8M90ojfRIowqpl0uLA3kW3PEZy9
-----END PRIVATE KEY-----
";
    #[cfg(any(feature = "cose", feature = "jwt"))]
    pub const VERIF_KEY: &str = r#"
    {
        "kty":"EC",
        "crv":"P-256",
        "x":"G8fAud93NgCg8C_0bY1YqVZ5zNlkb-cNsGTQia7m0is",
        "y":"RK1gonvUKKQOCSHDwz3SiN9EijCqmXS4sDeRbc8RnL0"
    }
    "#;

    #[test]
    fn serde() {
        let ear = Ear {
            profile: "tag:github.com,2023:veraison/ear".to_string(),
            iat: 1666529184,
            vid: VerifierID {
                build: "vsts 0.0.1".to_string(),
                developer: "https://veraison-project.org".to_string(),
            },
            raw_evidence: Some(Bytes::from(
                vec![
                    0x37, 0x34, 0x37, 0x32, 0x36, 0x39, 0x37, 0x33, 0x36, 0x35, 0x36, 0x33, 0x37,
                    0x34, 0x0a,
                ]
                .as_slice(),
            )),
            nonce: None,
            submods: BTreeMap::from([("test".to_string(), Appraisal::new())]),
            extensions: Extensions::new(),
        };

        let val = serde_json::to_string(&ear).unwrap();
        assert_eq!(
            val.parse::<serde_json::Value>().unwrap(),
            EAR_STRING.parse::<serde_json::Value>().unwrap(),
        );

        let mut buf: Vec<u8> = Vec::new();
        into_writer(&ear, &mut buf).unwrap();
        assert_eq!(
            buf,
            vec![
                0xbf, // map (indefinite length)
                  0x19, // unsigned int in the next 2 bytes
                    0x01, 0x09, // 265
                  0x78, 0x20, // text string (32)
                    0x74, 0x61, 0x67, 0x3a, 0x67, 0x69, 0x74, 0x68, // "tag:gith"
                    0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2c, 0x32, // "ub.com,2"
                    0x30, 0x32, 0x33, 0x3a, 0x76, 0x65, 0x72, 0x61, // "023:vera"
                    0x69, 0x73, 0x6f, 0x6e, 0x2f, 0x65, 0x61, 0x72, // "ison/ear"
                  0x06, // 6
                  0x1a, // unsigned int in the next 4 bytes
                    0x63, 0x55, 0x37, 0xa0, // 1666529184
                  0x19, // unsigned int in the next 2 bytes
                    0x3, 0xec, // 1004
                  0xa2, // map (2)
                    0x00, // 0
                    0x78, 0x1c, // text string (28)
                      0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, // "https://"
                      0x76, 0x65, 0x72, 0x61, 0x69, 0x73, 0x6f, 0x6e, // "veraison"
                      0x2d, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, // "-project"
                      0x2e, 0x6f, 0x72, 0x67, // ".org"
                    0x01, // 1
                    0x6a, // text string (10)
                      0x76, 0x73, 0x74, 0x73, 0x20, 0x30, 0x2e, 0x30, // "vsts 0.0"
                      0x2e, 0x31, // ".1"
                  0x19, // unsigned int in the next 2 bytes
                    0x01, 0x0a, // 266
                  0xa1, // map (1)
                    0x64, //  text string (4)
                      0x74, 0x65, 0x73, 0x74, // "test"
                    0xbf, // map (indefinite length)
                      0x19, // unsigned int in the next 2 bytes
                        0x03, 0xe8, // 1000
                      0x00, // 0
                    0xff, // break / end indefinite map
                  0x19, // unsigned int in the next 2 bytes
                    0x03, 0xea, // 1002
                  0x4f, // byte string (15)
                    0x37, 0x34, 0x37, 0x32, 0x36, 0x39, 0x37, 0x33,
                    0x36, 0x35, 0x36, 0x33, 0x37, 0x34, 0x0a,
                0xff, // break / end indefinite map
            ]
        );

        let ear2: Ear = serde_json::from_str(EAR_STRING).unwrap();
        assert_eq!(ear.profile, ear2.profile);
        assert_eq!(ear.iat, ear2.iat);
        assert_eq!(ear.vid.build, ear2.vid.build);
        assert_eq!(ear.vid.developer, ear2.vid.developer);
        assert_eq!(ear.raw_evidence, ear2.raw_evidence);

        let ear2: Ear = from_reader(buf.as_slice()).unwrap();
        assert_eq!(ear.profile, ear2.profile);
        assert_eq!(ear.iat, ear2.iat);
        assert_eq!(ear.vid.build, ear2.vid.build);
        assert_eq!(ear.vid.developer, ear2.vid.developer);
        assert_eq!(ear.raw_evidence, ear2.raw_evidence);
    }

    #[test]
    fn serde_extensions() {
        let mut profile = Profile::new("tag:github.com,2023:veraison/ear");
        profile
            .register_ear_extension("ext1", -1, RawValueKind::String)
            .unwrap();
        profile
            .register_ear_extension("ext2", -2, RawValueKind::Integer)
            .unwrap();
        profile
            .register_appraisal_extension("ext3", -1, RawValueKind::Bytes)
            .unwrap();
        register_profile(&profile).unwrap();

        let ear = serde_json::from_str::<Ear>(EAR_WITH_EXTENSIONS_STRING).unwrap();

        let v1 = ear.extensions.get_by_name("ext1").unwrap();
        assert_eq!(v1, RawValue::String("foo".to_string()));

        let text = serde_json::to_string(&ear).unwrap();
        assert_eq!(
            text.parse::<serde_json::Value>().unwrap(),
            EAR_WITH_EXTENSIONS_STRING
                .parse::<serde_json::Value>()
                .unwrap(),
        );

        let mut buf: Vec<u8> = Vec::new();
        into_writer(&ear, &mut buf).unwrap();
        assert_eq!(
            buf,
            vec![
                0xbf, // map (indefinite length)
                  0x19, // unsigned int in the next 2 bytes
                    0x01, 0x09, // 265
                  0x78, 0x20, // text string (32)
                    0x74, 0x61, 0x67, 0x3a, 0x67, 0x69, 0x74, 0x68, // "tag:gith"
                    0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2c, 0x32, // "ub.com,2"
                    0x30, 0x32, 0x33, 0x3a, 0x76, 0x65, 0x72, 0x61, // "023:vera"
                    0x69, 0x73, 0x6f, 0x6e, 0x2f, 0x65, 0x61, 0x72, // "ison/ear"
                  0x06, // 6
                  0x1a, // unsigned int in the next 4 bytes
                    0x63, 0x55, 0x37, 0xa0, // 1666529184
                  0x19, // unsigned int in the next 2 bytes
                    0x3, 0xec, // 1004
                  0xa2, // map (2)
                    0x00, // 0
                    0x78, 0x1c, // text string (28)
                      0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, // "https://"
                      0x76, 0x65, 0x72, 0x61, 0x69, 0x73, 0x6f, 0x6e, // "veraison"
                      0x2d, 0x70, 0x72, 0x6f, 0x6a, 0x65, 0x63, 0x74, // "-project"
                      0x2e, 0x6f, 0x72, 0x67, // ".org"
                    0x01, // 1
                    0x6a, // text string (10)
                      0x76, 0x73, 0x74, 0x73, 0x20, 0x30, 0x2e, 0x30, // "vsts 0.0"
                      0x2e, 0x31, // ".1"
                  0x19, // unsigned int in the next 2 bytes
                    0x01, 0x0a, // 266
                  0xa1, // map (1)
                    0x64, //  text string (4)
                      0x74, 0x65, 0x73, 0x74, // "test"
                    0xbf, // map (indefinite length)
                      0x19, // unsigned int in the next 2 bytes
                        0x03, 0xe8, // 1000
                      0x00, // 0
                      0x20, // -1
                      0x44, // byte string (3)
                        0xde, 0xad, 0xbe, 0xef,
                    0xff, // break / end indefinite map
                  0x19, // unsigned int in the next 2 bytes
                    0x03, 0xea, // 1002
                  0x4f, // byte string (15)
                    0x37, 0x34, 0x37, 0x32, 0x36, 0x39, 0x37, 0x33,
                    0x36, 0x35, 0x36, 0x33, 0x37, 0x34, 0x0a,
                  0x21, // -2
                  0x18, // unsigned int next byte
                    0x2a, // 42
                  0x20, // -1
                  0x63, // text string (3)
                    0x66, 0x6f, 0x6f, // "foo"
                0xff, // break / end indefinite map
            ]
        );

        let ear2: Ear = from_reader(buf.as_slice()).unwrap();
        assert_eq!(ear, ear2);
    }
}
