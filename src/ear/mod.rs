// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{
    de::{self, Deserialize, Visitor},
    ser::{Error as _, Serialize, SerializeMap},
};

use crate::appraisal::Appraisal;
use crate::error::Error;
use crate::extension::{get_profile, ClaimKey, Extensions};
use crate::id::VerifierID;
use crate::nonce::Nonce;
use crate::trust::tier::TrustTier;
use cmw::CMW;

#[cfg(feature = "cose")]
pub mod cose;
#[cfg(feature = "jwt")]
pub mod jwt;

/// EAT profile URI for [draft-ietf-rats-ear-04].
///
/// [draft-ietf-rats-ear-04]: https://datatracker.ietf.org/doc/draft-ietf-rats-ear/
pub const EAR_PROFILE: &str = "tag:ietf.org,2026:rats/ear#04";

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
    /// "Expiration Time" -- the time after which the EAR must not be accepted
    pub exp: Option<i64>,
    /// Identifier of the verifier that created the EAR
    pub vid: VerifierID,
    /// The set of attested environment submodule names and associated Appraisals
    ///
    /// At least one submod must be present (e.g. representing the entire attested environment).
    pub submods: BTreeMap<String, Appraisal>,
    /// A user-supplied nonce echoed by the verifier to provide freshness
    pub nonce: Option<Nonce>,
    /// Overall appraisal status for the composite attester (`ear_status` / 1000)
    ///
    /// When set to anything other than [`TrustTier::None`], it must not be more trustworthy than
    /// the worst status across all submod appraisals; [`Ear::validate`] enforces this. An explicit
    /// [`TrustTier::None`] means the verifier makes no overall claim.
    pub status: Option<TrustTier>,
    /// Raw evidence submitted for appraisal, wrapped in a Record CMW (`ear_raw_evidence` / 1002)
    ///
    /// [draft-ietf-rats-ear-04, Section 3] restricts this claim to `cmw-record`; CMW Collections
    /// are rejected by [`Ear::validate`].
    ///
    /// [draft-ietf-rats-ear-04, Section 3]: https://www.ietf.org/archive/id/draft-ietf-rats-ear-04.html#section-3
    pub raw_evidence: Option<CMW>,
    /// Device attester graph as adjacency lists (`ear_device_topology` / 1007)
    ///
    /// Per [draft-ietf-rats-ear-04, Section 3], attesters are represented by their corresponding
    /// `submods` labels. This implementation enforces the CDDL non-empty constraints, but does not
    /// require topology labels to exist in `submods`.
    ///
    /// [draft-ietf-rats-ear-04, Section 3]: https://www.ietf.org/archive/id/draft-ietf-rats-ear-04.html#section-3
    pub topology: Option<BTreeMap<String, Vec<String>>>,
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
            exp: None,
            vid: VerifierID::new(),
            submods: BTreeMap::new(),
            nonce: None,
            status: None,
            raw_evidence: None,
            topology: None,
            extensions: Extensions::new(),
        }
    }

    /// Create an empty EAR, registering extensions associated with the specified profile
    pub fn new_with_profile(profile: &str) -> Result<Ear, Error> {
        let mut ear = Ear {
            profile: profile.to_string(),
            iat: 0,
            exp: None,
            vid: VerifierID::new(),
            submods: BTreeMap::new(),
            nonce: None,
            status: None,
            raw_evidence: None,
            topology: None,
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

        if let Some(exp) = self.exp {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| Error::ValidationError(format!("system time before epoch: {e}")))?
                .as_secs() as i64;
            if exp <= now {
                return Err(Error::ValidationError("EAR has expired".to_string()));
            }
        }

        self.vid.validate().map_err(|e| {
            let msg = match e {
                Error::ValidationError(s) => s,
                _ => e.to_string(),
            };
            Error::ValidationError(format!("verifier-id: {msg}"))
        })?;

        if let Some(status) = self.status {
            let worst = self.most_severe_submod_status();
            if status != TrustTier::None && status < worst {
                return Err(Error::ValidationError(format!(
                    "status {status} is more trustworthy than the worst submod status {worst}"
                )));
            }
        }

        if self
            .raw_evidence
            .as_ref()
            .is_some_and(|raw_evidence| matches!(raw_evidence, CMW::Collection(_)))
        {
            return Err(Error::ValidationError(
                "ear_raw_evidence must be a Record CMW".to_string(),
            ));
        }

        if let Some(topology) = &self.topology {
            if topology.is_empty() {
                return Err(Error::ValidationError("empty topology".to_string()));
            }

            for (attester, sub_attesters) in topology {
                if sub_attesters.is_empty() {
                    return Err(Error::ValidationError(format!(
                        "topology: no sub-attesters for {attester}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// The status of the least trustworthy appraisal across all submods
    pub fn most_severe_submod_status(&self) -> TrustTier {
        self.submods
            .values()
            .map(|appraisal| appraisal.status)
            .max()
            .unwrap_or(TrustTier::None)
    }

    /// Set the status of each appraisal from its trustworthiness vector, and the overall `status`
    /// from the resulting submod statuses
    pub fn update_status_from_trust_vector(&mut self) {
        for submod in self.submods.values_mut() {
            if submod.status == TrustTier::None {
                submod.update_status_from_trust_vector();
            }
        }

        let worst = self.most_severe_submod_status();
        match self.status {
            // a status that is already at least as severe as the worst submod is left alone, as
            // the verifier may have deliberately set it to a lower tier.
            Some(status) if status >= worst => (),
            _ => self.status = Some(worst),
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
            if let Some(exp) = &self.exp {
                map.serialize_entry("exp", exp)?;
            }
            map.serialize_entry("ear_verifier_id", &self.vid)?;
            map.serialize_entry("submods", &self.submods)?;

            if let Some(s) = &self.status {
                map.serialize_entry("ear_status", s)?;
            }

            if let Some(n) = &self.nonce {
                map.serialize_entry("eat_nonce", n)?
            }

            if let Some(r) = &self.raw_evidence {
                map.serialize_entry("ear_raw_evidence", r)?
            }

            if let Some(t) = &self.topology {
                map.serialize_entry("ear_device_topology", t)?
            }

            self.extensions.serialize_to_map_by_name(&mut map)?;
        } else {
            // !is_human_readable
            map.serialize_entry(&265, &self.profile)?;
            map.serialize_entry(&6, &self.iat)?;
            if let Some(exp) = &self.exp {
                map.serialize_entry(&4, exp)?;
            }
            map.serialize_entry(&1004, &self.vid)?;
            map.serialize_entry(&266, &self.submods)?;

            if let Some(s) = &self.status {
                map.serialize_entry(&1000, s)?;
            }

            if let Some(n) = &self.nonce {
                map.serialize_entry(&10, &n)?
            }

            if let Some(r) = &self.raw_evidence {
                map.serialize_entry(&1002, &r)?
            }

            if let Some(t) = &self.topology {
                map.serialize_entry(&1007, &t)?
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
                    Some("exp") => ear.exp = Some(map.next_value::<i64>()?),
                    Some("ear_verifier_id") => ear.vid = map.next_value::<VerifierID>()?,
                    Some("ear_status") => ear.status = Some(map.next_value::<TrustTier>()?),
                    Some("submods") => {
                        ear.submods = map.next_value::<BTreeMap<String, Appraisal>>()?
                    }
                    Some("eat_nonce") => ear.nonce = Some(map.next_value::<Nonce>()?),
                    Some("ear_raw_evidence") => ear.raw_evidence = Some(map.next_value::<CMW>()?),
                    Some("ear_device_topology") => {
                        ear.topology = Some(map.next_value::<BTreeMap<String, Vec<String>>>()?)
                    }
                    Some(name) => ear.extensions.visit_map_entry_by_name(name, &mut map)?,
                    None => break,
                }
            } else {
                // !is_human_readable
                match map.next_key::<ClaimKey>()? {
                    Some(ClaimKey::Integer(265)) => ear.profile = map.next_value::<String>()?,
                    Some(ClaimKey::Integer(6)) => ear.iat = map.next_value::<i64>()?,
                    Some(ClaimKey::Integer(4)) => ear.exp = Some(map.next_value::<i64>()?),
                    Some(ClaimKey::Integer(1004)) => ear.vid = map.next_value::<VerifierID>()?,
                    Some(ClaimKey::Integer(1000)) => {
                        ear.status = Some(map.next_value::<TrustTier>()?)
                    }
                    Some(ClaimKey::Integer(266)) => {
                        ear.submods = map.next_value::<BTreeMap<String, Appraisal>>()?
                    }
                    Some(ClaimKey::Integer(10)) => ear.nonce = Some(map.next_value::<Nonce>()?),
                    Some(ClaimKey::Integer(1002)) => {
                        ear.raw_evidence = Some(map.next_value::<CMW>()?)
                    }
                    Some(ClaimKey::Integer(1007)) => {
                        ear.topology = Some(map.next_value::<BTreeMap<String, Vec<String>>>()?)
                    }
                    Some(ClaimKey::Integer(key)) => {
                        ear.extensions.visit_map_entry_by_cbor_key(key, &mut map)?
                    }
                    Some(ClaimKey::Unsigned(key)) => ear
                        .extensions
                        .ignore_map_entry_by_unsigned_cbor_key(key, &mut map)?,
                    Some(ClaimKey::Name(name)) => {
                        ear.extensions.visit_map_entry_by_name(&name, &mut map)?
                    }
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
    use crate::claim;
    use crate::extension::*;
    use crate::raw::{RawValue, RawValueKind};
    use ciborium::value::{Integer, Value};
    use ciborium::{de::from_reader, ser::into_writer};

    const EAR_STRING: &str = r#"
    {
        "eat_profile":"tag:ietf.org,2026:rats/ear#04",
        "iat":1666529184,
        "ear_verifier_id":{
            "build":"vsts 0.0.1",
            "developer":"https://veraison-project.org"
        },
        "submods":{
            "test": {"ear_status": "none"}
        },
        "ear_raw_evidence":[
            "application/vnd.evidence",
            "NzQ3MjY5NzM2NTYzNzQK"
        ]
    }
    "#;

    const EAR_WITH_EXTENSIONS_STRING: &str = r#"
    {
        "eat_profile":"tag:ietf.org,2026:rats/ear#04",
        "iat":1666529184,
        "ear_verifier_id":{
            "build":"vsts 0.0.1",
            "developer":"https://veraison-project.org"
        },
        "submods":{
            "test": {
                "ear_status": "none",
                "ext3": "3q2-7w"
            }
        },
        "ear_raw_evidence":[
            "application/vnd.evidence",
            "NzQ3MjY5NzM2NTYzNzQK"
        ],
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
    fn deserialize_draft_figure3_json() {
        const DRAFT_EXAMPLE: &str = r#"{
            "eat_profile": "tag:ietf.org,2026:rats/ear#04",
            "iat": 1666529184,
            "ear_verifier_id": {
                "developer": "https://veraison-project.org",
                "build": "vts 0.0.1"
            },
            "ear_raw_evidence": [
                "application/vnd.evidence",
                "NzQ3MjY5NzM2NTYzNzQK"
            ],
            "submods": {
                "PSA": {
                    "ear_status": "contraindicated",
                    "ear_trustworthiness_vector": {
                        "instance-identity": 2,
                        "executables": 96,
                        "hardware": 2
                    },
                    "ear_appraisal_policy_ids": [
                        "https://veraison.example/policy/1/60a0068d"
                    ]
                }
            }
        }"#;

        let ear: Ear = serde_json::from_str(DRAFT_EXAMPLE).unwrap();
        assert_eq!(ear.profile, EAR_PROFILE);
        assert_eq!(ear.iat, 1666529184);
        assert_eq!(ear.vid.developer, "https://veraison-project.org");
        assert_eq!(ear.vid.build, "vts 0.0.1");
        let raw_evidence = ear.raw_evidence.as_ref().unwrap().to_json_value().unwrap();
        let arr = raw_evidence.as_array().expect("record CMW is a JSON array");
        assert_eq!(arr[0].as_str().unwrap(), "application/vnd.evidence");

        let psa = ear.submods.get("PSA").unwrap();
        assert_eq!(psa.status.to_string(), "contraindicated");
        assert_eq!(psa.policy_ids.len(), 1);
    }

    #[test]
    fn deserialize_draft_figure4_composite_json() {
        const DRAFT_EXAMPLE: &str = r#"{
            "eat_profile": "tag:ietf.org,2026:rats/ear#04",
            "iat": 1666529300,
            "ear_verifier_id": {
                "developer": "https://veraison-project.org",
                "build": "vts 0.0.1"
            },
            "ear_raw_evidence": [
                "application/vnd.evidence",
                "NzQ3MjY5NzM2NTYzNzQKNzQ3MjY5NzM2NTYzNzQK"
            ],
            "submods": {
                "CCA Platform": {
                    "ear_status": "affirming",
                    "ear_trustworthiness_vector": {
                        "instance-identity": 2,
                        "executables": 2,
                        "hardware": 2
                    },
                    "ear_appraisal_policy_ids": [
                        "https://veraison.example/policy/1/60a0068d"
                    ]
                },
                "CCA Realm": {
                    "ear_status": "affirming",
                    "ear_trustworthiness_vector": {
                        "instance-identity": 2
                    },
                    "ear_appraisal_policy_ids": [
                        "https://veraison.example/policy/1/60a0068d"
                    ]
                }
            }
        }"#;

        let ear: Ear = serde_json::from_str(DRAFT_EXAMPLE).unwrap();
        assert_eq!(ear.profile, EAR_PROFILE);
        assert_eq!(ear.submods.len(), 2);

        let platform = ear.submods.get("CCA Platform").unwrap();
        assert_eq!(platform.status, TrustTier::Affirming);
        assert_eq!(platform.trust_vector.executables, 2i8);
        assert_eq!(platform.trust_vector.hardware, 2i8);

        let realm = ear.submods.get("CCA Realm").unwrap();
        assert_eq!(realm.status, TrustTier::Affirming);
        assert_eq!(realm.trust_vector.instance_identity, 2i8);
        assert_eq!(realm.trust_vector.executables, 0i8);

        assert_eq!(ear.most_severe_submod_status(), TrustTier::Affirming);
    }

    #[test]
    fn status_and_topology_serde() {
        const EAR_WITH_STATUS_AND_TOPOLOGY: &str = r#"
        {
            "eat_profile":"tag:ietf.org,2026:rats/ear#04",
            "iat":1666529184,
            "ear_verifier_id":{
                "build":"vsts 0.0.1",
                "developer":"https://veraison-project.org"
            },
            "ear_status":"warning",
            "submods":{
                "CCA Platform": {"ear_status": "warning"},
                "CCA Realm": {"ear_status": "affirming"}
            },
            "ear_device_topology":{
                "CCA Platform": ["CCA Realm"]
            }
        }
        "#;

        let ear = serde_json::from_str::<Ear>(EAR_WITH_STATUS_AND_TOPOLOGY).unwrap();
        assert_eq!(ear.status, Some(TrustTier::Warning));
        assert_eq!(
            ear.topology,
            Some(BTreeMap::from([(
                "CCA Platform".to_string(),
                vec!["CCA Realm".to_string()]
            )])),
        );

        let text = serde_json::to_string(&ear).unwrap();
        assert_eq!(
            text.parse::<serde_json::Value>().unwrap(),
            EAR_WITH_STATUS_AND_TOPOLOGY
                .parse::<serde_json::Value>()
                .unwrap(),
        );

        let mut buf: Vec<u8> = Vec::new();
        into_writer(&ear, &mut buf).unwrap();

        let entries = match from_reader::<Value, _>(buf.as_slice()).unwrap() {
            Value::Map(entries) => entries,
            other => panic!("expected a CBOR map, got {other:?}"),
        };
        let claim_value = |key: i32| {
            entries
                .iter()
                .find(|(k, _)| *k == Value::Integer(Integer::from(key)))
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("map must contain claim key {key}"))
        };
        assert_eq!(claim_value(1000), Value::Integer(Integer::from(32)));
        assert_eq!(
            claim_value(1007),
            Value::Map(vec![(
                Value::Text("CCA Platform".to_string()),
                Value::Array(vec![Value::Text("CCA Realm".to_string())]),
            )]),
        );

        let ear2: Ear = from_reader(buf.as_slice()).unwrap();
        assert_eq!(ear, ear2);
    }

    #[test]
    fn update_status_from_trust_vector_sets_overall_status() {
        let mut warning = Appraisal::new();
        warning.trust_vector.configuration.set(claim::UNSAFE_CONFIG);

        let mut affirming = Appraisal::new();
        affirming
            .trust_vector
            .instance_identity
            .set(claim::TRUSTWORTHY_INSTANCE);

        let mut ear = Ear::new();
        ear.profile = EAR_PROFILE.to_string();
        ear.vid.build = "vsts 0.0.1".to_string();
        ear.vid.developer = "https://veraison-project.org".to_string();
        ear.submods.insert("warning".to_string(), warning);
        ear.submods.insert("affirming".to_string(), affirming);

        ear.update_status_from_trust_vector();

        assert_eq!(ear.submods["warning"].status, TrustTier::Warning);
        assert_eq!(ear.submods["affirming"].status, TrustTier::Affirming);
        assert_eq!(ear.status, Some(TrustTier::Warning));
        ear.validate().unwrap();

        // a status that is already less trustworthy than the worst submod is preserved
        ear.status = Some(TrustTier::Contraindicated);
        ear.update_status_from_trust_vector();
        assert_eq!(ear.status, Some(TrustTier::Contraindicated));
    }

    #[test]
    fn validate_rejects_overly_trustworthy_status() {
        let mut contraindicated = Appraisal::new();
        contraindicated.status = TrustTier::Contraindicated;

        let mut ear = Ear::new();
        ear.profile = EAR_PROFILE.to_string();
        ear.vid.build = "vsts 0.0.1".to_string();
        ear.vid.developer = "https://veraison-project.org".to_string();
        ear.submods.insert("PSA".to_string(), contraindicated);
        ear.status = Some(TrustTier::Affirming);

        let err = ear.validate().unwrap_err();
        assert_eq!(
            err.to_string(),
            "validation error: status affirming is more trustworthy than \
             the worst submod status contraindicated"
        );
        assert!(serde_json::to_string(&ear).is_err());

        // no overall claim is being made, so there is nothing to contradict
        ear.status = Some(TrustTier::None);
        ear.validate().unwrap();
    }

    #[test]
    fn validate_rejects_degenerate_topology() {
        let mut ear = Ear::new();
        ear.profile = EAR_PROFILE.to_string();
        ear.vid.build = "vsts 0.0.1".to_string();
        ear.vid.developer = "https://veraison-project.org".to_string();
        ear.submods
            .insert("CCA Platform".to_string(), Appraisal::new());

        ear.topology = Some(BTreeMap::new());
        assert_eq!(
            ear.validate().unwrap_err().to_string(),
            "validation error: empty topology"
        );

        ear.topology = Some(BTreeMap::from([("CCA Platform".to_string(), Vec::new())]));
        assert_eq!(
            ear.validate().unwrap_err().to_string(),
            "validation error: topology: no sub-attesters for CCA Platform"
        );
    }

    #[test]
    fn validate_rejects_raw_evidence_collection() {
        let mut ear = Ear::new();
        ear.profile = EAR_PROFILE.to_string();
        ear.vid.build = "vsts 0.0.1".to_string();
        ear.vid.developer = "https://veraison-project.org".to_string();
        ear.submods.insert("test".to_string(), Appraisal::new());
        ear.raw_evidence = Some(
            CMW::from_json_value(&serde_json::json!({
                "evidence": [
                    "application/vnd.evidence",
                    "NzQ3MjY5NzM2NTYzNzQK"
                ]
            }))
            .unwrap(),
        );

        assert_eq!(
            ear.validate().unwrap_err().to_string(),
            "validation error: ear_raw_evidence must be a Record CMW"
        );
        assert!(serde_json::to_string(&ear).is_err());
    }

    #[test]
    fn cbor_unknown_text_claim_is_ignored_and_cached() {
        let mut ear = Ear::new();
        ear.profile = EAR_PROFILE.to_string();
        ear.vid.build = "vsts 0.0.1".to_string();
        ear.vid.developer = "https://veraison-project.org".to_string();
        ear.submods.insert("test".to_string(), Appraisal::new());

        let mut encoded = Vec::new();
        into_writer(&ear, &mut encoded).unwrap();
        let Value::Map(mut entries) = from_reader::<Value, _>(encoded.as_slice()).unwrap() else {
            panic!("expected a CBOR map");
        };
        entries.push((
            Value::Text("future_claim".to_string()),
            Value::Integer(Integer::from(42)),
        ));
        entries.push((
            Value::Integer(Integer::from(u64::MAX)),
            Value::Text("ignored".to_string()),
        ));

        encoded.clear();
        into_writer(&Value::Map(entries), &mut encoded).unwrap();
        let mut decoded = from_reader::<Ear, _>(encoded.as_slice()).unwrap();
        decoded
            .extensions
            .register("future_claim", -65537, RawValueKind::Integer)
            .unwrap();
        assert_eq!(
            decoded.extensions.get_by_name("future_claim"),
            Some(RawValue::Integer(42))
        );
    }

    #[test]
    fn expiration_serde_and_validation() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut ear = Ear::new();
        ear.profile = EAR_PROFILE.to_string();
        ear.exp = Some(now + 3600);
        ear.vid.build = "vsts 0.0.1".to_string();
        ear.vid.developer = "https://veraison-project.org".to_string();
        ear.submods.insert("test".to_string(), Appraisal::new());

        let text = serde_json::to_string(&ear).unwrap();
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(json["exp"], now + 3600);
        assert_eq!(serde_json::from_str::<Ear>(&text).unwrap().exp, ear.exp);

        let mut buf = Vec::new();
        into_writer(&ear, &mut buf).unwrap();
        let Value::Map(entries) = from_reader::<Value, _>(buf.as_slice()).unwrap() else {
            panic!("expected a CBOR map");
        };
        assert!(entries.iter().any(|(key, value)| {
            *key == Value::Integer(Integer::from(4))
                && *value == Value::Integer(Integer::from(now + 3600))
        }));
        assert_eq!(from_reader::<Ear, _>(buf.as_slice()).unwrap().exp, ear.exp);

        ear.exp = Some(now);
        assert_eq!(
            ear.validate().unwrap_err().to_string(),
            "validation error: EAR has expired"
        );
    }

    #[test]
    fn serde() {
        let ear = Ear {
            profile: EAR_PROFILE.to_string(),
            iat: 1666529184,
            exp: None,
            vid: VerifierID {
                build: "vsts 0.0.1".to_string(),
                developer: "https://veraison-project.org".to_string(),
            },
            raw_evidence: Some(
                CMW::from_json_value(&serde_json::json!([
                    "application/vnd.evidence",
                    "NzQ3MjY5NzM2NTYzNzQK"
                ]))
                .unwrap(),
            ),
            nonce: None,
            status: None,
            topology: None,
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
        let ear2: Ear = from_reader(buf.as_slice()).unwrap();
        assert_eq!(ear.profile, ear2.profile);
        assert_eq!(ear.iat, ear2.iat);
        assert_eq!(ear.vid.build, ear2.vid.build);
        assert_eq!(ear.vid.developer, ear2.vid.developer);
        assert_eq!(ear.raw_evidence, ear2.raw_evidence);

        let ear2: Ear = serde_json::from_str(EAR_STRING).unwrap();
        assert_eq!(ear.profile, ear2.profile);
        assert_eq!(ear.iat, ear2.iat);
        assert_eq!(ear.vid.build, ear2.vid.build);
        assert_eq!(ear.vid.developer, ear2.vid.developer);
        assert_eq!(ear.raw_evidence, ear2.raw_evidence);
    }

    #[test]
    fn serde_extensions() {
        let mut profile = Profile::new(EAR_PROFILE);
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
        let ear2: Ear = from_reader(buf.as_slice()).unwrap();
        assert_eq!(ear, ear2);
    }
}
