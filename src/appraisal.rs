// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, fmt};

use serde::{
    de::{self, Deserialize, Visitor},
    ser::{Serialize, SerializeMap},
};

use crate::extension::ClaimKey;
use crate::{
    get_profile, Error, Extensions, KeyAttestation, Nonce, RawValue, TrustTier, TrustVector,
};

/// An appraisal created by a verifier of the evidence provided by an attester
#[derive(Debug, PartialEq)]
pub struct Appraisal {
    /// The EAT profile of this appraisal claims-set (`eat_profile` / 265)
    ///
    /// Note that submods of the same EAR may each have a different profile.
    pub profile: Option<String>,
    /// The overall status of the appraisal represented by an AR4SI trustworthiness tier
    ///
    /// This is typically the lowest tier of all the claims that have been made (whose values have
    /// been set), though a verifier may choose to set it to a lower value.
    pub status: TrustTier,
    /// Contains the trustworthiness claims made in the appraisal
    ///
    /// When present on the wire, [draft-ietf-rats-ear-04 Appendix A] requires this map to be
    /// non-empty.
    ///
    /// [draft-ietf-rats-ear-04 Appendix A]: https://www.ietf.org/archive/id/draft-ietf-rats-ear-04.html#appendix-A
    pub trust_vector: TrustVector,
    /// Identifiers of the policies applied by the verifier (`ear_appraisal_policy_ids` / 1003)
    ///
    /// [draft-ietf-rats-ear-04, Section 3.1] requires a present list to be non-empty.
    ///
    /// [draft-ietf-rats-ear-04, Section 3.1]: https://www.ietf.org/archive/id/draft-ietf-rats-ear-04.html#section-3.1
    pub policy_ids: Vec<String>,
    /// The nonce extracted from the evidence this appraisal is based on (`eat_nonce` / 10)
    ///
    /// This reflects the freshness of the appraised evidence, and is distinct from the nonce of
    /// the enclosing [`crate::Ear`], which reflects the freshness of the attestation result.
    pub nonce: Option<Nonce>,
    /// Claims with Attester authority extracted from the appraised evidence (`ear_attester_claims` / 1005)
    ///
    /// [Appendix A] requires a present claims map to be non-empty.
    ///
    /// TODO(draft-04): [Appendix A] permits integer keys in CBOR claims maps. The public API
    /// intentionally uses strings for JSON/CBOR interoperability in this release.
    ///
    /// [Appendix A]: https://www.ietf.org/archive/id/draft-ietf-rats-ear-04.html#appendix-A
    pub attester_claims: BTreeMap<String, RawValue>,
    /// Claims with Verifier authority added during appraisal (`ear_verifier_claims` / 1006)
    ///
    /// [Appendix A] requires a present claims map to be non-empty.
    ///
    /// TODO(draft-04): [Appendix A] permits integer keys in CBOR claims maps. The public API
    /// intentionally uses strings for JSON/CBOR interoperability in this release.
    ///
    /// [Appendix A]: https://www.ietf.org/archive/id/draft-ietf-rats-ear-04.html#appendix-A
    pub verifier_claims: BTreeMap<String, RawValue>,
    /// Public key attestation (Veraison extension: `ear_veraison_key_attestation` / -70002)
    pub key_attestation: Option<KeyAttestation>,
    /// extension claims
    pub extensions: Extensions,
}

impl Appraisal {
    /// Create an empty Appraisal
    pub fn new() -> Appraisal {
        Appraisal {
            profile: None,
            status: TrustTier::None,
            trust_vector: TrustVector::new(),
            policy_ids: Vec::new(),
            nonce: None,
            attester_claims: BTreeMap::new(),
            verifier_claims: BTreeMap::new(),
            key_attestation: None,
            extensions: Extensions::new(),
        }
    }

    /// Create an empty Appraisal, registering extensions associated with the specified profile
    pub fn new_with_profile(profile: &str) -> Result<Appraisal, Error> {
        let mut appraisal = Appraisal::new();
        appraisal.profile = Some(profile.to_string());

        match get_profile(profile) {
            Some(profile) => {
                profile.populate_appraisal_extensions(&mut appraisal)?;
                Ok(appraisal)
            }
            None => Err(Error::ProfileError(format!("{profile} is not registered"))),
        }
    }

    /// Set the `status` based on the tiers of the claims in the trustworthiness vector
    pub fn update_status_from_trust_vector(&mut self) {
        for claim in self.trust_vector {
            let claim_tier = claim.tier();
            if self.status < claim_tier {
                self.status = claim_tier
            }
        }
    }
}

impl Default for Appraisal {
    fn default() -> Self {
        Self::new()
    }
}

impl Serialize for Appraisal {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let is_human_readable = serializer.is_human_readable();
        let mut map = serializer.serialize_map(None)?;

        if is_human_readable {
            if let Some(p) = &self.profile {
                map.serialize_entry("eat_profile", p)?;
            }

            map.serialize_entry("ear_status", &self.status)?;

            if self.trust_vector.any_set() {
                map.serialize_entry("ear_trustworthiness_vector", &self.trust_vector)?;
            }

            if !self.policy_ids.is_empty() {
                map.serialize_entry("ear_appraisal_policy_ids", &self.policy_ids)?;
            }

            if let Some(n) = &self.nonce {
                map.serialize_entry("eat_nonce", n)?;
            }

            if !self.attester_claims.is_empty() {
                map.serialize_entry("ear_attester_claims", &self.attester_claims)?;
            }

            if !self.verifier_claims.is_empty() {
                map.serialize_entry("ear_verifier_claims", &self.verifier_claims)?;
            }

            if let Some(ka) = &self.key_attestation {
                map.serialize_entry("ear_veraison_key_attestation", ka)?;
            }

            self.extensions.serialize_to_map_by_name(&mut map)?;
        } else {
            if let Some(p) = &self.profile {
                map.serialize_entry(&265, p)?;
            }

            map.serialize_entry(&1000, &self.status)?;

            if self.trust_vector.any_set() {
                map.serialize_entry(&1001, &self.trust_vector)?;
            }

            if !self.policy_ids.is_empty() {
                map.serialize_entry(&1003, &self.policy_ids)?;
            }

            if let Some(n) = &self.nonce {
                map.serialize_entry(&10, n)?;
            }

            if !self.attester_claims.is_empty() {
                map.serialize_entry(&1005, &self.attester_claims)?;
            }

            if !self.verifier_claims.is_empty() {
                map.serialize_entry(&1006, &self.verifier_claims)?;
            }

            if let Some(ka) = &self.key_attestation {
                map.serialize_entry(&-70002, ka)?;
            }

            self.extensions.serialize_to_map_by_key(&mut map)?;
        }

        map.end()
    }
}

impl<'de> Deserialize<'de> for Appraisal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let is_hr = deserializer.is_human_readable();

        deserializer.deserialize_map(AppraisalVisitor {
            is_human_readable: is_hr,
        })
    }
}

struct AppraisalVisitor {
    pub is_human_readable: bool,
}

impl<'de> Visitor<'de> for AppraisalVisitor {
    type Value = Appraisal;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a CBOR map or JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut appraisal = Appraisal::new();

        loop {
            if self.is_human_readable {
                match map.next_key::<&str>()? {
                    Some("eat_profile") => appraisal.profile = Some(map.next_value::<String>()?),
                    Some("ear_status") => appraisal.status = map.next_value::<TrustTier>()?,
                    Some("ear_trustworthiness_vector") => {
                        let trust_vector = map.next_value::<TrustVector>()?;
                        if !trust_vector.any_set() {
                            return Err(de::Error::custom(
                                "ear_trustworthiness_vector must not be empty",
                            ));
                        }
                        appraisal.trust_vector = trust_vector;
                    }
                    Some("ear_appraisal_policy_ids") => {
                        let policy_ids = map.next_value::<Vec<String>>()?;
                        if policy_ids.is_empty() {
                            return Err(de::Error::custom(
                                "ear_appraisal_policy_ids must not be empty",
                            ));
                        }
                        appraisal.policy_ids = policy_ids;
                    }
                    Some("eat_nonce") => appraisal.nonce = Some(map.next_value::<Nonce>()?),
                    Some("ear_attester_claims") => {
                        let claims = map.next_value::<BTreeMap<String, RawValue>>()?;
                        if claims.is_empty() {
                            return Err(de::Error::custom("ear_attester_claims must not be empty"));
                        }
                        appraisal.attester_claims = claims;
                    }
                    Some("ear_verifier_claims") => {
                        let claims = map.next_value::<BTreeMap<String, RawValue>>()?;
                        if claims.is_empty() {
                            return Err(de::Error::custom("ear_verifier_claims must not be empty"));
                        }
                        appraisal.verifier_claims = claims;
                    }
                    Some("ear_veraison_key_attestation") => {
                        appraisal.key_attestation = Some(map.next_value::<KeyAttestation>()?)
                    }
                    Some(name) => appraisal
                        .extensions
                        .visit_map_entry_by_name(name, &mut map)?,
                    None => break,
                }
            } else {
                match map.next_key::<ClaimKey>()? {
                    Some(ClaimKey::Integer(265)) => {
                        appraisal.profile = Some(map.next_value::<String>()?)
                    }
                    Some(ClaimKey::Integer(1000)) => {
                        appraisal.status = map.next_value::<TrustTier>()?
                    }
                    Some(ClaimKey::Integer(1001)) => {
                        let trust_vector = map.next_value::<TrustVector>()?;
                        if !trust_vector.any_set() {
                            return Err(de::Error::custom(
                                "ear_trustworthiness_vector must not be empty",
                            ));
                        }
                        appraisal.trust_vector = trust_vector;
                    }
                    Some(ClaimKey::Integer(1003)) => {
                        let policy_ids = map.next_value::<Vec<String>>()?;
                        if policy_ids.is_empty() {
                            return Err(de::Error::custom(
                                "ear_appraisal_policy_ids must not be empty",
                            ));
                        }
                        appraisal.policy_ids = policy_ids;
                    }
                    Some(ClaimKey::Integer(10)) => {
                        appraisal.nonce = Some(map.next_value::<Nonce>()?)
                    }
                    Some(ClaimKey::Integer(1005)) => {
                        let claims = map.next_value::<BTreeMap<String, RawValue>>()?;
                        if claims.is_empty() {
                            return Err(de::Error::custom("ear_attester_claims must not be empty"));
                        }
                        appraisal.attester_claims = claims;
                    }
                    Some(ClaimKey::Integer(1006)) => {
                        let claims = map.next_value::<BTreeMap<String, RawValue>>()?;
                        if claims.is_empty() {
                            return Err(de::Error::custom("ear_verifier_claims must not be empty"));
                        }
                        appraisal.verifier_claims = claims;
                    }
                    Some(ClaimKey::Integer(-70002)) => {
                        appraisal.key_attestation = Some(map.next_value::<KeyAttestation>()?)
                    }
                    Some(ClaimKey::Integer(key)) => appraisal
                        .extensions
                        .visit_map_entry_by_cbor_key(key, &mut map)?,
                    Some(ClaimKey::Unsigned(key)) => appraisal
                        .extensions
                        .ignore_map_entry_by_unsigned_cbor_key(key, &mut map)?,
                    Some(ClaimKey::Name(name)) => appraisal
                        .extensions
                        .visit_map_entry_by_name(&name, &mut map)?,
                    None => break,
                }
            }
        }

        Ok(appraisal)
    }
}

#[cfg(test)]
mod test {
    use ciborium::value::{Integer, Value};
    use ciborium::{de::from_reader, ser::into_writer};

    use crate::{claim, Appraisal, Nonce, RawValue};

    pub(crate) const DRAFT_POLICY_ID_EXAMPLE: &str = "https://veraison.example/policy/1/60a0068d";

    fn claim_value(cbor: &[u8], key: i32) -> Value {
        let root: Value = from_reader(cbor).unwrap();
        let Value::Map(entries) = root else {
            panic!("expected CBOR map, got {root:?}");
        };

        entries
            .iter()
            .find(|(k, _)| *k == Value::Integer(Integer::from(key)))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("map must contain claim key {key}"))
    }

    #[test]
    fn profile_and_nonce_serde() {
        let mut a = Appraisal::new();
        a.profile = Some("http://arm.com/psa/2.0.0".to_string());
        a.nonce = Some(Nonce::try_from("QUJDREVGR0hJSg".to_string()).unwrap());

        let text = serde_json::to_string(&a).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v.get("eat_profile").and_then(|p| p.as_str()),
            Some("http://arm.com/psa/2.0.0"),
        );
        assert_eq!(
            v.get("eat_nonce").and_then(|n| n.as_str()),
            Some("QUJDREVGR0hJSg"),
        );

        let b: Appraisal = serde_json::from_str(&text).unwrap();
        assert_eq!(a, b);

        let mut json_to_cbor = Vec::new();
        into_writer(&b, &mut json_to_cbor).unwrap();
        assert_eq!(
            claim_value(&json_to_cbor, 10),
            Value::Bytes(b"ABCDEFGHIJ".to_vec()),
        );

        let mut a = Appraisal::new();
        a.profile = Some("http://arm.com/psa/2.0.0".to_string());
        a.nonce = Some(
            Nonce::try_from([0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef].as_slice()).unwrap(),
        );

        let mut buf = Vec::new();
        into_writer(&a, &mut buf).unwrap();
        assert_eq!(
            claim_value(&buf, 265),
            Value::Text("http://arm.com/psa/2.0.0".to_string()),
        );
        assert_eq!(
            claim_value(&buf, 10),
            Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef]),
        );

        let b: Appraisal = from_reader(buf.as_slice()).unwrap();
        assert_eq!(a, b);
        let cbor_to_json = serde_json::to_value(&b).unwrap();
        assert_eq!(cbor_to_json["eat_nonce"], "3q2-796tvu8");
    }

    #[test]
    fn attester_and_verifier_claims_serde() {
        // from the Project Veraison extension example in draft-ietf-rats-ear-04 4.5.1
        const DRAFT_EXAMPLE: &str = r#"{
            "ear_status": "contraindicated",
            "ear_trustworthiness_vector": {
                "instance-identity": 2,
                "executables": 96,
                "hardware": 2
            },
            "ear_appraisal_policy_ids": [
                "https://veraison.example/policy/1/60a0068d"
            ],
            "ear_attester_claims": {
                "eat-profile": "http://arm.com/psa/2.0.0",
                "psa-client-id": 1,
                "psa-security-lifecycle": 12288
            },
            "ear_verifier_claims": {
                "psa-certified": {
                    "certificate-number": "1234567890123-12345",
                    "test-lab": "Riscure"
                }
            }
        }"#;

        let a: Appraisal = serde_json::from_str(DRAFT_EXAMPLE).unwrap();

        assert_eq!(
            a.attester_claims.get("eat-profile"),
            Some(&RawValue::String("http://arm.com/psa/2.0.0".to_string())),
        );
        assert_eq!(
            a.attester_claims.get("psa-security-lifecycle"),
            Some(&RawValue::Integer(12288)),
        );
        assert_eq!(
            a.verifier_claims.get("psa-certified"),
            Some(&RawValue::Map(vec![
                (
                    RawValue::String("certificate-number".to_string()),
                    RawValue::String("1234567890123-12345".to_string()),
                ),
                (
                    RawValue::String("test-lab".to_string()),
                    RawValue::String("Riscure".to_string()),
                ),
            ])),
        );

        let text = serde_json::to_string(&a).unwrap();
        assert_eq!(
            text.parse::<serde_json::Value>().unwrap(),
            DRAFT_EXAMPLE.parse::<serde_json::Value>().unwrap(),
        );

        let mut buf = Vec::new();
        into_writer(&a, &mut buf).unwrap();
        assert!(matches!(claim_value(&buf, 1005), Value::Map(_)));
        assert!(matches!(claim_value(&buf, 1006), Value::Map(_)));

        let b: Appraisal = from_reader(buf.as_slice()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn policy_ids_json_roundtrip() {
        let mut a = Appraisal::new();
        a.policy_ids = vec!["https://example/p/1".into(), "https://example/p/2".into()];
        let s = serde_json::to_string(&a).unwrap();
        assert!(s.contains("ear_appraisal_policy_ids"));
        let b: Appraisal = serde_json::from_str(&s).unwrap();
        assert_eq!(a.policy_ids, b.policy_ids);
    }

    #[test]
    fn policy_ids_json_shape_matches_draft() {
        let mut a = Appraisal::new();
        a.policy_ids = vec![
            DRAFT_POLICY_ID_EXAMPLE.into(),
            "tag:example.com,2026:policy#2".into(),
        ];
        let s = serde_json::to_string(&a).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();

        let ids = v
            .get("ear_appraisal_policy_ids")
            .expect("ear_appraisal_policy_ids claim must be present");
        let arr = ids.as_array().expect("claim value must be a JSON array");
        assert_eq!(arr.len(), 2);
        assert!(arr.iter().all(|x| x.as_str().is_some()));
        assert_eq!(arr[0].as_str().unwrap(), DRAFT_POLICY_ID_EXAMPLE);
    }

    #[test]
    fn policy_ids_json_deserialize_draft_example_document() {
        let s = format!(
            r#"{{"ear_status":"none","ear_appraisal_policy_ids":["{0}"]}}"#,
            DRAFT_POLICY_ID_EXAMPLE
        );
        let a: Appraisal = serde_json::from_str(&s).unwrap();
        assert_eq!(a.policy_ids, vec![DRAFT_POLICY_ID_EXAMPLE.to_string()]);
        assert_eq!(a.status.to_string(), "none");
    }

    #[test]
    fn policy_ids_omitted_when_empty_json() {
        let a = Appraisal::new();
        let s = serde_json::to_string(&a).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(
            v.get("ear_appraisal_policy_ids").is_none(),
            "empty policy_ids must omit ear_appraisal_policy_ids: {v}"
        );
    }

    #[test]
    fn policy_ids_cbor_roundtrip() {
        use ciborium::{de::from_reader, ser::into_writer};

        let mut a = Appraisal::new();
        a.policy_ids = vec![DRAFT_POLICY_ID_EXAMPLE.into()];
        let mut buf = Vec::new();
        into_writer(&a, &mut buf).unwrap();
        let b: Appraisal = from_reader(buf.as_slice()).unwrap();
        assert_eq!(a.policy_ids, b.policy_ids);
    }

    #[test]
    fn policy_ids_cbor_uses_claim_key_1003_array_of_text() {
        use ciborium::value::{Integer, Value};
        use ciborium::{de::from_reader, ser::into_writer};

        let mut a = Appraisal::new();
        a.policy_ids = vec![DRAFT_POLICY_ID_EXAMPLE.into()];
        let mut buf = Vec::new();
        into_writer(&a, &mut buf).unwrap();

        let root: Value = from_reader(buf.as_slice()).unwrap();
        let Value::Map(entries) = root else {
            panic!("expected CBOR map, got {root:?}");
        };

        let key_1003 = Value::Integer(Integer::from(1003));
        let (_, policy_val) = entries
            .iter()
            .find(|(k, _)| *k == key_1003)
            .expect("map must contain claim key 1003");

        let Value::Array(items) = policy_val else {
            panic!("claim 1003 must be a CBOR array, got {policy_val:?}");
        };
        assert_eq!(items.len(), 1);
        let Value::Text(t) = &items[0] else {
            panic!("policy id elements must be CBOR text, got {:?}", items[0]);
        };
        assert_eq!(t, DRAFT_POLICY_ID_EXAMPLE);
    }

    #[test]
    fn rejects_present_empty_claims() {
        for (document, expected) in [
            (
                r#"{"ear_status":"none","ear_trustworthiness_vector":{}}"#,
                "ear_trustworthiness_vector must not be empty",
            ),
            (
                r#"{"ear_status":"none","ear_appraisal_policy_ids":[]}"#,
                "ear_appraisal_policy_ids must not be empty",
            ),
            (
                r#"{"ear_status":"none","ear_attester_claims":{}}"#,
                "ear_attester_claims must not be empty",
            ),
            (
                r#"{"ear_status":"none","ear_verifier_claims":{}}"#,
                "ear_verifier_claims must not be empty",
            ),
        ] {
            let error = serde_json::from_str::<Appraisal>(document).unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }

        let value = Value::Map(vec![
            (
                Value::Integer(Integer::from(1000)),
                Value::Integer(Integer::from(0)),
            ),
            (
                Value::Integer(Integer::from(1003)),
                Value::Array(Vec::new()),
            ),
        ]);
        let mut buf = Vec::new();
        into_writer(&value, &mut buf).unwrap();
        let error = from_reader::<Appraisal, _>(buf.as_slice()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ear_appraisal_policy_ids must not be empty"),
            "{error}"
        );
    }

    #[test]
    fn serde() {
        let mut appraisal = Appraisal::new();
        let val = serde_json::to_string(&appraisal).unwrap();
        assert_eq!(val, r#"{"ear_status":"none"}"#);

        appraisal
            .trust_vector
            .configuration
            .set(claim::APPROVED_CONFIG);

        let val = serde_json::to_string(&appraisal).unwrap();
        assert_eq!(
            val,
            r#"{"ear_status":"none","ear_trustworthiness_vector":{"configuration":2}}"#
        );

        let appraisal2: Appraisal = serde_json::from_str(val.as_str()).unwrap();
        assert_eq!(appraisal, appraisal2);
    }
}
