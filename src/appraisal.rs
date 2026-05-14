// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, fmt};

use serde::{
    de::{Deserialize, Visitor},
    ser::{Serialize, SerializeMap},
};

use crate::{get_profile, Error, Extensions, KeyAttestation, RawValue, TrustTier, TrustVector};

/// An appraisal crated by a verifier of the evidence provided by an attester
#[derive(Debug, PartialEq)]
pub struct Appraisal {
    /// The overall status of the appraisal represented by an AR4SI trustworthiness tier
    ///
    /// This is typically the lowest tier of all the claims that have been made (who's values have
    /// been set), though a verifier may chose to set it to a lower value.
    pub status: TrustTier,
    /// Contains the trustworthiness claims made in the appraisal
    pub trust_vector: TrustVector,
    /// Identifiers of the policies applied by the verifier (EAR `ear.appraisal-policy-ids` / 1003)
    pub policy_ids: Vec<String>,
    /// Evidence claims extracted and annotated by the verifier from the evidence supplied by the
    /// attester
    /// (note: this is a Veraison project extension to EAR)
    pub annotated_evidence: BTreeMap<String, RawValue>,
    /// Additional claims made as part of the appraisal based on the policies in `policy_ids`
    /// (note: this is a Veraison project extension to EAR)
    pub policy_claims: BTreeMap<String, RawValue>,
    /// Claims about the public key that is being attested
    /// (note: this is a Veraison project extension to EAR)
    pub key_attestation: Option<KeyAttestation>,
    /// extension claims
    pub extensions: Extensions,
}

impl Appraisal {
    /// Create an empty Appraisal
    pub fn new() -> Appraisal {
        Appraisal {
            status: TrustTier::None,
            trust_vector: TrustVector::new(),
            policy_ids: Vec::new(),
            annotated_evidence: BTreeMap::new(),
            policy_claims: BTreeMap::new(),
            key_attestation: None,
            extensions: Extensions::new(),
        }
    }

    /// Create an empty Appraisal, registering extensions associated with the specified profile
    pub fn new_with_profile(profile: &str) -> Result<Appraisal, Error> {
        let mut appraisal = Appraisal {
            status: TrustTier::None,
            trust_vector: TrustVector::new(),
            policy_ids: Vec::new(),
            annotated_evidence: BTreeMap::new(),
            policy_claims: BTreeMap::new(),
            key_attestation: None,
            extensions: Extensions::new(),
        };

        match get_profile(profile) {
            Some(profile) => {
                profile.populate_appraisal_extensions(&mut appraisal)?;
                Ok(appraisal)
            }
            None => Err(Error::ProfileError(format!("{profile} is not registered"))),
        }
    }

    /// Set the `status` based on the theirs of the claims in the trustworthiness vector
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
            map.serialize_entry("ear.status", &self.status)?;

            if self.trust_vector.any_set() {
                map.serialize_entry("ear.trustworthiness-vector", &self.trust_vector)?;
            }

            if !self.policy_ids.is_empty() {
                map.serialize_entry("ear.appraisal-policy-ids", &self.policy_ids)?;
            }

            if !self.annotated_evidence.is_empty() {
                map.serialize_entry("ear.veraison.annotated-evidence", &self.annotated_evidence)?;
            }

            if !self.policy_claims.is_empty() {
                map.serialize_entry("ear.veraison.policy-claims", &self.policy_claims)?;
            }

            self.extensions.serialize_to_map_by_name(&mut map)?;
        } else {
            // !is_human_readable
            map.serialize_entry(&1000, &self.status)?;

            if self.trust_vector.any_set() {
                map.serialize_entry(&1001, &self.trust_vector)?;
            }

            if !self.policy_ids.is_empty() {
                map.serialize_entry(&1003, &self.policy_ids)?;
            }

            if !self.annotated_evidence.is_empty() {
                map.serialize_entry(&-70000, &self.annotated_evidence)?;
            }

            if !self.policy_claims.is_empty() {
                map.serialize_entry(&-70001, &self.policy_claims)?;
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
                    Some("ear.status") => appraisal.status = map.next_value::<TrustTier>()?,
                    Some("ear.trustworthiness-vector") => {
                        appraisal.trust_vector = map.next_value::<TrustVector>()?
                    }
                    Some("ear.appraisal-policy-ids") => {
                        appraisal.policy_ids = map.next_value::<Vec<String>>()?;
                    }
                    Some("ear.veraison.annotated-evidence") => {
                        appraisal.annotated_evidence =
                            map.next_value::<BTreeMap<String, RawValue>>()?
                    }
                    Some("ear.veraison.policy-claims") => {
                        appraisal.policy_claims = map.next_value::<BTreeMap<String, RawValue>>()?
                    }
                    Some("ear.veraison.key-attestation") => {
                        appraisal.key_attestation = Some(map.next_value::<KeyAttestation>()?)
                    }
                    Some(name) => appraisal
                        .extensions
                        .visit_map_entry_by_name(name, &mut map)?,
                    None => break,
                }
            } else {
                // !is_human_readable
                match map.next_key::<i32>()? {
                    Some(1000) => appraisal.status = map.next_value::<TrustTier>()?,
                    Some(1001) => appraisal.trust_vector = map.next_value::<TrustVector>()?,
                    Some(1003) => {
                        appraisal.policy_ids = map.next_value::<Vec<String>>()?;
                    }
                    Some(-70000) => {
                        appraisal.annotated_evidence =
                            map.next_value::<BTreeMap<String, RawValue>>()?
                    }
                    Some(-70001) => {
                        appraisal.policy_claims = map.next_value::<BTreeMap<String, RawValue>>()?
                    }
                    Some(-70002) => {
                        appraisal.key_attestation = Some(map.next_value::<KeyAttestation>()?)
                    }
                    Some(key) => appraisal.extensions.visit_map_entry_by_key(key, &mut map)?,
                    None => break,
                }
            }
        }

        Ok(appraisal)
    }
}

#[cfg(test)]
mod test {
    use crate::{claim, Appraisal};

    /// `ear_appraisal_policy_ids` in draft-ietf-rats-ear (JSON examples use this URL).
    const DRAFT_POLICY_ID_EXAMPLE: &str = "https://veraison.example/policy/1/60a0068d";

    #[test]
    fn policy_ids_json_roundtrip() {
        let mut a = Appraisal::new();
        a.policy_ids = vec!["https://example/p/1".into(), "https://example/p/2".into()];
        let s = serde_json::to_string(&a).unwrap();
        assert!(s.contains("ear.appraisal-policy-ids"));
        let b: Appraisal = serde_json::from_str(&s).unwrap();
        assert_eq!(a.policy_ids, b.policy_ids);
    }

    /// draft-ietf-rats-ear: `appraisal-policy-ids-label => [ + text ]` with label 1003 (CBOR).
    /// This crate uses dotted claim names in JSON (`ear.*`) parallel to other EAR JSON fields.
    #[test]
    fn policy_ids_json_shape_matches_ear_appraisal_policy_ids() {
        let mut a = Appraisal::new();
        a.policy_ids = vec![
            DRAFT_POLICY_ID_EXAMPLE.into(),
            "tag:example.com,2026:policy#2".into(),
        ];
        let s = serde_json::to_string(&a).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();

        let ids = v
            .get("ear.appraisal-policy-ids")
            .expect("ear.appraisal-policy-ids claim must be present");
        let arr = ids.as_array().expect("claim value must be a JSON array");
        assert_eq!(arr.len(), 2);
        assert!(arr.iter().all(|x| x.as_str().is_some()));
        assert_eq!(arr[0].as_str().unwrap(), DRAFT_POLICY_ID_EXAMPLE);
    }

    /// Deserialize a minimal appraisal-shaped object using the same URL as the draft examples.
    #[test]
    fn policy_ids_json_deserialize_draft_example_document() {
        let s = format!(
            r#"{{"ear.status":"none","ear.appraisal-policy-ids":["{0}"]}}"#,
            DRAFT_POLICY_ID_EXAMPLE
        );
        let a: Appraisal = serde_json::from_str(&s).unwrap();
        assert_eq!(a.policy_ids, vec![DRAFT_POLICY_ID_EXAMPLE.to_string()]);
        assert_eq!(a.status.to_string(), "none");
    }

    /// Optional claim: empty `policy_ids` must not emit the field (matches optional in CDDL).
    #[test]
    fn policy_ids_omitted_when_empty_json() {
        let a = Appraisal::new();
        let s = serde_json::to_string(&a).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(
            v.get("ear.appraisal-policy-ids").is_none(),
            "empty policy_ids must omit ear.appraisal-policy-ids: {v}"
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

    /// CBOR map must use claim key 1003 for appraisal policy identifiers (draft-ietf-rats-ear).
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
    fn serde() {
        let mut appraisal = Appraisal::new();
        let val = serde_json::to_string(&appraisal).unwrap();
        assert_eq!(val, r#"{"ear.status":"none"}"#);

        appraisal
            .trust_vector
            .configuration
            .set(claim::APPROVED_CONFIG);

        let val = serde_json::to_string(&appraisal).unwrap();
        assert_eq!(
            val,
            r#"{"ear.status":"none","ear.trustworthiness-vector":{"configuration":2}}"#
        );

        let appraisal2: Appraisal = serde_json::from_str(val.as_str()).unwrap();
        assert_eq!(appraisal, appraisal2);
    }
}
