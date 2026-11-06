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
    /// This is typically the least trustworthy tier of all the claims that have been made (whose
    /// values have been set), though a verifier may choose to set it to a less trustworthy tier. It
    /// defaults to [`TrustTier::Incomplete`], until the appraisal is done. draft-ietf-rats-ear-05
    /// forbids [`TrustTier::None`], which [`crate::Ear`] rejects when serializing, and when parsing
    /// an EAR with the [`crate::EAR_PROFILE`] profile.
    pub status: TrustTier,
    /// Reasons for the value of `status`, for people rather than for automated decisions
    /// (`ear_status_details` / 1010)
    ///
    /// A present list must be non-empty. Per [draft-ietf-rats-ear-05, Section 3.3], Relying Parties
    /// must treat its contents as untrusted input.
    ///
    /// [draft-ietf-rats-ear-05, Section 3.3]: https://www.ietf.org/archive/id/draft-ietf-rats-ear-05.html#section-3.3
    pub status_details: Vec<String>,
    /// Contains the trustworthiness claims made in the appraisal
    ///
    /// When present on the wire, [draft-ietf-rats-ear-04 Appendix A] requires this map to be
    /// non-empty.
    ///
    /// [draft-ietf-rats-ear-04 Appendix A]: https://www.ietf.org/archive/id/draft-ietf-rats-ear-04.html#appendix-A
    pub trust_vector: TrustVector,
    /// Reasons for the values of trustworthiness vector categories, keyed by category name, e.g.
    /// `"executables"` (`ear_trustworthiness_vector_details` / 1011)
    ///
    /// Per [draft-ietf-rats-ear-05, Section 3.2], each key must be a category present in
    /// `trust_vector`, and each list of reasons must be non-empty. In CBOR the keys are the
    /// categories' integer labels.
    ///
    /// [draft-ietf-rats-ear-05, Section 3.2]: https://www.ietf.org/archive/id/draft-ietf-rats-ear-05.html#section-3.2
    pub trust_vector_details: BTreeMap<String, Vec<String>>,
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
    /// Claims with Endorser authority added during appraisal using Endorsements, keyed by the
    /// supply chain entity that asserted them (`ear_endorser_claims` / 1014)
    pub endorser_claims: BTreeMap<String, BTreeMap<String, RawValue>>,
    /// Claims present in the evidence that the verifier corroborated using Reference Values, keyed
    /// by the supply chain entity that provided them (`ear_reference_value_provider_claims` / 1015)
    pub reference_value_provider_claims: BTreeMap<String, BTreeMap<String, RawValue>>,
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
            status: TrustTier::Incomplete,
            status_details: Vec::new(),
            trust_vector: TrustVector::new(),
            trust_vector_details: BTreeMap::new(),
            policy_ids: Vec::new(),
            nonce: None,
            attester_claims: BTreeMap::new(),
            verifier_claims: BTreeMap::new(),
            endorser_claims: BTreeMap::new(),
            reference_value_provider_claims: BTreeMap::new(),
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

    /// Set the `status` to the least trustworthy tier of the claims in the trustworthiness vector
    ///
    /// Claims in the [`TrustTier::None`] tier make no statement and don't affect the result. If no
    /// claim has another tier, the status is [`TrustTier::Incomplete`], since draft-ietf-rats-ear-05
    /// forbids a [`TrustTier::None`] status. A claim in the incomplete tier, e.g.
    /// [`claim::VERIFIER_MALFUNCTION`](crate::claim::VERIFIER_MALFUNCTION), makes the status
    /// incomplete.
    pub fn update_status_from_trust_vector(&mut self) {
        self.status = self
            .most_severe_claim_tier()
            .unwrap_or(TrustTier::Incomplete);
    }

    /// The tier of the least trustworthy claim in the trustworthiness vector, ignoring claims in
    /// the [`TrustTier::None`] tier
    pub(crate) fn most_severe_claim_tier(&self) -> Option<TrustTier> {
        self.trust_vector
            .into_iter()
            .map(|claim| claim.tier())
            .filter(|tier| *tier != TrustTier::None)
            .max()
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

            if !self.status_details.is_empty() {
                map.serialize_entry("ear_status_details", &self.status_details)?;
            }

            if self.trust_vector.any_set() {
                map.serialize_entry("ear_trustworthiness_vector", &self.trust_vector)?;
            }

            if !self.trust_vector_details.is_empty() {
                map.serialize_entry(
                    "ear_trustworthiness_vector_details",
                    &self.trust_vector_details,
                )?;
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

            if !self.endorser_claims.is_empty() {
                map.serialize_entry("ear_endorser_claims", &self.endorser_claims)?;
            }

            if !self.reference_value_provider_claims.is_empty() {
                map.serialize_entry(
                    "ear_reference_value_provider_claims",
                    &self.reference_value_provider_claims,
                )?;
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

            if !self.status_details.is_empty() {
                map.serialize_entry(&1010, &self.status_details)?;
            }

            if self.trust_vector.any_set() {
                map.serialize_entry(&1001, &self.trust_vector)?;
            }

            if !self.trust_vector_details.is_empty() {
                let details = details_by_key(&self.trust_vector_details)
                    .map_err(serde::ser::Error::custom)?;
                map.serialize_entry(&1011, &details)?;
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

            if !self.endorser_claims.is_empty() {
                map.serialize_entry(&1014, &self.endorser_claims)?;
            }

            if !self.reference_value_provider_claims.is_empty() {
                map.serialize_entry(&1015, &self.reference_value_provider_claims)?;
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
                    Some("ear_status_details") => {
                        let reasons = map.next_value::<Vec<String>>()?;
                        if reasons.is_empty() {
                            return Err(de::Error::custom("ear_status_details must not be empty"));
                        }
                        appraisal.status_details = reasons;
                    }
                    Some("ear_trustworthiness_vector_details") => {
                        let details = map.next_value::<BTreeMap<String, Vec<String>>>()?;
                        appraisal.trust_vector_details = vector_details(details)?;
                    }
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
                    Some("ear_endorser_claims") => {
                        appraisal.endorser_claims =
                            supply_chain_claims(map.next_value()?, "ear_endorser_claims")?;
                    }
                    Some("ear_reference_value_provider_claims") => {
                        appraisal.reference_value_provider_claims = supply_chain_claims(
                            map.next_value()?,
                            "ear_reference_value_provider_claims",
                        )?;
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
                    Some(ClaimKey::Integer(1010)) => {
                        let reasons = map.next_value::<Vec<String>>()?;
                        if reasons.is_empty() {
                            return Err(de::Error::custom("ear_status_details must not be empty"));
                        }
                        appraisal.status_details = reasons;
                    }
                    Some(ClaimKey::Integer(1011)) => {
                        let details = map.next_value::<BTreeMap<i64, Vec<String>>>()?;
                        appraisal.trust_vector_details =
                            vector_details(details_by_name(details).map_err(de::Error::custom)?)?;
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
                    Some(ClaimKey::Integer(1014)) => {
                        appraisal.endorser_claims =
                            supply_chain_claims(map.next_value()?, "ear_endorser_claims")?;
                    }
                    Some(ClaimKey::Integer(1015)) => {
                        appraisal.reference_value_provider_claims = supply_chain_claims(
                            map.next_value()?,
                            "ear_reference_value_provider_claims",
                        )?;
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

        for category in appraisal.trust_vector_details.keys() {
            // vector_details() has checked that the category name is valid
            if !appraisal
                .trust_vector
                .by_name(category)
                .is_ok_and(|c| c.is_set())
            {
                return Err(de::Error::custom(format!(
                    "ear_trustworthiness_vector_details: category {category} is not present \
                     in ear_trustworthiness_vector"
                )));
            }
        }

        Ok(appraisal)
    }
}

/// Checks an `ear_trustworthiness_vector_details` map keyed by category name.
fn vector_details<E: de::Error>(
    details: BTreeMap<String, Vec<String>>,
) -> Result<BTreeMap<String, Vec<String>>, E> {
    if details.is_empty() {
        return Err(E::custom(
            "ear_trustworthiness_vector_details must not be empty",
        ));
    }
    for (category, reasons) in &details {
        if TrustVector::new().by_name(category).is_err() {
            return Err(E::custom(format!(
                "ear_trustworthiness_vector_details: unknown category {category}"
            )));
        }
        if reasons.is_empty() {
            return Err(E::custom(format!(
                "ear_trustworthiness_vector_details: {category} must not be empty"
            )));
        }
    }
    Ok(details)
}

/// Converts trustworthiness vector details keyed by category name to the CBOR integer labels.
fn details_by_key(
    details: &BTreeMap<String, Vec<String>>,
) -> Result<BTreeMap<i8, &Vec<String>>, Error> {
    let vector = TrustVector::new();
    details
        .iter()
        .map(|(category, reasons)| Ok((vector.by_name(category)?.key(), reasons)))
        .collect()
}

/// Converts trustworthiness vector details keyed by CBOR integer label to category names.
fn details_by_name(
    details: BTreeMap<i64, Vec<String>>,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let vector = TrustVector::new();
    details
        .into_iter()
        .map(|(key, reasons)| {
            let category = i32::try_from(key)
                .ok()
                .and_then(|key| vector.by_key(key).ok())
                .ok_or_else(|| {
                    format!("ear_trustworthiness_vector_details: unknown category {key}")
                })?;
            Ok((category.tag().to_string(), reasons))
        })
        .collect()
}

/// Checks an endorser or reference value provider claims map: a non-empty map from supply chain
/// entity to a non-empty claims map.
fn supply_chain_claims<E: de::Error>(
    claims: BTreeMap<String, BTreeMap<String, RawValue>>,
    claim: &str,
) -> Result<BTreeMap<String, BTreeMap<String, RawValue>>, E> {
    if claims.is_empty() {
        return Err(E::custom(format!("{claim} must not be empty")));
    }
    if let Some((entity, _)) = claims.iter().find(|(_, claims)| claims.is_empty()) {
        return Err(E::custom(format!(
            "{claim}: claims of {entity} must not be empty"
        )));
    }
    Ok(claims)
}

#[cfg(test)]
mod test {
    use ciborium::value::{Integer, Value};
    use ciborium::{de::from_reader, ser::into_writer};

    use crate::{claim, Appraisal, Nonce, RawValue, TrustTier};

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
            Some("QUJDREVGR0hJSg=="),
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
        assert_eq!(cbor_to_json["eat_nonce"], "3q2+796tvu8=");
    }

    #[test]
    fn claims_serde() {
        // from the Project Veraison extension example in draft-ietf-rats-ear-05 4.6.1,
        // abridged, plus ear_verifier_claims, which the example doesn't have
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
                "psa-certification-checked": true
            },
            "ear_endorser_claims": {
                "ACME Security Lab": {
                    "psa-certified": {
                        "certificate-number": "1234567890123-12345",
                        "test-lab": "Riscure"
                    }
                }
            },
            "ear_reference_value_provider_claims": {
                "Arm": {
                    "psa-implementation-id": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
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
            a.verifier_claims.get("psa-certification-checked"),
            Some(&RawValue::Bool(true)),
        );
        assert_eq!(
            a.endorser_claims["ACME Security Lab"].get("psa-certified"),
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
        assert_eq!(
            a.reference_value_provider_claims["Arm"].get("psa-implementation-id"),
            Some(&RawValue::String(
                "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=".to_string()
            )),
        );

        let text = serde_json::to_string(&a).unwrap();
        assert_eq!(
            text.parse::<serde_json::Value>().unwrap(),
            DRAFT_EXAMPLE.parse::<serde_json::Value>().unwrap(),
        );

        let mut buf = Vec::new();
        into_writer(&a, &mut buf).unwrap();
        for key in [1005, 1006, 1014, 1015] {
            assert!(matches!(claim_value(&buf, key), Value::Map(_)), "{key}");
        }

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
    fn rejects_invalid_claims() {
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
            (
                r#"{"ear_status":"none","ear_status_details":[]}"#,
                "ear_status_details must not be empty",
            ),
            (
                r#"{"ear_status":"none","ear_trustworthiness_vector":{"executables":2},
                    "ear_trustworthiness_vector_details":{}}"#,
                "ear_trustworthiness_vector_details must not be empty",
            ),
            (
                r#"{"ear_status":"none","ear_trustworthiness_vector":{"executables":2},
                    "ear_trustworthiness_vector_details":{"executables":[]}}"#,
                "ear_trustworthiness_vector_details: executables must not be empty",
            ),
            (
                r#"{"ear_status":"none","ear_trustworthiness_vector":{"executables":2},
                    "ear_trustworthiness_vector_details":{"firmware":["x"]}}"#,
                "ear_trustworthiness_vector_details: unknown category firmware",
            ),
            (
                // the category must be present in the trust vector, in either order
                r#"{"ear_status":"none","ear_trustworthiness_vector_details":{"hardware":["x"]},
                    "ear_trustworthiness_vector":{"executables":2}}"#,
                "category hardware is not present in ear_trustworthiness_vector",
            ),
            (
                r#"{"ear_status":"none","ear_endorser_claims":{}}"#,
                "ear_endorser_claims must not be empty",
            ),
            (
                r#"{"ear_status":"none","ear_endorser_claims":{"ACME":{}}}"#,
                "ear_endorser_claims: claims of ACME must not be empty",
            ),
            (
                r#"{"ear_status":"none","ear_reference_value_provider_claims":{}}"#,
                "ear_reference_value_provider_claims must not be empty",
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

        // an unknown CBOR category label
        let value = Value::Map(vec![
            (
                Value::Integer(Integer::from(1000)),
                Value::Integer(Integer::from(0)),
            ),
            (
                Value::Integer(Integer::from(1011)),
                Value::Map(vec![(
                    Value::Integer(Integer::from(9)),
                    Value::Array(vec![Value::Text("x".to_string())]),
                )]),
            ),
        ]);
        let mut buf = Vec::new();
        into_writer(&value, &mut buf).unwrap();
        let error = from_reader::<Appraisal, _>(buf.as_slice()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ear_trustworthiness_vector_details: unknown category 9"),
            "{error}"
        );
    }

    /// The "PSA" submod of the draft-ietf-rats-ear-05 Figure 4 example
    const DETAILS_EXAMPLE: &str = r#"{
        "ear_status": "contraindicated",
        "ear_status_details": [
            "The 'executables' category is contraindicated."
        ],
        "ear_trustworthiness_vector": {
            "instance-identity": 2,
            "executables": 96,
            "hardware": 2
        },
        "ear_trustworthiness_vector_details": {
            "executables": [ "unauthorized code found in runtime memory" ]
        },
        "ear_appraisal_policy_ids": [ "https://veraison.example/policy/1/60a0068d" ]
    }"#;

    #[test]
    fn details_serde() {
        let a: Appraisal = serde_json::from_str(DETAILS_EXAMPLE).unwrap();
        assert_eq!(
            a.status_details,
            vec!["The 'executables' category is contraindicated.".to_string()],
        );
        assert_eq!(
            a.trust_vector_details.get("executables"),
            Some(&vec![
                "unauthorized code found in runtime memory".to_string()
            ]),
        );

        let text = serde_json::to_string(&a).unwrap();
        assert_eq!(
            text.parse::<serde_json::Value>().unwrap(),
            DETAILS_EXAMPLE.parse::<serde_json::Value>().unwrap(),
        );

        // the same appraisal as in the draft-ietf-rats-ear-05 Figure 6 CBOR example
        let mut buf = Vec::new();
        into_writer(&a, &mut buf).unwrap();
        assert_eq!(
            claim_value(&buf, 1010),
            Value::Array(vec![Value::Text(
                "The 'executables' category is contraindicated.".to_string()
            )]),
        );
        assert_eq!(
            claim_value(&buf, 1011),
            Value::Map(vec![(
                Value::Integer(Integer::from(2)),
                Value::Array(vec![Value::Text(
                    "unauthorized code found in runtime memory".to_string()
                )]),
            )]),
        );

        let b: Appraisal = from_reader(buf.as_slice()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn update_status_from_trust_vector() {
        let mut appraisal = Appraisal::new();
        appraisal.update_status_from_trust_vector();
        assert_eq!(appraisal.status, TrustTier::Incomplete);

        appraisal
            .trust_vector
            .configuration
            .set(claim::APPROVED_CONFIG);
        appraisal.update_status_from_trust_vector();
        assert_eq!(appraisal.status, TrustTier::Affirming);

        // a NO_CLAIM value doesn't affect the result
        appraisal.trust_vector.executables.set(claim::NO_CLAIM);
        appraisal.update_status_from_trust_vector();
        assert_eq!(appraisal.status, TrustTier::Affirming);

        for value in [claim::VERIFIER_MALFUNCTION, claim::UNEXPECTED_EVIDENCE] {
            appraisal.trust_vector.instance_identity.set(value);
            appraisal.update_status_from_trust_vector();
            assert_eq!(appraisal.status, TrustTier::Incomplete, "{value}");
        }
    }

    #[test]
    fn serde() {
        let mut appraisal = Appraisal::new();
        let val = serde_json::to_string(&appraisal).unwrap();
        assert_eq!(val, r#"{"ear_status":"incomplete"}"#);

        appraisal
            .trust_vector
            .configuration
            .set(claim::APPROVED_CONFIG);

        let val = serde_json::to_string(&appraisal).unwrap();
        assert_eq!(
            val,
            r#"{"ear_status":"incomplete","ear_trustworthiness_vector":{"configuration":2}}"#
        );

        let appraisal2: Appraisal = serde_json::from_str(val.as_str()).unwrap();
        assert_eq!(appraisal, appraisal2);
    }
}
