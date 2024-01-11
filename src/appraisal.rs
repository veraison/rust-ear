// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, fmt};

use serde::{
    de::{Deserialize, Visitor},
    ser::{Serialize, SerializeMap},
};

use crate::{KeyAttestation, RawValue, TrustTier, TrustVector};

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
    /// Identifier of the policy applied by the verifier
    pub policy_id: Option<String>,
    /// Evidence claims extracted and annotated by the verifier from the evidence supplied by the
    /// attester
    pub annotated_evidence: BTreeMap<String, RawValue>,
    /// Addition claims made as part of the appraisal based on the policy indicated by `policy_id`
    pub policy_claims: BTreeMap<String, RawValue>,
    /// Claims about the public key that is being attested
    pub key_attestation: Option<KeyAttestation>,
}

impl Appraisal {
    /// Create an empty Appraisal
    pub fn new() -> Appraisal {
        Appraisal {
            status: TrustTier::None,
            trust_vector: TrustVector::new(),
            policy_id: None,
            annotated_evidence: BTreeMap::new(),
            policy_claims: BTreeMap::new(),
            key_attestation: None,
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

            match &self.policy_id {
                Some(pid) => map.serialize_entry("ear.appraisal-policy-id", pid.as_str())?,
                None => (),
            }

            if !self.annotated_evidence.is_empty() {
                map.serialize_entry("ear.veraison.annotated-evidence", &self.annotated_evidence)?;
            }

            if !self.policy_claims.is_empty() {
                map.serialize_entry("ear.veraison.policy-claims", &self.policy_claims)?;
            }
        } else {
            // !is_human_readable
            map.serialize_entry(&1000, &self.status)?;

            if self.trust_vector.any_set() {
                map.serialize_entry(&1001, &self.trust_vector)?;
            }

            match &self.policy_id {
                Some(pid) => map.serialize_entry(&1003, pid.as_str())?,
                None => (),
            }

            if !self.annotated_evidence.is_empty() {
                map.serialize_entry(&-70000, &self.annotated_evidence)?;
            }

            if !self.policy_claims.is_empty() {
                map.serialize_entry(&-70001, &self.policy_claims)?;
            }
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
                    Some("ear.appraisal-policy-id") => {
                        appraisal.policy_id = Some(map.next_value::<String>()?)
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
                    Some(_) => (), // unknown extensions are ignored
                    None => break,
                }
            } else {
                // !is_human_readable
                match map.next_key::<i32>()? {
                    Some(1000) => appraisal.status = map.next_value::<TrustTier>()?,
                    Some(1001) => appraisal.trust_vector = map.next_value::<TrustVector>()?,
                    Some(1003) => appraisal.policy_id = Some(map.next_value::<String>()?),
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
                    Some(_) => (), // unknown extensions are ignored
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
