// SPDX-License-Identifier: Apache-2.0
use core::ops::DerefMut;

use std::collections::BTreeMap;
use std::fmt;

use jsonwebtoken::{self as jwt, jwk};
use openssl::{bn, ec, nid::Nid, pkey};
use serde::{
    de::{self, Deserialize, Visitor},
    ser::{Error as _, Serialize, SerializeMap},
};

use crate::algorithm::Algorithm;
use crate::appraisal::Appraisal;
use crate::base64::{self, Bytes};
use crate::error::Error;
use crate::id::VerifierID;
use crate::nonce::Nonce;
use crate::trust::tier::TrustTier;
use cose::message::CoseMessage;

#[allow(clippy::upper_case_acronyms)]
enum KeyFormat {
    PEM,
    DER,
}

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
    // Raw encoded evidence received by the verifier
    pub raw_evidence: Option<Bytes>,
}

impl Ear {
    // Create an empty EAR
    pub fn new() -> Ear {
        Ear {
            profile: "".to_string(),
            iat: 0,
            vid: VerifierID::new(),
            submods: BTreeMap::new(),
            nonce: None,
            raw_evidence: None,
        }
    }

    /// Decode an EAR from a JWT token, verifying the signature using the specified JWK-encoded
    /// key.
    pub fn from_jwt_jwk(token: &str, alg: Algorithm, key: &[u8]) -> Result<Self, Error> {
        let jwk: jwk::Jwk =
            serde_json::from_slice(key).map_err(|e| Error::KeyError(e.to_string()))?;

        let dk = jwt::DecodingKey::from_jwk(&jwk).map_err(|e| Error::KeyError(e.to_string()))?;

        let jwt_alg = match alg {
            Algorithm::ES256 => jwt::Algorithm::ES256,
            Algorithm::ES384 => jwt::Algorithm::ES384,
            Algorithm::EdDSA => jwt::Algorithm::EdDSA,
            Algorithm::PS256 => jwt::Algorithm::PS256,
            Algorithm::PS384 => jwt::Algorithm::PS384,
            Algorithm::PS512 => jwt::Algorithm::PS512,
            _ => return Err(Error::SignError(format!("algorithm {alg:?} not supported"))),
        };

        Self::from_jwt(token, jwt_alg, &dk)
    }

    pub fn from_jwt(
        token: &str,
        alg: jwt::Algorithm,
        key: &jwt::DecodingKey,
    ) -> Result<Self, Error> {
        let mut validation = jwt::Validation::new(alg);
        // the default validation sets "exp" as a mandatory claim, which an E is not required to
        // have.
        validation.set_required_spec_claims::<&str>(&[]);

        let token_data =
            jwt::decode(token, key, &validation).map_err(|e| Error::VerifyError(e.to_string()))?;
        Ok(token_data.claims)
    }

    /// Decode an EAR from a COSE token, verifying the signature using the specified JWK-encoded
    /// key.
    pub fn from_cose_jwk(token: &[u8], alg: Algorithm, key: &[u8]) -> Result<Self, Error> {
        let jwk: jwk::Jwk =
            serde_json::from_slice(key).map_err(|e| Error::KeyError(e.to_string()))?;

        let cose_alg = alg_to_cose(&alg)?;

        let mut cose_key = cose::keys::CoseKey::new();
        cose_key.alg(match jwk.common.key_algorithm {
            Some(jwt::jwk::KeyAlgorithm::ES256) => cose::algs::ES256,
            Some(jwt::jwk::KeyAlgorithm::ES384) => cose::algs::ES384,
            Some(jwt::jwk::KeyAlgorithm::EdDSA) => cose::algs::EDDSA,
            Some(a) => return Err(Error::KeyError(format!("unsupported algorithm {a:?}"))),
            None => cose_alg,
        });
        cose_key.key_ops(vec![cose::keys::KEY_OPS_VERIFY]);

        // NOTE: there appears to be a bug in the cose-rust lib, which means CoseSign.key() expects
        // the d param to be set, even if the key is only used for verification.
        cose_key.d(hex::decode("deadbeef").unwrap());

        match jwk.algorithm {
            jwk::AlgorithmParameters::EllipticCurve(ec_params) => {
                cose_key.kty(cose::keys::EC2);
                cose_key.crv(match ec_params.curve {
                    jwk::EllipticCurve::P256 => cose::keys::P_256,
                    jwk::EllipticCurve::P384 => cose::keys::P_384,
                    jwk::EllipticCurve::P521 => cose::keys::P_521,
                    c => return Err(Error::KeyError(format!("invalid EC2 curve {c:?}"))),
                });
                cose_key.x(base64::decode_str(ec_params.x.as_str())?);
                cose_key.y(base64::decode_str(ec_params.y.as_str())?);
            }
            jwk::AlgorithmParameters::OctetKeyPair(okp_params) => {
                cose_key.kty(cose::keys::OKP);
                cose_key.crv(match okp_params.curve {
                    jwk::EllipticCurve::Ed25519 => cose::keys::ED25519,
                    c => return Err(Error::KeyError(format!("invalid OKP curve {c:?}"))),
                });
                cose_key.x(base64::decode_str(okp_params.x.as_str())?);
            }
            a => {
                return Err(Error::KeyError(format!(
                    "unsupported algorithm params {a:?}"
                )))
            }
        }

        Self::from_cose(token, &cose_key)
    }

    fn from_cose(token: &[u8], key: &cose::keys::CoseKey) -> Result<Self, Error> {
        let mut sign1 = CoseMessage::new_sign();

        sign1.bytes = token.to_vec();
        sign1.init_decoder(None).unwrap();
        sign1.key(key).unwrap();
        sign1.decode(None, None).unwrap();

        ciborium::de::from_reader(sign1.payload.as_slice())
            .map_err(|e| Error::VerifyError(e.to_string()))
    }

    /// Encode the EAR as a JWT token, signing it with the specified PEM-encoded key
    #[allow(clippy::type_complexity)]
    pub fn sign_jwt_pem(&self, alg: Algorithm, key: &[u8]) -> Result<String, Error> {
        let (jwt_alg, keyfunc): (
            jwt::Algorithm,
            fn(&[u8]) -> Result<jwt::EncodingKey, jwt::errors::Error>,
        ) = match alg {
            Algorithm::ES256 => (jwt::Algorithm::ES256, jwt::EncodingKey::from_ec_pem),
            Algorithm::ES384 => (jwt::Algorithm::ES384, jwt::EncodingKey::from_ec_pem),
            Algorithm::EdDSA => (jwt::Algorithm::EdDSA, jwt::EncodingKey::from_ed_pem),
            Algorithm::PS256 => (jwt::Algorithm::PS256, jwt::EncodingKey::from_rsa_pem),
            Algorithm::PS384 => (jwt::Algorithm::PS384, jwt::EncodingKey::from_rsa_pem),
            Algorithm::PS512 => (jwt::Algorithm::PS512, jwt::EncodingKey::from_rsa_pem),
            _ => return Err(Error::SignError(format!("algorithm {alg:?} not supported"))),
        };

        let ek = keyfunc(key).map_err(|e| Error::KeyError(e.to_string()))?;

        self.sign_jwk(jwt_alg, &ek)
    }

    /// Encode the EAR as a JWT token, signing it with the specified DER-encoded key
    pub fn sign_jwk_der(&self, alg: Algorithm, key: &[u8]) -> Result<String, Error> {
        let (jwt_alg, ek) = match alg {
            Algorithm::ES256 => (jwt::Algorithm::ES256, jwt::EncodingKey::from_ec_der(key)),
            Algorithm::ES384 => (jwt::Algorithm::ES384, jwt::EncodingKey::from_ec_der(key)),
            Algorithm::EdDSA => (jwt::Algorithm::EdDSA, jwt::EncodingKey::from_ed_der(key)),
            Algorithm::PS256 => (jwt::Algorithm::PS256, jwt::EncodingKey::from_rsa_der(key)),
            Algorithm::PS384 => (jwt::Algorithm::PS384, jwt::EncodingKey::from_rsa_der(key)),
            Algorithm::PS512 => (jwt::Algorithm::PS512, jwt::EncodingKey::from_rsa_der(key)),
            _ => return Err(Error::SignError(format!("algorithm {alg:?} not supported"))),
        };

        self.sign_jwk(jwt_alg, &ek)
    }

    fn sign_jwk(&self, alg: jwt::Algorithm, key: &jwt::EncodingKey) -> Result<String, Error> {
        let header = jwt::Header::new(alg);
        jwt::encode(&header, self, key).map_err(|e| Error::SignError(e.to_string()))
    }

    /// Encode the EAR as a COSE token, signing it with the specified PEM-encoded key
    pub fn sign_cose_pem(&self, alg: Algorithm, key: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_cose_bytes(alg, key, KeyFormat::PEM)
    }

    /// Encode the EAR as a COSE token, signing it with the specified DER-encoded key
    pub fn sign_cose_der(&self, alg: Algorithm, key: &[u8]) -> Result<Vec<u8>, Error> {
        self.sign_cose_bytes(alg, key, KeyFormat::DER)
    }

    fn sign_cose_bytes(
        &self,
        alg: Algorithm,
        key: &[u8],
        key_fmt: KeyFormat,
    ) -> Result<Vec<u8>, Error> {
        let cose_alg = alg_to_cose(&alg)?;

        let mut cose_key = cose::keys::CoseKey::new();
        cose_key.alg(cose_alg);
        cose_key.key_ops(vec![cose::keys::KEY_OPS_SIGN]);

        match alg {
            Algorithm::ES256 | Algorithm::ES384 | Algorithm::PS512 => {
                let ec_key = match key_fmt {
                    KeyFormat::PEM => ec::EcKey::private_key_from_pem(key),
                    KeyFormat::DER => ec::EcKey::private_key_from_der(key),
                }
                .map_err(|e| Error::KeyError(e.to_string()))?;

                let ec_group = ec_key.group();

                cose_key.kty(cose::keys::EC2);
                cose_key.crv(match ec_group.curve_name() {
                    Some(Nid::X9_62_PRIME256V1) => cose::keys::P_256,
                    Some(Nid::SECP384R1) => cose::keys::P_384,
                    Some(Nid::SECP521R1) => cose::keys::P_521,
                    _ => return Err(Error::KeyError("unsupported EC group".to_string())),
                });

                let mut x = bn::BigNum::new().map_err(|e| Error::KeyError(e.to_string()))?;
                let mut y = bn::BigNum::new().map_err(|e| Error::KeyError(e.to_string()))?;

                let mut ctx =
                    bn::BigNumContext::new_secure().map_err(|e| Error::KeyError(e.to_string()))?;

                let x_ref = x.deref_mut();
                let y_ref = y.deref_mut();
                let ctx_ref = ctx.deref_mut();

                ec_key
                    .public_key()
                    .affine_coordinates(ec_group, x_ref, y_ref, ctx_ref)
                    .map_err(|e| Error::KeyError(e.to_string()))?;

                cose_key.x(x_ref.to_vec());
                cose_key.y(y_ref.to_vec());
                cose_key.d(ec_key.private_key().to_vec());
            }
            Algorithm::EdDSA => {
                cose_key.kty(cose::keys::OKP);
                cose_key.crv(cose::keys::ED25519);

                let p_key = match key_fmt {
                    KeyFormat::PEM => pkey::PKey::private_key_from_pem(key),
                    KeyFormat::DER => pkey::PKey::private_key_from_der(key),
                }
                .map_err(|e| Error::KeyError(e.to_string()))?;

                let raw = p_key
                    .raw_private_key()
                    .map_err(|e| Error::KeyError(e.to_string()))?;

                cose_key.d(raw[..32].to_vec());
                cose_key.x(raw[32..].to_vec());
            }
            _ => return Err(Error::SignError(format!("algorithm {alg:?} not supported"))),
        };

        self.sign_cose(cose_alg, &cose_key)
    }

    fn sign_cose(&self, alg: i32, key: &cose::keys::CoseKey) -> Result<Vec<u8>, Error> {
        let mut payload: Vec<u8> = Vec::new();
        ciborium::ser::into_writer(self, &mut payload)
            .map_err(|e| Error::SignError(e.to_string()))?;

        let mut sign1 = CoseMessage::new_sign();
        sign1.payload(payload);
        sign1.header.alg(alg, true, false);

        if let Some(a) = key.alg {
            if a != sign1.header.alg.unwrap() {
                return Err(Error::SignError(
                    "specified algorithm doesn't match key".to_string(),
                ));
            }
        };

        sign1
            .key(key)
            .map_err(|e| Error::SignError(format!("{e:?}")))?;

        sign1
            .secure_content(None)
            .map_err(|e| Error::SignError(format!("{e:?}")))?;
        sign1
            .encode(true)
            .map_err(|e| Error::SignError(format!("{e:?}")))?;

        Ok(sign1.bytes.to_vec())
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

            match &self.nonce {
                Some(n) => map.serialize_entry("eat_nonce", &n)?,
                None => (),
            }

            match &self.raw_evidence {
                Some(r) => map.serialize_entry("ear.raw-evidence", &r)?,
                None => (),
            }
        } else {
            // !is_human_readable
            map.serialize_entry(&265, &self.profile)?;
            map.serialize_entry(&6, &self.iat)?;
            map.serialize_entry(&1004, &self.vid)?;
            map.serialize_entry(&266, &self.submods)?;

            match &self.nonce {
                Some(n) => map.serialize_entry(&10, &n)?,
                None => (),
            }

            match &self.raw_evidence {
                Some(r) => map.serialize_entry(&1002, &r)?,
                None => (),
            }
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
                    Some(_) => (), // ignore unknown extensions
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
                    Some(_) => (), // ignore unknown extensions
                    None => break,
                }
            }
        }

        ear.validate().map_err(de::Error::custom)?;

        Ok(ear)
    }
}

#[inline]
fn alg_to_cose(alg: &Algorithm) -> Result<i32, Error> {
    match alg {
        Algorithm::ES256 => Ok(cose::algs::ES256),
        Algorithm::ES384 => Ok(cose::algs::ES384),
        Algorithm::ES512 => Ok(cose::algs::ES512),
        Algorithm::EdDSA => Ok(cose::algs::EDDSA),
        _ => Err(Error::SignError(format!("algorithm {alg:?} not supported"))),
    }
}

#[cfg(test)]
mod test {
    use super::*;
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

    const SIGNING_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPp4XZRnRHSMhGg0t
6yjQCRV35J4TUY4idLgiCu6EyLqhRANCAAQbx8C533c2AKDwL/RtjVipVnnM2WRv
5w2wZNCJrubSK0StYKJ71CikDgkhw8M90ojfRIowqpl0uLA3kW3PEZy9
-----END PRIVATE KEY-----
";
    const VERIF_KEY: &str = r#"
    {
        "kty":"EC",
        "crv":"P-256",
        "x":"G8fAud93NgCg8C_0bY1YqVZ5zNlkb-cNsGTQia7m0is",
        "y":"RK1gonvUKKQOCSHDwz3SiN9EijCqmXS4sDeRbc8RnL0"
    }
    "#;

    #[test]
    fn sign_jwk() {
        let ear = Ear {
            profile: "test".to_string(),
            iat: 1,
            vid: VerifierID {
                build: "vsts 0.0.1".to_string(),
                developer: "https://veraison-project.org".to_string(),
            },
            raw_evidence: None,
            nonce: None,
            submods: BTreeMap::from([("test".to_string(), Appraisal::new())]),
        };

        let signed = ear
            .sign_jwt_pem(Algorithm::ES256, SIGNING_KEY.as_bytes())
            .unwrap();

        let ear2 =
            Ear::from_jwt_jwk(signed.as_str(), Algorithm::ES256, VERIF_KEY.as_bytes()).unwrap();

        assert_eq!(ear, ear2);
    }

    #[test]
    fn cose() {
        let ear = Ear {
            profile: "test".to_string(),
            iat: 1,
            vid: VerifierID {
                build: "vsts 0.0.1".to_string(),
                developer: "https://veraison-project.org".to_string(),
            },
            raw_evidence: None,
            nonce: None,
            submods: BTreeMap::from([("test".to_string(), Appraisal::new())]),
        };

        let signed = ear
            .sign_cose_pem(Algorithm::ES256, SIGNING_KEY.as_bytes())
            .unwrap();

        let ear2 =
            Ear::from_cose_jwk(signed.as_slice(), Algorithm::ES256, VERIF_KEY.as_bytes()).unwrap();

        assert_eq!(ear, ear2);
    }

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
                0xbf, // map (indefinte length)
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
                0xff, // break
                0x19, // unsigned int in the next 2 bytes
                0x03, 0xea, // 1002
                0x4f, // byte string (15)
                0x37, 0x34, 0x37, 0x32, 0x36, 0x39, 0x37, 0x33, 0x36, 0x35, 0x36, 0x33, 0x37, 0x34,
                0x0a, 0xff,
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
    fn verify() {
        const VERIF_KEY: &str = r#"
        {
            "crv": "P-256",
            "kty": "EC",
            "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
            "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"
        }
        "#;

        let ear_jwt = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJlYXIudmVyaWZpZXItaWQiOnsiYnVpbGQiOiJOL0EiLCJkZXZlbG9wZXIiOiJWZXJhaXNvbiBQcm9qZWN0In0sImVhdF9ub25jZSI6IjNXSHlqbmRHT1RJPSIsImVhdF9wcm9maWxlIjoidGFnOmdpdGh1Yi5jb20sMjAyMzp2ZXJhaXNvbi9lYXIiLCJpYXQiOjE3MDQ5MDgxOTUsInN1Ym1vZHMiOnsiUEFSU0VDX1RQTSI6eyJlYXIuYXBwcmFpc2FsLXBvbGljeS1pZCI6InBvbGljeTpQQVJTRUNfVFBNIiwiZWFyLnN0YXR1cyI6ImFmZmlybWluZyIsImVhci50cnVzdHdvcnRoaW5lc3MtdmVjdG9yIjp7ImNvbmZpZ3VyYXRpb24iOjAsImV4ZWN1dGFibGVzIjoyLCJmaWxlLXN5c3RlbSI6MCwiaGFyZHdhcmUiOjIsImluc3RhbmNlLWlkZW50aXR5IjoyLCJydW50aW1lLW9wYXF1ZSI6MCwic291cmNlZC1kYXRhIjowLCJzdG9yYWdlLW9wYXF1ZSI6MH0sImVhci52ZXJhaXNvbi5hbm5vdGF0ZWQtZXZpZGVuY2UiOnsia2F0Ijp7ImNlcnRJbmZvIjoiLzFSRFI0QVhBQ0lBQzRPZnJLT0ZLSGxhM2pFelVQSzNNSkNTK1cydHdCVlRFREY4RTk2dzFWWlpBQWdBQVFJREJBVUdCd0FBQUFBYXZJOTFPSFRnOTNOdHliUUJETTZINVJSQTFjNEFJZ0FMM3p1UDlHSy96MXhBR3Fuc1Zxd0ZxU09BdkxVUExoQUkrTmErOFV3VmZWWUFJZ0FMNGhRWm1kbXJaN05vbEExdmRXbEJMeC96TXQ0RldhSWt1R3JoWEdHUkJpWT0iLCJraWQiOiJBYUZKUUNRSDNzT3RxSFdUVWs2WjUrZncvazE4dnl2SkVuWXcxTTdrVHZ0VCIsInB1YkFyZWEiOiJBQ01BQ3dBRUFISUFBQUFRQUJnQUN3QURBQkFBSUtFL0JCMjJySmFDbktRK3BxM05PeEQxcmJaNXp5ZituTThzMS9jbDlwd1RBQ0IyUDlCb2gwcDlEYmlqYUdpVVF1ZkRHWDNaL0ZYZFVqd3JCTUZEKzlPTW53PT0iLCJzaWciOiJBQmdBQ3dBZzA4SkVGY1lxRmsrUnpPVHZvaUp0K1JMOEZvd3oxNzVMakVmTW1KTHcyOU1BSUJLbDQ3eWJyYmdmOTltK21DblVDbkZtTFRNZDN5MUFLTWVoaFNiWEMvYzQiLCJ0cG1WZXIiOiIyLjAifSwicGF0Ijp7ImF0dGVzdEluZm8iOiIvMVJEUjRBWUFDSUFDNE9mcktPRktIbGEzakV6VVBLM01KQ1MrVzJ0d0JWVEVERjhFOTZ3MVZaWkFBZ0FBUUlEQkFVR0J3QUFBQUFhdkk5Mk9IVGc5M050eWJRQkRNNkg1UlJBMWM0QUFBQUJBQXNEQndBQUFDQXVxYXVSbU5GamdBZEFETkxEdnZITWRGdUdTM1lCR2c0YnhTR0FyR1JTMUE9PSIsImtpZCI6IkFhRkpRQ1FIM3NPdHFIV1RVazZaNStmdy9rMTh2eXZKRW5ZdzFNN2tUdnRUIiwic2lnIjoiQUJnQUN3QWdNcWN0TlRuZFh3VU5MZkNERW1lOC81c0hVM2diaGFPL05OdW4xY2tpT0xBQUlLVFkwU2VWUUJIWkpuaXNPRzNTb2VOQ1dHYTJnWlMrSUhuWkN2M3dUOTVJIiwidHBtVmVyIjoiMi4wIn19LCJlYXIudmVyYWlzb24ua2V5LWF0dGVzdGF0aW9uIjp7ImFrcHViIjoiTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFb1Q4RUhiYXNsb0tjcEQ2bXJjMDdFUFd0dG5uUEpfNmN6eXpYOXlYMm5CTjJQOUJvaDBwOURiaWphR2lVUXVmREdYM1pfRlhkVWp3ckJNRkQtOU9NbncifX19fQ.eRyCRmGEOt2GeMvi1-PiSaIVOuixBHwz8FYPSm7XuKnZd6XYe_8HQaCXEtarpOppvzoyHcZvU_4rV54iE7PQaw";

        let ear = Ear::from_jwt_jwk(ear_jwt, Algorithm::ES256, VERIF_KEY.as_bytes())
            .expect("successfully verified");

        assert_eq!("tag:github.com,2023:veraison/ear", ear.profile);
    }
}
