// SPDX-License-Identifier: Apache-2.0

use jsonwebtoken::{self as jwt, jwk};

use crate::algorithm::Algorithm;
use crate::error::Error;
use crate::Ear;

impl Ear {
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
        // the default validation sets "exp" as a mandatory claim, which an EAR is not required to
        // have.
        validation.set_required_spec_claims::<&str>(&[]);

        let token_data =
            jwt::decode(token, key, &validation).map_err(|e| Error::VerifyError(e.to_string()))?;
        Ok(token_data.claims)
    }

    /// Encode the EAR as a JWT token, signing it with the specified PEM-encoded key
    #[allow(clippy::type_complexity)]
    pub fn sign_jwt_pem(&self, alg: Algorithm, key: &[u8]) -> Result<String, Error> {
        let header = &jwt::Header::new(alg_to_jwt_alg(&alg)?);
        self.sign_jwt_pem_with_header(header, key)
    }

    /// Encode the EAR as a JWT token, signing it with the specified PEM-encoded key, and including
    /// the provided headers.
    pub fn sign_jwt_pem_with_header(
        &self,
        header: &jwt::Header,
        key: &[u8],
    ) -> Result<String, Error> {
        let keyfunc: fn(&[u8]) -> Result<jwt::EncodingKey, jwt::errors::Error> = match header.alg {
            jwt::Algorithm::ES256 => jwt::EncodingKey::from_ec_pem,
            jwt::Algorithm::ES384 => jwt::EncodingKey::from_ec_pem,
            jwt::Algorithm::EdDSA => jwt::EncodingKey::from_ed_pem,
            jwt::Algorithm::PS256 => jwt::EncodingKey::from_rsa_pem,
            jwt::Algorithm::PS384 => jwt::EncodingKey::from_rsa_pem,
            jwt::Algorithm::PS512 => jwt::EncodingKey::from_rsa_pem,
            _ => {
                return Err(Error::SignError(format!(
                    "algorithm {0:?} not supported",
                    header.alg
                )))
            }
        };

        let ek = keyfunc(key).map_err(|e| Error::KeyError(e.to_string()))?;

        jwt::encode(header, self, &ek).map_err(|e| Error::SignError(e.to_string()))
    }

    /// Encode the EAR as a JWT token, signing it with the specified DER-encoded key
    pub fn sign_jwk_der(&self, alg: Algorithm, key: &[u8]) -> Result<String, Error> {
        let header = &jwt::Header::new(alg_to_jwt_alg(&alg)?);
        self.sign_jwk_der_with_header(header, key)
    }

    /// Encode the EAR as a JWT token, signing it with the specified DER-encoded key,
    /// including the specified header(s).
    pub fn sign_jwk_der_with_header(
        &self,
        header: &jwt::Header,
        key: &[u8],
    ) -> Result<String, Error> {
        let ek = match header.alg {
            jwt::Algorithm::ES256 => jwt::EncodingKey::from_ec_der(key),
            jwt::Algorithm::ES384 => jwt::EncodingKey::from_ec_der(key),
            jwt::Algorithm::EdDSA => jwt::EncodingKey::from_ed_der(key),
            jwt::Algorithm::PS256 => jwt::EncodingKey::from_rsa_der(key),
            jwt::Algorithm::PS384 => jwt::EncodingKey::from_rsa_der(key),
            jwt::Algorithm::PS512 => jwt::EncodingKey::from_rsa_der(key),
            _ => {
                return Err(Error::SignError(format!(
                    "algorithm {:?} not supported",
                    header.alg
                )))
            }
        };

        jwt::encode(header, self, &ek).map_err(|e| Error::SignError(e.to_string()))
    }
}

#[inline]
pub fn new_jwt_header(alg: &Algorithm) -> Result<jwt::Header, Error> {
    Ok(jwt::Header::new(alg_to_jwt_alg(alg)?))
}

#[inline]
fn alg_to_jwt_alg(alg: &Algorithm) -> Result<jwt::Algorithm, Error> {
    match alg {
        Algorithm::ES256 => Ok(jwt::Algorithm::ES256),
        Algorithm::ES384 => Ok(jwt::Algorithm::ES384),
        Algorithm::EdDSA => Ok(jwt::Algorithm::EdDSA),
        Algorithm::PS256 => Ok(jwt::Algorithm::PS256),
        Algorithm::PS384 => Ok(jwt::Algorithm::PS384),
        Algorithm::PS512 => Ok(jwt::Algorithm::PS512),
        _ => Err(Error::SignError(format!("algorithm {alg:?} not supported"))),
    }
}

#[cfg(test)]
#[rustfmt::skip::macros(vec)]
mod test {
    use super::*;
    use crate::{Appraisal, Extensions, VerifierID, EAR_PROFILE};
    use std::collections::BTreeMap;

    #[test]
    fn sign_jwk() {
        let ear = Ear {
            profile: EAR_PROFILE.to_string(),
            iat: 1,
            exp: None,
            vid: VerifierID {
                build: "vsts 0.0.1".to_string(),
                developer: "https://veraison-project.org".to_string(),
            },
            raw_evidence: None,
            nonce: None,
            status: None,
            topology: None,
            submods: BTreeMap::from([("test".to_string(), Appraisal::new())]),
            extensions: Extensions::new(),
        };

        let signed = ear
            .sign_jwt_pem(Algorithm::ES256, crate::ear::test::SIGNING_KEY.as_bytes())
            .unwrap();

        let ear2 = Ear::from_jwt_jwk(
            signed.as_str(),
            Algorithm::ES256,
            crate::ear::test::VERIF_KEY.as_bytes(),
        )
        .unwrap();

        assert_eq!(ear, ear2);
    }

    #[test]
    fn verify_signed_ear() {
        let ear = Ear {
            profile: EAR_PROFILE.to_string(),
            iat: 1704908195,
            exp: None,
            vid: VerifierID {
                build: "N/A".to_string(),
                developer: "Veraison Project".to_string(),
            },
            raw_evidence: None,
            nonce: None,
            status: None,
            topology: None,
            submods: BTreeMap::from([("PARSEC_TPM".to_string(), Appraisal::new())]),
            extensions: Extensions::new(),
        };

        let signed = ear
            .sign_jwt_pem(Algorithm::ES256, crate::ear::test::SIGNING_KEY.as_bytes())
            .unwrap();

        let ear2 = Ear::from_jwt_jwk(
            signed.as_str(),
            Algorithm::ES256,
            crate::ear::test::VERIF_KEY.as_bytes(),
        )
        .unwrap();

        assert_eq!(EAR_PROFILE, ear2.profile);
    }
}
