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
    use crate::{Appraisal, Extensions, VerifierID};
    use std::collections::BTreeMap;

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
