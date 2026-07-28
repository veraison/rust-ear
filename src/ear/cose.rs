// SPDX-License-Identifier: Apache-2.0

use core::ops::DerefMut;

use cose::message::CoseMessage;
use jsonwebtoken::{self as jwt, jwk};
use openssl::{bn, ec, nid::Nid, pkey};

use crate::algorithm::Algorithm;
use crate::base64;
use crate::error::Error;
use crate::Ear;

#[allow(clippy::upper_case_acronyms)]
enum KeyFormat {
    PEM,
    DER,
}

impl Ear {
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

    /// Encode the EAR as a COSE token, signing it with the specified PEM-encoded key
    pub fn sign_cose_pem(&self, alg: Algorithm, key: &[u8]) -> Result<Vec<u8>, Error> {
        let header = new_cose_header(&alg)?;
        self.sign_cose_bytes_with_header(header, key, KeyFormat::PEM)
    }

    /// Encode the EAR as a COSE token, signing it with the specified DER-encoded key
    pub fn sign_cose_der(&self, alg: Algorithm, key: &[u8]) -> Result<Vec<u8>, Error> {
        let header = new_cose_header(&alg)?;
        self.sign_cose_bytes_with_header(header, key, KeyFormat::DER)
    }

    /// Encode the EAR as a COSE token with the specified header, signing it with the specified
    /// PEM-encoded key
    pub fn sign_cose_pem_with_header(
        &self,
        header: cose::headers::CoseHeader,
        key: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.sign_cose_bytes_with_header(header, key, KeyFormat::PEM)
    }

    /// Encode the EAR as a COSE token with the specified header, signing it with the specified
    /// DER-encoded key
    pub fn sign_cose_der_with_header(
        &self,
        header: cose::headers::CoseHeader,
        key: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.sign_cose_bytes_with_header(header, key, KeyFormat::DER)
    }

    fn sign_cose_bytes_with_header(
        &self,
        header: cose::headers::CoseHeader,
        key: &[u8],
        key_fmt: KeyFormat,
    ) -> Result<Vec<u8>, Error> {
        let cose_alg = header
            .alg
            .ok_or(Error::SignError("alg header must be set".to_string()))?;

        let mut cose_key = cose::keys::CoseKey::new();
        cose_key.alg(cose_alg);
        cose_key.key_ops(vec![cose::keys::KEY_OPS_SIGN]);

        match cose_alg {
            cose::algs::ES256 | cose::algs::ES384 | cose::algs::PS512 => {
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
            cose::algs::EDDSA => {
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
            _ => {
                return Err(Error::SignError(format!(
                    "algorithm {cose_alg:?} not supported"
                )))
            }
        };

        self.sign_cose_with_header(header, &cose_key)
    }

    fn sign_cose_with_header(
        &self,
        header: cose::headers::CoseHeader,
        key: &cose::keys::CoseKey,
    ) -> Result<Vec<u8>, Error> {
        let mut payload: Vec<u8> = Vec::new();
        ciborium::ser::into_writer(self, &mut payload)
            .map_err(|e| Error::SignError(e.to_string()))?;

        let mut sign1 = CoseMessage::new_sign();
        sign1.payload(payload);
        sign1.add_header(header);

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
}

#[inline]
pub fn new_cose_header(alg: &Algorithm) -> Result<cose::headers::CoseHeader, Error> {
    let cose_alg = alg_to_cose(alg)?;
    let mut header = cose::headers::CoseHeader::new();
    header.alg(cose_alg, true, false);

    Ok(header)
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
#[rustfmt::skip::macros(vec)]
mod test {
    use super::*;
    use crate::{Appraisal, Extensions, VerifierID, EAR_PROFILE};
    use std::collections::BTreeMap;

    #[test]
    fn cose() {
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
            .sign_cose_pem(Algorithm::ES256, crate::ear::test::SIGNING_KEY.as_bytes())
            .unwrap();

        let ear2 = Ear::from_cose_jwk(
            signed.as_slice(),
            Algorithm::ES256,
            crate::ear::test::VERIF_KEY.as_bytes(),
        )
        .unwrap();

        assert_eq!(ear, ear2);
    }
}
