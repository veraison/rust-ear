// SPDX-License-Identifier: Apache-2.0

//! An implementation of EAT Attestation Results token.
//!
//! This crate provides an implementation of attestation results tokens that conforms to
//! [draft-fv-rats-ear-00] specification. This defines a token intended to communicate a set of
//! appraisals of attested evidence produced by a verifier. Each appraisal is based around a set of
//! trust claims defined by [draft-ietf-rats-ar4si-04].
//!
//! The attestation result may be serialized as a signed JSON or CBOR token (using JWT and COSE,
//! respectively).
//!
//! [draft-fv-rats-ear-00]: https://datatracker.ietf.org/doc/html/draft-fv-rats-ear-00
//! [draft-ietf-rats-ar4si-04]: https://datatracker.ietf.org/doc/html/draft-ietf-rats-ar4si-04
//!
//! # Examples
//!
//! ## Signing
//!
//! ```
//! use std::collections::BTreeMap;
//! use ear::{Ear, VerifierID, Algorithm, Appraisal};
//!
//! const SIGNING_KEY: &str = "-----BEGIN PRIVATE KEY-----
//! MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPp4XZRnRHSMhGg0t
//! 6yjQCRV35J4TUY4idLgiCu6EyLqhRANCAAQbx8C533c2AKDwL/RtjVipVnnM2WRv
//! 5w2wZNCJrubSK0StYKJ71CikDgkhw8M90ojfRIowqpl0uLA3kW3PEZy9
//! -----END PRIVATE KEY-----
//! ";
//!
//! fn main() {
//!     let token = Ear{
//!         profile: "test".to_string(),
//!         iat: 1,
//!         vid: VerifierID {
//!             build: "vsts 0.0.1".to_string(),
//!             developer: "https://veraison-project.org".to_string(),
//!         },
//!         raw_evidence: None,
//!         nonce: None,
//!         submods: BTreeMap::from([("test".to_string(), Appraisal::new())]),
//!     };
//!
//!     let signed = token.sign_jwt_pem(Algorithm::ES256, SIGNING_KEY.as_bytes()).unwrap();
//! }
//! ```
//!
//! ## Verification
//!
//! ```
//! use ear::{Ear, Algorithm};
//!
//! const VERIF_KEY: &str = r#"
//! {
//!     "kty":"EC",
//!     "crv":"P-256",
//!     "x":"G8fAud93NgCg8C_0bY1YqVZ5zNlkb-cNsGTQia7m0is",
//!     "y":"RK1gonvUKKQOCSHDwz3SiN9EijCqmXS4sDeRbc8RnL0"
//! }
//! "#;
//!
//! fn main() {
//!     let signed = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJlYXRfcHJvZmlsZSI6InRlc3QiLCJpYXQiOjEsImVhci52ZXJpZmllci1pZCI6eyJkZXZlbG9wZXIiOiJodHRwczovL3ZlcmFpc29uLXByb2plY3Qub3JnIiwiYnVpbGQiOiJ2c3RzIDAuMC4xIn0sInN1Ym1vZHMiOnsidGVzdCI6eyJlYXIuc3RhdHVzIjoibm9uZSJ9fX0.G25v0j0NDQhSOcK3Jtfq5vqVxnoWuWf-Q0DCNkCwpyB03DGr25ZDJ3IDSAHVPZrr6TVMwj8RcGEzQnCrucem4Q";
//!
//!     let token = Ear::from_jwt_jwk(signed, Algorithm::ES256, VERIF_KEY.as_bytes()).unwrap();
//!     println!("EAR profiles: {}", token.profile);
//! }
//! ```
//!
//! # Limitations
//!
//! - Signing supports PEM and DER keys; verification currently only supports JWK
//!   keys.
//! - JWT signing currently only supports ES256, ES384, EdDSA, PS256, PS384, and
//!   PS512.
//! - COSE signing currently only supports ES256, ES384, ES512, and EdDSA.

mod algorithm;
mod appraisal;
mod base64;
mod ear;
mod error;
mod id;
mod key;
mod nonce;
mod raw;
mod trust;

pub use self::algorithm::Algorithm;
pub use self::appraisal::Appraisal;
pub use self::base64::Bytes;
pub use self::ear::Ear;
pub use self::error::Error;
pub use self::id::VerifierID;
pub use self::key::KeyAttestation;
pub use self::nonce::Nonce;
pub use self::raw::RawValue;
pub use self::trust::claim::TrustClaim;
pub use self::trust::tier::TrustTier;
pub use self::trust::vector::TrustVector;

/// trustworthiness claims
pub mod claim {
    pub use super::trust::claim::CRYPTO_VALIDATION_FAILED;
    pub use super::trust::claim::NO_CLAIM;
    pub use super::trust::claim::UNEXPECTED_EVIDENCE;
    pub use super::trust::claim::VERIFIER_MALFUNCTION;

    pub use super::trust::claim::TRUSTWORTHY_INSTANCE;
    pub use super::trust::claim::UNRECOGNIZED_INSTANCE;
    pub use super::trust::claim::UNTRUSTWORTHY_INSTANCE;

    pub use super::trust::claim::APPROVED_CONFIG;
    pub use super::trust::claim::NO_CONFIG_VULNS;
    pub use super::trust::claim::UNAVAIL_CONFIG_ELEMS;
    pub use super::trust::claim::UNSAFE_CONFIG;
    pub use super::trust::claim::UNSUPPORTABLE_CONFIG;

    pub use super::trust::claim::APPROVED_BOOT;
    pub use super::trust::claim::APPROVED_RUNTIME;
    pub use super::trust::claim::CONTRAINDICATED_RUNTIME;
    pub use super::trust::claim::UNRECOGNIZED_RUNTIME;
    pub use super::trust::claim::UNSAFE_RUNTIME;

    pub use super::trust::claim::APPROVED_FILES;
    pub use super::trust::claim::CONTRAINDICATED_FILES;
    pub use super::trust::claim::UNRECOGNIZED_FILES;

    pub use super::trust::claim::CONTRAINDICATED_HARDWARE;
    pub use super::trust::claim::GENUINE_HARDWARE;
    pub use super::trust::claim::UNRECOGNIZED_HARDWARE;
    pub use super::trust::claim::UNSAFE_HARDWARE;

    pub use super::trust::claim::ENCRYPTED_MEMORY_RUNTIME;
    pub use super::trust::claim::ISOLATED_MEMORY_RUNTIME;
    pub use super::trust::claim::VISIBLE_MEMORY_RUNTIME;

    pub use super::trust::claim::HW_KEYS_ENCRYPTED_SECRETS;
    pub use super::trust::claim::SW_KEYS_ENCRYPTED_SECRETS;
    pub use super::trust::claim::UNENCRYPTED_SECRETS;

    pub use super::trust::claim::CONTRAINDICATED_SOURCES;
    pub use super::trust::claim::TRUSTED_SOURCES;
    pub use super::trust::claim::UNTRUSTED_SOURCES;
}
