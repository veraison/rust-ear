// SPDX-License-Identifier: Apache-2.0

/// Singing algorithms supported by this implementation
///
/// Not all algorithms are supported by all serialization formats. JWT does not support ES512; COSE
/// does not support PS256, PS384, and PS512.
#[derive(Debug)]
pub enum Algorithm {
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    ES512,
    EdDSA,
}
