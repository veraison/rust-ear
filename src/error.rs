// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

/// EAR errors
#[derive(Error, Debug)]
pub enum Error {
    /// an error occured while parsing serialized structures
    #[error("parse error: {0}")]
    ParseError(String),
    /// an error occured while formatting structures
    #[error("format error: {0}")]
    FormatError(String),
    /// an error occured during signing
    #[error("sign error: {0}")]
    SignError(String),
    /// an error occured during verification
    #[error("verify error: {0}")]
    VerifyError(String),
    /// an error occured while processing cryptographic keys
    #[error("key error: {0}")]
    KeyError(String),
    /// an error occured during validation of the internal integrity of structures
    #[error("validation error: {0}")]
    ValidationError(String),
    // invalid claim value
    #[error("invalid value: {0}")]
    InvalidValue(i8),
    // invalid string name
    #[error("invalid name: {0}")]
    InvalidName(String),
    // invalid integer key
    #[error("invalid key: {0}")]
    InvalidKey(i32),
}
