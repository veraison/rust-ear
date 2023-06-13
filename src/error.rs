// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("format error: {0}")]
    FormatError(String),
    #[error("sign error: {0}")]
    SignError(String),
    #[error("verify error: {0}")]
    VerifyError(String),
    #[error("key error: {0}")]
    KeyError(String),
    #[error("validation error: {0}")]
    ValidationError(String),
    #[error("invalid value: {0}")]
    InvalidValue(i8),
    #[error("invalid name: {0}")]
    InvalidName(String),
    #[error("invalid key: {0}")]
    InvalidKey(i32),
}
