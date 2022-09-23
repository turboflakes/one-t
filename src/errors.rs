// The MIT License (MIT)
// Copyright © 2021 Aukbit Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use actix_web::{error::ResponseError, HttpResponse};
use codec;
use derive_more::Display;
use reqwest;
use serde::{Deserialize, Serialize};
use std::{str::Utf8Error, string::String};
use subxt;
use thiserror::Error;

/// On specific error messages
#[derive(Error, Debug)]
pub enum OnetError {
    #[error("Cache error: {0}")]
    CacheError(#[from] CacheError),
    #[error("Subxt error: {0}")]
    SubxtError(#[from] subxt::BasicError),
    #[error("Codec error: {0}")]
    CodecError(#[from] codec::Error),
    #[error("Utf8 error: {0}")]
    Utf8Error(#[from] Utf8Error),
    #[error("Metadata error: {0}")]
    MetadataError(#[from] subxt::MetadataError),
    #[error("Matrix error: {0}")]
    MatrixError(String),
    #[error("Subscription finished")]
    SubscriptionFinished,
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("ParseError error: {0}")]
    ParseError(#[from] url::ParseError),
    #[error("SerdeError error: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("IOError error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Nomination pool error: {0}")]
    PoolError(String),
    #[error("Other error: {0}")]
    Other(String),
}

/// Convert &str to OnetError
impl From<&str> for OnetError {
    fn from(error: &str) -> Self {
        OnetError::Other(error.into())
    }
}

/// Convert OnetError to String
impl From<OnetError> for String {
    fn from(error: OnetError) -> Self {
        format!("{}", error).to_string()
    }
}

/// Onet specific error messages
#[derive(Error, Debug)]
pub enum MatrixError {
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("ParseError error: {0}")]
    ParseError(#[from] url::ParseError),
    #[error("SerdeError error: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("IOError error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

/// Convert MatrixError to String
impl From<MatrixError> for String {
    fn from(error: MatrixError) -> Self {
        format!("{}", error).to_string()
    }
}

/// Convert MatrixError to OnetError
impl From<MatrixError> for OnetError {
    fn from(error: MatrixError) -> Self {
        OnetError::MatrixError(error.into())
    }
}

#[derive(Error, Debug, Display, PartialEq)]
pub enum ApiError {
    #[allow(dead_code)]
    BadRequest(String),
    NotFound(String),
    InternalServerError(String),
}

/// Automatically convert ApiErrors to external Response Errors
impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ApiError::BadRequest(error) => {
                // let error_resp: ErrorResponse = error.into();
                HttpResponse::BadRequest().json(ErrorResponse::from(error))
            }
            ApiError::NotFound(message) => {
                HttpResponse::NotFound().json(ErrorResponse::from(message))
            }
            ApiError::InternalServerError(error) => {
                HttpResponse::InternalServerError().json(ErrorResponse::from(error))
            }
        }
    }
}

impl From<&str> for ApiError {
    fn from(error: &str) -> Self {
        ApiError::InternalServerError(error.into())
    }
}

/// User-friendly error messages
#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    errors: Vec<String>,
}

/// Utility to make transforming a string reference into an ErrorResponse
impl From<&String> for ErrorResponse {
    fn from(error: &String) -> Self {
        ErrorResponse {
            errors: vec![error.into()],
        }
    }
}

/// Convert io::Error to ApiError
impl From<std::io::Error> for ApiError {
    fn from(error: std::io::Error) -> Self {
        ApiError::InternalServerError(format!("{:?}", error))
    }
}

/// Convert serde_json::Error to ApiError
impl From<serde_json::Error> for ApiError {
    fn from(error: serde_json::Error) -> Self {
        ApiError::InternalServerError(format!("{:?}", error))
    }
}

/// Cache specific error messages
#[derive(Error, Debug)]
pub enum CacheError {
    #[error("Could not get redis connection from pool : {0}")]
    RedisPoolError(mobc::Error<mobc_redis::redis::RedisError>),
    #[error("Error parsing string from redis result: {0}")]
    RedisTypeError(mobc_redis::redis::RedisError),
    #[error("Error executing redis command: {0}")]
    RedisCMDError(mobc_redis::redis::RedisError),
    #[error("Error creating redis client: {0}")]
    RedisClientError(mobc_redis::redis::RedisError),
    #[error("Pong response error")]
    RedisPongError,
    #[error("Other error: {0}")]
    Other(String),
}

/// Convert CacheError to Sttring
impl From<CacheError> for String {
    fn from(error: CacheError) -> Self {
        format!("{}", error).to_string()
    }
}

/// Convert CacheError to ApiErrors
impl From<CacheError> for ApiError {
    fn from(error: CacheError) -> Self {
        ApiError::InternalServerError(error.into())
    }
}
