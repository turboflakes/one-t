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
use derive_more::Display;
use onet_cache::error::CacheError;
use onet_dn::error::DnError;
use onet_mcda::error::McdaError;
use serde::{Deserialize, Serialize};
use std::string::String;
use thiserror::Error;

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

/// Convert CacheError to ApiErrors
impl From<CacheError> for ApiError {
    fn from(error: CacheError) -> Self {
        ApiError::InternalServerError(error.into())
    }
}

/// Convert McdaError to ApiErrors
impl From<McdaError> for ApiError {
    fn from(error: McdaError) -> Self {
        ApiError::InternalServerError(error.into())
    }
}

/// Convert DnError to ApiErrors
impl From<DnError> for ApiError {
    fn from(error: DnError) -> Self {
        ApiError::InternalServerError(error.into())
    }
}
