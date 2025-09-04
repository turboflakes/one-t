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

use codec;
use std::{str::Utf8Error, string::String};
use subxt_metadata::TryFromError as MetadataTryFromError;
use thiserror::Error;

/// On specific error messages
#[derive(Error, Debug)]
pub enum OnetError {
    #[error("Cache error: {0}")]
    CacheError(#[from] onet_cache::error::CacheError),
    #[error("Report error: {0}")]
    ReportError(#[from] onet_report::error::ReportError),
    #[error("DN error: {0}")]
    DnError(#[from] onet_dn::error::DnError),
    #[error("Matrix error: {0}")]
    MatrixError(#[from] onet_matrix::error::MatrixError),
    #[error("Subxt error: {0}")]
    SubxtError(#[from] subxt::Error),
    #[error("SubxtCore error: {0}")]
    SubxtCoreError(#[from] subxt::ext::subxt_core::Error),
    #[error("RPC error: {0}")]
    RpcError(#[from] subxt::ext::subxt_rpcs::Error),
    #[error("Metadata error: {0}")]
    MetadataError(#[from] subxt::error::MetadataError),
    #[error("Metadata Decoding error: {0}")]
    MetadataDecoding(#[from] MetadataTryFromError),
    #[error("Codec error: {0}")]
    CodecError(#[from] codec::Error),
    #[error("Utf8 error: {0}")]
    Utf8Error(#[from] Utf8Error),
    #[error("Subscription finished")]
    SubscriptionFinished,
    #[error("SerdeError error: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("IOError error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Nomination pool error: {0}")]
    PoolError(String),
    #[error("Box error: {0}")]
    BoxError(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("Other error: {0}")]
    Other(String),
}

/// Convert &str to OnetError
impl From<&str> for OnetError {
    fn from(error: &str) -> Self {
        OnetError::Other(error.into())
    }
}

/// Convert String to OnetError
impl From<String> for OnetError {
    fn from(error: String) -> Self {
        OnetError::Other(error)
    }
}

/// Convert OnetError to String
impl From<OnetError> for String {
    fn from(error: OnetError) -> Self {
        format!("{}", error).to_string()
    }
}
