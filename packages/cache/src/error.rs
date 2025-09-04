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

use std::string::String;
use thiserror::Error;

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
    #[error("SerdeError error: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("Other error: {0}")]
    Other(String),
}

/// Convert CacheError to Sttring
impl From<CacheError> for String {
    fn from(error: CacheError) -> Self {
        format!("{}", error).to_string()
    }
}
