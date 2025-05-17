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

use crate::helpers::respond_json;
use actix_web::web::{Data, Json};
use onet_cache::provider::{get_conn, RedisPool};
use onet_errors::{ApiError, CacheError};
use redis::aio::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct HealthResponse {
    pub status: String,
}

/// Handler to get the liveness of the service
pub async fn get_health(cache: Data<RedisPool>) -> Result<Json<HealthResponse>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let pong: String = redis::cmd("PING")
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    if pong.as_str() != "PONG" {
        return Err(CacheError::RedisPongError.into());
    }
    respond_json(HealthResponse {
        status: "ok".into(),
    })
}
