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

use crate::api::{
    helpers::respond_json,
    responses::{CacheMap, SessionResult},
};
use crate::cache::{get_conn, CacheKey, Index, RedisPool};
use crate::errors::{ApiError, CacheError};
use actix_web::web::{Data, Json, Path};
use log::warn;
use redis::aio::Connection;

/// Get current session details
pub async fn get_session_by_index(
    index: Path<String>,
    cache: Data<RedisPool>,
) -> Result<Json<SessionResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;

    let data: CacheMap = redis::cmd("HGETALL")
        .arg(CacheKey::SessionByIndex(Index::Str(index.to_string())))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    if data.is_empty() {
        let msg = format!("Current session details not found");
        warn!("{}", msg);
        return Err(ApiError::NotFound(msg));
    }
    respond_json(data.into())
}
