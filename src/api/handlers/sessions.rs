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
    responses::{CacheMap, SessionResult, SessionStats, SessionsResult, ValidatorResult},
};
use crate::cache::{get_conn, CacheKey, Index, RedisPool, Verbosity};
use crate::errors::{ApiError, CacheError};
use crate::records::EpochIndex;
use actix_web::web::{Data, Json, Path, Query};
use log::warn;
use redis::aio::Connection;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Params {
    #[serde(default = "default_number_last_sessions")]
    number_last_sessions: u32,
    // show_stats indicates whether session stats should be retrieved or not, default false
    #[serde(default)]
    show_stats: bool,
}

fn default_number_last_sessions() -> u32 {
    48
}

/// Pull, Compile and cache stats result
async fn pull_and_cache_stats(
    index: EpochIndex,
    cache: Data<RedisPool>,
) -> Result<CacheMap, ApiError> {
    let mut conn = get_conn(&cache).await?;

    let authority_keys: Vec<String> = redis::cmd("SMEMBERS")
        .arg(CacheKey::AuthorityKeysBySession(index))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    let mut data: Vec<ValidatorResult> = Vec::new();
    for key in authority_keys.iter() {
        let mut auth_data: CacheMap = redis::cmd("HGETALL")
            .arg(key)
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;

        let summary: CacheMap = redis::cmd("HGETALL")
            .arg(CacheKey::AuthorityRecordVerbose(
                key.to_string(),
                Verbosity::Summary,
            ))
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;
        auth_data.extend(summary);

        data.push(auth_data.into());
    }

    let stats: SessionStats = data.into();
    let serialized = serde_json::to_string(&stats)?;
    let result = CacheMap::from([(String::from("stats"), serialized)]);

    redis::cmd("HSET")
        .arg(CacheKey::SessionByIndexStats(Index::Num(index)))
        .arg(result.clone())
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(result)
}

/// Get a sessions filtered by query params
pub async fn get_sessions(
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<SessionsResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;

    let current_session: EpochIndex = redis::cmd("GET")
        .arg(CacheKey::SessionByIndex(Index::Current))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    let mut data: Vec<SessionResult> = Vec::new();
    let mut last = Some(current_session - params.number_last_sessions);
    while let Some(session_index) = last {
        if session_index >= current_session {
            last = None;
        } else {
            let mut session_data: CacheMap = redis::cmd("HGETALL")
                .arg(CacheKey::SessionByIndex(Index::Num(session_index)))
                .query_async(&mut conn as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;

            if session_data.is_empty() || session_data.get("session").is_none() {
                session_data.insert(String::from("session"), session_index.to_string());
            }

            if params.show_stats {
                let mut session_stats_data: CacheMap = redis::cmd("HGETALL")
                    .arg(CacheKey::SessionByIndexStats(Index::Num(session_index)))
                    .query_async(&mut conn as &mut Connection)
                    .await
                    .map_err(CacheError::RedisCMDError)?;

                if session_stats_data.is_empty() {
                    let mut latest = pull_and_cache_stats(session_index, cache.clone()).await?;
                    session_stats_data.append(&mut latest);
                }

                session_data.append(&mut session_stats_data);
            }

            data.push(session_data.into());

            last = Some(session_index + 1);
        }
    }

    respond_json(data.into())
}

/// Get current session details
pub async fn get_session_by_index(
    index: Path<String>,
    cache: Data<RedisPool>,
) -> Result<Json<SessionResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;

    let current: String = redis::cmd("GET")
        .arg(CacheKey::SessionByIndex(Index::Current))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    let index: Index = if String::from("current") == index.to_string() {
        Index::Str(current.clone())
    } else {
        Index::Str(index.to_string())
    };

    let mut data: CacheMap = redis::cmd("HGETALL")
        .arg(CacheKey::SessionByIndex(index))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    if data.is_empty() {
        let msg = format!("Current session details not found");
        warn!("{}", msg);
        return Err(ApiError::NotFound(msg));
    }

    // check if is_current session
    if let Some(session) = data.get("session") {
        if current == *session {
            data.insert(String::from("is_current"), (true).to_string());
        }
    }

    respond_json(data.into())
}
