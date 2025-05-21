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

use crate::{
    handlers::params::Params,
    helpers::respond_json,
    responses::{CacheMap, SessionResult, SessionsResult},
};
use actix_web::{
    web::{Data, Json, Path, Query},
    HttpRequest,
};
use log::warn;
use onet_cache::{
    provider::{get_conn, RedisPool},
    types::{CacheKey, Index},
};
use onet_config::CONFIG;
use onet_errors::{ApiError, CacheError};
use onet_records::EpochIndex;
use redis::aio::Connection;

/// Get a sessions filtered by query params
pub async fn get_sessions(
    req: HttpRequest,
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<SessionsResult>, ApiError> {
    let config = CONFIG.clone();
    let mut conn = get_conn(&cache).await?;

    let current_session: EpochIndex = redis::cmd("GET")
        .arg(CacheKey::SessionByIndex(Index::Current))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    let (start_session, end_session) = if params.from != 0 && params.from < params.to {
        (params.from, params.to)
    } else if params.number_last_sessions != 0 {
        (
            current_session - params.number_last_sessions,
            current_session - 1,
        )
    } else {
        (current_session, current_session)
    };

    // Try if query exists in cache
    if params.from != 0 && params.from < params.to && params.show_netstats {
        // Check if query is already cached
        if let Ok(serialized_data) = redis::cmd("GET")
            .arg(CacheKey::QuerySessions(req.query_string().to_string()))
            .query_async::<Connection, String>(&mut conn)
            .await
        {
            let data: Vec<SessionResult> = serde_json::from_str(&serialized_data).unwrap();
            return respond_json(data.into());
        }
    }

    let mut cache_query = true;
    let mut data: Vec<SessionResult> = Vec::new();
    let mut i = Some(start_session);
    while let Some(session_index) = i {
        if session_index > end_session {
            i = None;
        } else {
            let mut session_data: CacheMap = redis::cmd("HGETALL")
                .arg(CacheKey::SessionByIndex(Index::Num(session_index.into())))
                .query_async(&mut conn as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;

            if session_data.is_empty() || session_data.get("session").is_none() {
                session_data.insert(String::from("session"), session_index.to_string());
            }

            if params.show_stats {
                if let Ok(serialized_data) = redis::cmd("GET")
                    .arg(CacheKey::SessionByIndexStats(Index::Num(
                        session_index.into(),
                    )))
                    .query_async::<Connection, String>(&mut conn)
                    .await
                {
                    session_data.insert(String::from("stats"), serialized_data);
                } else {
                    session_data.insert(String::from("is_syncing"), (true).to_string());
                    cache_query = false;
                }
            }

            if params.show_netstats {
                if let Ok(serialized_data) = redis::cmd("GET")
                    .arg(CacheKey::NetworkStatsBySession(Index::Num(
                        session_index.into(),
                    )))
                    .query_async::<Connection, String>(&mut conn)
                    .await
                {
                    session_data.insert(String::from("netstats"), serialized_data);
                } else {
                    session_data.insert(String::from("is_syncing"), (true).to_string());
                    cache_query = false;
                }
            }

            data.push(session_data.into());

            i = Some(session_index + 1);
        }
    }

    // // TODO: cache only when new session sync is complete
    // Cache specific query
    if params.from != 0 && params.from < params.to && params.show_netstats && cache_query {
        // Serialize data and cache for one session
        // 1 hour kusama, 4 hours polkadot
        let serialized = serde_json::to_string(&data)?;
        redis::cmd("SET")
            .arg(CacheKey::QuerySessions(req.query_string().to_string()))
            .arg(serialized.to_string())
            .arg("ex")
            .arg(config.blocks_per_session * 6)
            .query_async::<Connection, String>(&mut conn)
            .await
            .map_err(CacheError::RedisCMDError)?;
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
