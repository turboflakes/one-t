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

use crate::error::ApiError;
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
    error::CacheError,
    provider::{get_conn, RedisPool},
    types::{CacheKey, Index},
};
use onet_config::CONFIG;
use onet_records::EpochIndex;
use redis::aio::MultiplexedConnection as Connection;
use std::collections::BTreeMap;

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
            .query_async::<String>(&mut conn as &mut Connection)
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
            let (session_data, is_complete) = get_session_data(
                &mut conn as &mut Connection,
                session_index,
                params.show_stats,
                params.show_netstats,
            )
            .await?;
            cache_query = cache_query && is_complete;

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
            .query_async::<String>(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;
    }

    respond_json(data.into())
}

/// Get the session data with the requested stats.
/// The second element is false if any of the requested stats is not yet cached.
async fn get_session_data(
    conn: &mut Connection,
    session_index: EpochIndex,
    show_stats: bool,
    show_netstats: bool,
) -> Result<(CacheMap, bool), ApiError> {
    let mut is_complete = true;
    let mut session_data: CacheMap = redis::cmd("HGETALL")
        .arg(CacheKey::SessionByIndex(Index::Num(session_index.into())))
        .query_async(conn)
        .await
        .map_err(CacheError::RedisCMDError)?;

    if session_data.is_empty() || !session_data.contains_key("session") {
        session_data.insert(String::from("session"), session_index.to_string());
    }

    if show_stats {
        let mut stats = redis::cmd("GET")
            .arg(CacheKey::SessionByIndexStats(Index::Num(
                session_index.into(),
            )))
            .query_async::<Option<String>>(conn)
            .await
            .map_err(CacheError::RedisCMDError)?;

        // Note: the stats of the running session are only cached by block
        if stats.is_none() {
            if let Some(block) = session_data
                .get("current_block")
                .and_then(|b| b.parse::<u64>().ok())
            {
                stats = redis::cmd("GET")
                    .arg(CacheKey::BlockByIndexStats(Index::Num(block)))
                    .query_async::<Option<String>>(conn)
                    .await
                    .map_err(CacheError::RedisCMDError)?;
            }
        }

        if let Some(stats) = stats {
            session_data.insert(String::from("stats"), stats);
        } else {
            session_data.insert(String::from("is_syncing"), (true).to_string());
            is_complete = false;
        }

        // Note: collation stats by parachain id, not having them does not mean syncing
        let collation: CacheMap = redis::cmd("HGETALL")
            .arg(CacheKey::CollatorStatsByEpoch(session_index))
            .query_async(conn)
            .await
            .map_err(CacheError::RedisCMDError)?;
        if !collation.is_empty() {
            let by_para: BTreeMap<String, serde_json::Value> = collation
                .iter()
                .filter_map(|(para_id, stats)| {
                    Some((para_id.clone(), serde_json::from_str(stats).ok()?))
                })
                .collect();
            session_data.insert(String::from("collation"), serde_json::to_string(&by_para)?);
        }
    }

    if show_netstats {
        if let Some(netstats) = redis::cmd("GET")
            .arg(CacheKey::NetworkStatsBySession(Index::Num(
                session_index.into(),
            )))
            .query_async::<Option<String>>(conn)
            .await
            .map_err(CacheError::RedisCMDError)?
        {
            session_data.insert(String::from("netstats"), netstats);
        } else {
            session_data.insert(String::from("is_syncing"), (true).to_string());
            is_complete = false;
        }
    }

    Ok((session_data, is_complete))
}

/// Get current session details
pub async fn get_session_by_index(
    index: Path<String>,
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<SessionResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;

    let current: String = redis::cmd("GET")
        .arg(CacheKey::SessionByIndex(Index::Current))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    let index: Index = if "current" == index.to_string() {
        Index::Str(current.clone())
    } else {
        Index::Str(index.to_string())
    };
    let requested = index.to_string();

    let mut data: CacheMap = redis::cmd("HGETALL")
        .arg(CacheKey::SessionByIndex(index))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    if data.is_empty() {
        let msg = format!("Session {} details not found", requested);
        warn!("{}", msg);
        return Err(ApiError::NotFound(msg));
    }

    // check if is_current session
    if let Some(session) = data.get("session") {
        if current == *session {
            data.insert(String::from("is_current"), (true).to_string());
        }
    }

    // add the requested stats, including the ones of the running session
    if params.show_stats || params.show_netstats {
        if let Ok(session_index) = requested.parse::<EpochIndex>() {
            let (extra, _) = get_session_data(
                &mut conn as &mut Connection,
                session_index,
                params.show_stats,
                params.show_netstats,
            )
            .await?;
            for key in ["stats", "collation", "netstats", "is_syncing"] {
                if let Some(value) = extra.get(key) {
                    data.insert(key.to_string(), value.clone());
                }
            }
        }
    }

    respond_json(data.into())
}
