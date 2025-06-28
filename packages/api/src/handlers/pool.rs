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

use crate::handlers::params::Params;
use crate::helpers::respond_json;
use crate::responses::{PoolResult, PoolsResult};
use actix_web::web::{Data, Json, Path, Query};
use onet_cache::{
    provider::{get_conn, RedisPool},
    types::{CacheKey, Index},
};
use onet_errors::{ApiError, CacheError};
use onet_pools::{Pool, PoolId, PoolNominees, PoolNomineesStats};
use onet_records::EpochIndex;
use redis::aio::Connection;
use std::convert::TryInto;
use std::result::Result;

pub async fn get_pools(
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<PoolsResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;

    // get current session
    let requested_session_index: EpochIndex = match &params.session {
        Index::Str(index) => {
            if String::from("current") == *index {
                redis::cmd("GET")
                    .arg(CacheKey::SessionByIndex(Index::Current))
                    .query_async(&mut conn as &mut Connection)
                    .await
                    .map_err(CacheError::RedisCMDError)?
            } else {
                index.parse::<EpochIndex>().unwrap_or_default()
            }
        }
        _ => redis::cmd("GET")
            .arg(CacheKey::SessionByIndex(Index::Current))
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?,
    };

    let mut data: Vec<PoolResult> = Vec::new();

    let (start_session, end_session) = if params.from != 0 && params.from < params.to {
        (params.from, params.to)
    } else if params.number_last_sessions != 0 {
        (
            requested_session_index - params.number_last_sessions,
            requested_session_index - 1,
        )
    } else {
        (requested_session_index, requested_session_index)
    };

    let mut i = Some(start_session);
    while let Some(session_index) = i {
        if session_index > end_session {
            i = None;
        } else {
            let session_pool_ids: Vec<PoolId> = if params.pool != 0 {
                vec![params.pool]
            } else {
                if let Ok(pool_ids) = redis::cmd("ZRANGE")
                    .arg(CacheKey::NominationPoolIdsBySession(session_index))
                    .arg(0) // min
                    .arg(-1) // max
                    .query_async::<Connection, Vec<PoolId>>(&mut conn)
                    .await
                {
                    pool_ids
                } else {
                    vec![]
                }
            };

            if !session_pool_ids.is_empty() {
                for id in session_pool_ids.iter() {
                    let pool: Pool = if params.show_metadata {
                        if let Ok(serialized_data) = redis::cmd("GET")
                            .arg(CacheKey::NominationPoolRecord(*id))
                            .query_async::<Connection, String>(&mut conn)
                            .await
                        {
                            serde_json::from_str(&serialized_data).unwrap_or_default()
                        } else {
                            // return Err(ApiError::InternalServerError(format!(
                            //     "Cache for Pool ID {} is not available.",
                            //     *id
                            // )));
                            // TODO: if not cached attach an error message
                            Pool::with_id(*id)
                        }
                    } else {
                        Pool::with_id(*id)
                    };

                    let mut pool_response: PoolResult = pool.into();
                    pool_response.session = session_index;

                    if params.show_stats {
                        if let Ok(serialized_data) = redis::cmd("GET")
                            .arg(CacheKey::NominationPoolStatsByPoolAndSession(
                                *id,
                                session_index,
                            ))
                            .query_async::<Connection, String>(&mut conn)
                            .await
                        {
                            pool_response.stats =
                                serde_json::from_str(&serialized_data).unwrap_or_default();
                        }
                    }

                    if params.show_nominees {
                        if let Ok(serialized_data) = redis::cmd("GET")
                            .arg(CacheKey::NominationPoolNomineesByPoolAndSession(
                                *id,
                                session_index,
                            ))
                            .query_async::<Connection, String>(&mut conn)
                            .await
                        {
                            pool_response.nominees =
                                serde_json::from_str(&serialized_data).unwrap_or_default();
                        }
                    }

                    if params.show_nomstats {
                        if let Ok(serialized_data) = redis::cmd("GET")
                            .arg(CacheKey::NominationPoolNomineesByPoolAndSession(
                                *id,
                                session_index,
                            ))
                            .query_async::<Connection, String>(&mut conn)
                            .await
                        {
                            // TODO: nominees_changed
                            // verify if nominees are different from previous session

                            let pool_nominees: PoolNominees =
                                serde_json::from_str(&serialized_data).unwrap_or_default();
                            let pool_nominees_stats = PoolNomineesStats {
                                nominees: pool_nominees.nominees.len().try_into().unwrap(),
                                apr: pool_nominees.apr,
                                active: pool_nominees.active.len().try_into().unwrap(),
                                block_number: pool_nominees.block_number,
                            };
                            pool_response.nomstats = pool_nominees_stats;
                        }
                    }

                    data.push(pool_response.into());
                }
            }

            i = Some(session_index + 1);
        }
    }

    respond_json(data.into())
}

pub async fn get_pool(
    id: Path<u32>,
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<PoolResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;

    // get current session
    let requested_session_index: EpochIndex = match &params.session {
        Index::Str(index) => {
            if String::from("current") == *index {
                redis::cmd("GET")
                    .arg(CacheKey::SessionByIndex(Index::Current))
                    .query_async(&mut conn as &mut Connection)
                    .await
                    .map_err(CacheError::RedisCMDError)?
            } else {
                index.parse::<EpochIndex>().unwrap_or_default()
            }
        }
        _ => redis::cmd("GET")
            .arg(CacheKey::SessionByIndex(Index::Current))
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?,
    };

    if let Ok(serialized_data) = redis::cmd("GET")
        .arg(CacheKey::NominationPoolRecord(*id))
        .query_async::<Connection, String>(&mut conn)
        .await
    {
        let pool: Pool = serde_json::from_str(&serialized_data).unwrap_or_default();
        let mut pool_response: PoolResult = pool.into();

        if params.show_stats {
            if let Ok(serialized_data) = redis::cmd("GET")
                .arg(CacheKey::NominationPoolStatsByPoolAndSession(
                    *id,
                    requested_session_index,
                ))
                .query_async::<Connection, String>(&mut conn)
                .await
            {
                pool_response.stats = serde_json::from_str(&serialized_data).unwrap_or_default();
            }
        }

        if params.show_nominees {
            if let Ok(serialized_data) = redis::cmd("GET")
                .arg(CacheKey::NominationPoolNomineesByPoolAndSession(
                    *id,
                    requested_session_index,
                ))
                .query_async::<Connection, String>(&mut conn)
                .await
            {
                pool_response.nominees = serde_json::from_str(&serialized_data).unwrap_or_default();
            }
        }

        return respond_json(pool_response);
    } else {
        return Err(ApiError::InternalServerError(format!(
            "Cache for Pool ID {} at session {} is not available.",
            *id, requested_session_index
        )));
    }
}
