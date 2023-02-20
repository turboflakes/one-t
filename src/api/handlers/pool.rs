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

use crate::api::helpers::respond_json;
use crate::api::responses::CacheMap;
use crate::cache::{get_conn, CacheKey, Index, RedisPool, Verbosity};
use crate::config::CONFIG;
use crate::errors::{ApiError, CacheError};
use crate::pools::{Pool, PoolNominees};
use crate::records::{grade, EpochIndex};
use actix_web::web::{Data, Json, Path, Query};
use redis::aio::Connection;
use serde::{de::Deserializer, Deserialize};
use std::{fs, path, result::Result};

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Params {
    #[serde(default = "default_index")]
    session: Index,
}

fn default_index() -> Index {
    Index::Current
}

type PoolResponse = Pool;

type PoolsResponse = Vec<Pool>;

// pub async fn get_pools(
//     id: Path<u32>,
//     params: Query<Params>,
//     cache: Data<RedisPool>,
// ) -> Result<Json<PoolsResponse>, ApiError> {
//     return respond_json("TODO".into());
// }

pub async fn get_pool(
    id: Path<u32>,
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<PoolResponse>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let config = CONFIG.clone();

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

    let mut pool_data: CacheMap = CacheMap::new();

    if let Ok(serialized_data) = redis::cmd("GET")
        .arg(CacheKey::NominationPoolRecord(requested_session_index, *id))
        .query_async::<Connection, String>(&mut conn)
        .await
    {
        if params.show_stats {
            if let Ok(serialized_data) = redis::cmd("GET")
                .arg(CacheKey::NominationPoolStatsByPoolAndSession(
                    *id,
                    requested_session_index,
                ))
                .query_async::<Connection, String>( &mut conn)
                .await
            {
                session_data.insert(String::from("stats"), serialized_data);
            }
        }

        let pool: Pool = serde_json::from_str(&serialized_data).unwrap();
        return respond_json(pool.into());
    } else {
        return Err(ApiError::InternalServerError(format!(
            "Cache for Pool ID {} at session {} is not available.",
            *id, requested_session_index
        )));
    }
}

type PoolNomineesResponse = PoolNominees;

// pub async fn get_pool_nominees(id: Path<u32>) -> Result<Json<PoolNomineesResponse>, ApiError> {
//     let config = CONFIG.clone();

//     if *id != config.pool_id_1 && *id != config.pool_id_2 {
//         return Err(ApiError::NotFound(format!(
//             "Pool with ID: {} not found.",
//             *id
//         )));
//     }

//     let filename = format!(
//         "{}{}_{}_nominees_{}",
//         config.data_path_read_only,
//         POOL_FILENAME,
//         *id,
//         config.chain_name.to_lowercase()
//     );

//     // Try to read from cached file
//     if !path::Path::new(&filename).exists() {
//         return Err(ApiError::InternalServerError(format!(
//             "Cache ({}) is not available.",
//             filename
//         )));
//     }

//     let serialized = fs::read_to_string(filename)?;
//     let pool_nominees: PoolNominees = serde_json::from_str(&serialized).unwrap();
//     respond_json(pool_nominees.into())
// }

// type PoolsEraResponse = PoolsEra;

// pub async fn get_pools_stats() -> Result<Json<PoolsEraResponse>, ApiError> {
//     let config = CONFIG.clone();

//     let filename = format!(
//         "{}{}s_era_{}",
//         config.data_path_read_only,
//         POOL_FILENAME,
//         config.chain_name.to_lowercase()
//     );

//     // Try to read from cached file
//     if !path::Path::new(&filename).exists() {
//         return Err(ApiError::InternalServerError(format!(
//             "Cache ({}) is not available.",
//             filename
//         )));
//     }

//     let serialized = fs::read_to_string(filename)?;
//     let pools_era: PoolsEra = serde_json::from_str(&serialized).unwrap();
//     respond_json(pools_era.into())
// }

// type PoolNominationResponse = PoolNomination;

// pub async fn get_pool_nomination(id: Path<u32>) -> Result<Json<PoolNominationResponse>, ApiError> {
//     let config = CONFIG.clone();

//     if *id != config.pool_id_1 && *id != config.pool_id_2 {
//         return Err(ApiError::NotFound(format!(
//             "Pool with ID: {} not found.",
//             *id
//         )));
//     }

//     let filename = format!(
//         "{}{}_{}_nomination_{}",
//         config.data_path_read_only,
//         POOL_FILENAME,
//         *id,
//         config.chain_name.to_lowercase()
//     );

//     // Try to read from cached file
//     if !path::Path::new(&filename).exists() {
//         return Err(ApiError::InternalServerError(format!(
//             "Cache ({}) is not available.",
//             filename
//         )));
//     }

//     let serialized = fs::read_to_string(filename)?;
//     let pool_nomination: PoolNomination = serde_json::from_str(&serialized).unwrap();
//     respond_json(pool_nomination.into())
// }
