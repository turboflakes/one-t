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

use crate::api::responses::CacheMap;
use crate::api::{
    helpers::respond_json,
    responses::{BlockResult, BlocksResult},
};
use crate::cache::{get_conn, CacheKey, Index, RedisPool};
use crate::errors::{ApiError, CacheError};
use crate::records::{BlockNumber, EpochIndex};
use actix_web::web::{Data, Json, Path, Query};
use log::warn;
use redis::aio::Connection;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Params {
    #[serde(default = "default_index")]
    session: Index,
    // show_stats indicates whether session stats should be retrieved or not, default false
    #[serde(default)]
    show_stats: bool,
}

fn default_index() -> Index {
    Index::Current
}

/// Get a blocks filtered by query params
pub async fn get_blocks(
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<BlocksResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;

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

    if let Ok(session_blocks) = redis::cmd("ZRANGE")
        .arg(CacheKey::BlocksBySession(Index::Num(
            requested_session_index.into(),
        )))
        .arg(0) // min
        .arg(-1) // max
        .query_async::<Connection, Vec<BlockNumber>>(&mut conn)
        .await
    {
        let mut data: Vec<BlockResult> = Vec::new();
        if !session_blocks.is_empty() {
            for block_number in session_blocks.iter() {
                let mut block_data = CacheMap::new();
                block_data.insert(String::from("block_number"), block_number.to_string());
                block_data.insert(String::from("is_finalized"), (true).to_string());

                if params.show_stats {
                    if let Ok(stats) = redis::cmd("GET")
                        .arg(CacheKey::BlockByIndexStats(Index::Num(*block_number)))
                        .query_async::<Connection, String>(&mut conn)
                        .await
                    {
                        block_data.insert(String::from("stats"), stats);
                    }
                }
                data.push(block_data.into());
            }
        }
        return respond_json(data.into());
    }
    let msg = format!(
        "Blocks not found for the session {}",
        requested_session_index
    );
    warn!("{}", msg);
    Err(ApiError::NotFound(msg))
}

/// Get finalized block
pub async fn get_finalized_block(
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<BlockResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;

    if let Ok(block_number) = redis::cmd("GET")
        .arg(CacheKey::FinalizedBlock)
        .query_async::<Connection, BlockNumber>(&mut conn)
        .await
    {
        let mut data = CacheMap::new();
        data.insert(String::from("block_number"), block_number.to_string());
        data.insert(String::from("is_finalized"), (true).to_string());

        if params.show_stats {
            if let Ok(stats) = redis::cmd("GET")
                .arg(CacheKey::BlockByIndexStats(Index::Num(block_number)))
                .query_async::<Connection, String>(&mut conn)
                .await
            {
                data.insert(String::from("stats"), stats);
            }
        }

        return respond_json(data.into());
    }

    let msg = format!("Finalized block not found");
    warn!("{}", msg);
    Err(ApiError::NotFound(msg))
}

/// Get best block
pub async fn get_best_block(
    _params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<BlockResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;

    if let Ok(block_number) = redis::cmd("GET")
        .arg(CacheKey::BestBlock)
        .query_async::<Connection, BlockNumber>(&mut conn)
        .await
    {
        let mut data = CacheMap::new();
        data.insert(String::from("block_number"), block_number.to_string());
        data.insert(String::from("is_finalized"), (false).to_string());
        return respond_json(data.into());
    }

    let msg = format!("Best block not found");
    warn!("{}", msg);
    Err(ApiError::NotFound(msg))
}

/// Get block by block_number
pub async fn get_block_by_number(
    block_number: Path<BlockNumber>,
    cache: Data<RedisPool>,
) -> Result<Json<BlockResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;

    if let Ok(stats) = redis::cmd("GET")
        .arg(CacheKey::BlockByIndexStats(Index::Num(*block_number)))
        .query_async::<Connection, String>(&mut conn)
        .await
    {
        let mut data = CacheMap::new();
        data.insert(String::from("block_number"), block_number.to_string());
        data.insert(String::from("is_finalized"), (true).to_string());
        data.insert(String::from("stats"), stats);
        return respond_json(data.into());
    }
    let msg = format!("Block #{} not found", block_number);
    warn!("{}", msg);
    Err(ApiError::NotFound(msg))
}
