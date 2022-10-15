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

use crate::api::responses::{CacheMap, SessionResult, SessionsResult, ValidatorResult};
use crate::api::{helpers::respond_json, responses::BlockResult};
use crate::cache::{get_conn, CacheKey, Index, RedisPool};
use crate::errors::{ApiError, CacheError};
use crate::records::BlockNumber;
use actix_web::web::{Data, Json, Query};
use log::{info, warn};
use redis::aio::Connection;
use serde::Deserialize;
use std::convert::TryInto;

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Params {
    // show_stats indicates whether session stats should be retrieved or not, default false
    #[serde(default)]
    show_stats: bool,
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
        // let block_number = String::from_utf8(block_number).unwrap_or("0".to_string());
        let mut data = CacheMap::new();
        data.insert(String::from("finalized_block"), block_number.to_string());

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
pub async fn get_best_block(cache: Data<RedisPool>) -> Result<Json<BlockResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;

    if let Ok(block_number) = redis::cmd("GET")
        .arg(CacheKey::BestBlock)
        .query_async::<Connection, BlockNumber>(&mut conn)
        .await
    {
        let mut data = CacheMap::new();
        data.insert(String::from("best_block"), block_number.to_string());
        return respond_json(data.into());
    }

    let msg = format!("Best block not found");
    warn!("{}", msg);
    Err(ApiError::NotFound(msg))
}
