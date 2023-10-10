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

use crate::api::handlers::boards::{
    params::{board_name, Intervals, Params, Quantity, Weights},
    responses::{MetaResponse, ValidatorsResponse},
};
use crate::api::helpers::respond_json;
use crate::cache::{get_conn, CacheKey, Index, RedisPool};
use crate::errors::{ApiError, CacheError};
use crate::records::EraIndex;
use actix_web::web::{Data, Json, Path, Query};
use redis::aio::Connection;
use std::convert::TryInto;
use std::result::Result;

/// Get a list of validators (board) based on weights and intervals per era
pub async fn get_boards(
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorsResponse>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    // get current era
    let requested_era_index: EraIndex = match &params.e {
        Index::Str(index) => {
            if String::from("current") == *index {
                redis::cmd("GET")
                    .arg(CacheKey::EraByIndex(Index::Current))
                    .query_async(&mut conn as &mut Connection)
                    .await
                    .map_err(CacheError::RedisCMDError)?
            } else {
                index.parse::<EraIndex>().unwrap_or_default()
            }
        }
        _ => redis::cmd("GET")
            .arg(CacheKey::EraByIndex(Index::Current))
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?,
    };

    return get_validators(requested_era_index, params, cache).await;
}

/// Get validators
async fn get_validators(
    era_index: EraIndex,
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorsResponse>, ApiError> {
    let key = CacheKey::NomiBoardByEraAndName(era_index, board_name(&params.w, Some(&params.i)));

    // Generate leaderboard scores and cache it
    // generate_board_scores(era_index, &params.w, cache.clone()).await?;

    // Generate filtered leaderboard and cache it
    // generate_board_filtered_by_intervals(era_index, &params.w, &params.i, cache.clone()).await?;

    // Increase board stats counter
    // increase_board_stats(key.clone(), cache.clone()).await?;

    // let limits: BoardLimits = get_board_limits(era_index, &params.w, cache.clone()).await?;

    respond_json(ValidatorsResponse {
        addresses: get_validators_stashes(key.clone(), params.n, cache.clone()).await?,
        meta: MetaResponse {
            limits: "".to_string(),
        },
    })
}

async fn get_validators_stashes(
    key: CacheKey,
    n: Quantity,
    cache: Data<RedisPool>,
) -> Result<Vec<String>, ApiError> {
    let mut conn = get_conn(&cache).await?;

    let stashes: Vec<String> = redis::cmd("ZRANGE")
        .arg(key)
        .arg("+inf")
        .arg("0")
        .arg("BYSCORE")
        .arg("REV")
        .arg("LIMIT")
        .arg("0")
        .arg(n)
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(stashes)
}
