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
    limits::{Interval, Limits, LimitsCache},
    params::{
        get_board_name_from_weights, Intervals, Params, Quantity, Weights, CAPACITY, DECIMALS,
    },
    responses::{MetaResponse, ValidatorsResponse},
    scores::{calculate_scores, scores_to_string},
};
use crate::api::helpers::respond_json;
use crate::cache::{get_conn, CacheKey, Index, RedisPool};
use crate::errors::{ApiError, CacheError};
use crate::records::EraIndex;
use crate::records::ValidatorProfileRecord;
use actix_web::web::{Data, Json, Path, Query};
use log::{error, warn};
use redis::aio::Connection;
use std::convert::TryInto;
use std::result::Result;
use std::{collections::BTreeMap, str::FromStr};
use subxt::utils::AccountId32;

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
    let key = CacheKey::NomiBoardByEraAndName(
        era_index,
        get_board_name_from_weights(&params.w, Some(&params.i)),
    );

    // Generate leaderboard scores and cache it
    generate_board_scores(era_index, &params.w, &params.i, &params.force, cache.clone()).await?;

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

async fn is_board_cached(key: CacheKey, cache: Data<RedisPool>) -> Result<bool, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let exists: bool = redis::cmd("EXISTS")
        .arg(key.clone())
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(exists)
}

async fn is_era_data_available(
    era_index: EraIndex,
    cache: Data<RedisPool>,
) -> Result<bool, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let key = CacheKey::EraByIndex(Index::Num(era_index.into()));
    let exists: bool = redis::cmd("EXISTS")
        .arg(key.clone())
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(exists)
}

async fn get_validator_stashes_by_era(
    era_index: EraIndex,
    cache: Data<RedisPool>,
) -> Result<Vec<String>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let key = CacheKey::ValidatorAccountsByEra(era_index);
    let stashes: Vec<String> = redis::cmd("SMEMBERS")
        .arg(key.clone())
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(stashes)
}

async fn cache_limits(
    era_index: EraIndex,
    board_name: String,
    cache: Data<RedisPool>,
) -> Result<Limits, ApiError> {
    let mut conn = get_conn(&cache).await?;

    let mut limits: LimitsCache = BTreeMap::new();

    // // let max_avg_reward_points =
    // //     calculate_avg_points(cache.clone(), sync::BOARD_MAX_POINTS_ERAS).await?;
    // // limits.insert("max_avg_reward_points".to_string(), max_avg_reward_points);
    // // let min_avg_reward_points =
    // //     calculate_avg_points(cache.clone(), sync::BOARD_MIN_POINTS_ERAS).await?;
    // // limits.insert("min_avg_reward_points".to_string(), min_avg_reward_points);

    // let avg_reward_points_interval =
    //     calculate_min_max_interval(cache.clone(), sync::BOARD_AVG_POINTS_ERAS).await?;
    // limits.insert(
    //     "min_avg_reward_points".to_string(),
    //     avg_reward_points_interval.0,
    // );
    // limits.insert(
    //     "max_avg_reward_points".to_string(),
    //     avg_reward_points_interval.1,
    // );

    // let own_stake_interval =
    //     calculate_min_max_interval(cache.clone(), sync::BOARD_OWN_STAKE_VALIDATORS).await?;
    // // let own_stake_interval = calculate_confidence_interval_95(cache.clone(), sync::BOARD_OWN_STAKE_VALIDATORS).await?;
    // limits.insert("min_own_stake".to_string(), own_stake_interval.0);
    // limits.insert("max_own_stake".to_string(), own_stake_interval.1);

    // let total_stake_interval =
    //     calculate_min_max_interval(cache.clone(), sync::BOARD_TOTAL_STAKE_VALIDATORS).await?;
    // // let total_stake_interval = calculate_confidence_interval_95(cache.clone(), sync::BOARD_TOTAL_STAKE_VALIDATORS).await?;
    // limits.insert("min_total_stake".to_string(), total_stake_interval.0);
    // limits.insert("max_total_stake".to_string(), total_stake_interval.1);

    // let judgements_interval =
    //     calculate_min_max_interval(cache.clone(), sync::BOARD_JUDGEMENTS_VALIDATORS).await?;
    // // let judgements_interval = calculate_confidence_interval_95(cache.clone(), sync::BOARD_JUDGEMENTS_VALIDATORS).await?;
    // limits.insert("min_judgements".to_string(), judgements_interval.0);
    // limits.insert("max_judgements".to_string(), judgements_interval.1);

    // let sub_accounts_interval =
    //     calculate_min_max_interval(cache.clone(), sync::BOARD_SUB_ACCOUNTS_VALIDATORS).await?;
    // // let sub_accounts_interval = calculate_confidence_interval_95(cache.clone(), sync::BOARD_SUB_ACCOUNTS_VALIDATORS).await?;
    // limits.insert("min_sub_accounts".to_string(), sub_accounts_interval.0);
    // limits.insert("max_sub_accounts".to_string(), sub_accounts_interval.1);

    // let key_limits = sync::Key::BoardAtEra(era_index, format!("{}:limits", board_name));
    // // Cache board limits
    // let _: () = redis::cmd("HSET")
    //     .arg(key_limits.to_string())
    //     .arg(limits.clone())
    //     .query_async(&mut conn as &mut Connection)
    //     .await
    //     .map_err(CacheError::RedisCMDError)?;

    Ok(limits.into())
}

async fn generate_board_scores(
    era_index: EraIndex,
    weights: &Weights,
    intervals: &Intervals,
    force: &bool,
    cache: Data<RedisPool>,
) -> Result<(), ApiError> {
    let mut conn = get_conn(&cache).await?;

    let board_name = get_board_name_from_weights(weights, Some(intervals));
    let board_name_key = CacheKey::NomiBoardByEraAndName(era_index, board_name.to_string());

    // If board is already cached do nothing
    if !force && is_board_cached(board_name_key.clone(), cache.clone()).await? {
        return Ok(());
    }

    // Only generate board if data for the era is already available
    if !is_era_data_available(era_index, cache.clone()).await? {
        let msg = format!("There is no data available for requested era: {era_index}");
        warn!("{}", msg);
        return Err(ApiError::NotFound(msg));
    }

    // Convert user defined intervals into limits to be able to filter out validators
    let limits: Limits = intervals.into();

    // load stashes
    let stashes = get_validator_stashes_by_era(era_index, cache.clone()).await?;

    for stash in stashes {
        let stash = AccountId32::from_str(&*stash.to_string()).map_err(|e| {
            ApiError::BadRequest(format!(
                "Invalid account: {:?} error: {e:?}",
                &*stash.to_string()
            ))
        })?;
        if let Ok(serialized_data) = redis::cmd("GET")
            .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
            .query_async::<Connection, String>(&mut conn as &mut Connection)
            .await
        {
            let validator = ValidatorProfileRecord::from(serialized_data);

            // TODO:
            // // If the validator does not accept nominations
            // // score is not given
            // if validator.blocked {
            //     continue;
            // }

            // Skip validators that are outside the intervals
            if (validator.commission as u64) < limits.commission.min
                || (validator.commission as u64) > limits.commission.max
            {
                continue;
            }

            // Calculate scores
            let scores = calculate_scores(&validator, &limits, weights)?;
            let total_score = scores.iter().fold(0_u64, |acc, x| acc + x);

            redis::pipe()
                .atomic()
                // Cache total score
                .cmd("ZADD")
                .arg(board_name_key.to_string())
                .arg(total_score)
                .arg(stash.to_string())
                // Cache partial scores
                .cmd("HSET")
                .arg(CacheKey::NomiBoardScoresByEraAndName(
                    era_index,
                    board_name.to_string(),
                ))
                .arg(stash.to_string())
                .arg(scores_to_string(scores))
                .query_async(&mut conn as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;
        }
    }

    Ok(())
}
