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

use crate::handlers::boards::{
    params::{Params, Quantity},
    responses::{BoardResult, BoardsResult, LimitsResult},
};
use crate::helpers::respond_json;
use actix_web::web::{Data, Json, Query};
use log::{debug, warn};
use onet_cache::{
    provider::{get_conn, RedisPool},
    types::{CacheKey, Index},
};
use onet_config::CONFIG;
use onet_errors::{ApiError, CacheError};
use onet_mcda::{
    criterias::{
        criterias_hash, CriteriaFilters, CriteriaLimits, CriteriaWeights, Filters, Intervals,
        Weights,
    },
    scores::{calculate_scores, scores_to_string},
};
use onet_records::{BlockNumber, EpochIndex, ValidatorProfileRecord};
use redis::aio::Connection;
use std::{collections::BTreeMap, result::Result, str::FromStr};
use subxt::utils::AccountId32;

/// Get a list of validators (board) based on weights, intervals and filters per session
pub async fn get_boards(
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<BoardsResult>, ApiError> {
    let session_index = get_requested_session(params.clone(), cache.clone()).await?;

    get_board_by_session(session_index, params, cache).await
}

/// Get traits upper and lower limits per session
pub async fn get_criteria_limits(
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<LimitsResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let session_index = get_requested_session(params.clone(), cache.clone()).await?;
    let block_number = get_synced_block_number_by_session(session_index, cache.clone()).await?;
    let serialized_data: String = redis::cmd("HGET")
        .arg(CacheKey::NomiBoardEraBySession(session_index))
        .arg(String::from("limits"))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    respond_json(LimitsResult {
        session: session_index,
        block_number,
        limits: serialized_data.into(),
    })
}

async fn get_requested_session(
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<EpochIndex, ApiError> {
    let session_index: EpochIndex = match &params.session {
        Index::Str(index) => {
            if String::from("current") == *index {
                get_latest_synced_session(cache.clone()).await?
            } else {
                index.parse::<EpochIndex>().unwrap_or_default()
            }
        }
        _ => get_latest_synced_session(cache.clone()).await?,
    };

    Ok(session_index)
}

async fn get_latest_synced_session(cache: Data<RedisPool>) -> Result<EpochIndex, ApiError> {
    let mut conn = get_conn(&cache).await?;

    // get current era
    let era_index: u64 = redis::cmd("GET")
        .arg(CacheKey::EraByIndex(Index::Current))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    // get latest synced session from current era
    let session_index: u32 = redis::cmd("HGET")
        .arg(CacheKey::EraByIndex(Index::Num(era_index)))
        .arg(String::from("synced_session"))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(session_index)
}

async fn get_synced_block_number_by_session(
    session_index: EpochIndex,
    cache: Data<RedisPool>,
) -> Result<BlockNumber, ApiError> {
    let mut conn = get_conn(&cache).await?;

    // get current era
    let era_index: u64 = redis::cmd("HGET")
        .arg(CacheKey::SessionByIndex(Index::Num(session_index.into())))
        .arg(String::from("era".to_string()))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    // get latest synced session from current era
    let block_number: u64 = redis::cmd("HGET")
        .arg(CacheKey::EraByIndex(Index::Num(era_index)))
        .arg(String::from(format!("synced_at_block:{}", session_index)))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(block_number)
}

async fn get_board_by_session(
    session_index: EpochIndex,
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<BoardsResult>, ApiError> {
    // TODO: check if weights available in params

    let board_hash = criterias_hash(&params.w, &params.i, &params.f);
    let board_key = CacheKey::NomiBoardBySessionAndHash(session_index, board_hash);

    // Generate leaderboard scores and cache it
    let (weights, limits, filters) = generate_board_scores(
        session_index,
        &params.w,
        &params.i,
        &params.f,
        &params.force,
        cache.clone(),
    )
    .await?;

    let block_number = get_synced_block_number_by_session(session_index, cache.clone()).await?;

    // Increase board stats counter
    increase_board_stats(board_key.clone(), cache.clone()).await?;

    respond_json(BoardsResult {
        data: vec![BoardResult {
            hash: board_hash,
            session: session_index,
            block_number,
            addresses: get_validators_stashes(board_key, params.n, cache.clone()).await?,
            limits,
            weights,
            filters,
        }],
    })
}

/// Increase board stats counter
async fn increase_board_stats(key: CacheKey, cache: Data<RedisPool>) -> Result<(), ApiError> {
    let mut conn = get_conn(&cache).await?;

    let _: () = redis::cmd("HINCRBY")
        .arg(CacheKey::NomiBoardStats)
        .arg(key.to_string())
        .arg(1)
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
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

async fn generate_board_scores(
    session_index: EpochIndex,
    weights: &Weights,
    intervals: &Intervals,
    filters: &Filters,
    force: &bool,
    cache: Data<RedisPool>,
) -> Result<(CriteriaWeights, CriteriaLimits, CriteriaFilters), ApiError> {
    let config = CONFIG.clone();
    let mut conn = get_conn(&cache).await?;

    let board_hash = criterias_hash(&weights, &intervals, &filters);
    let board_key = CacheKey::NomiBoardBySessionAndHash(session_index, board_hash);

    // Convert user defined weights into criteria_weights
    let criteria_weights: CriteriaWeights = weights.into();
    debug!("criteria_weights {:?}", criteria_weights);

    // Convert user defined intervals into limits to be able to filter out validators
    let criteria_limits: CriteriaLimits = intervals.into();
    debug!("criteria_limits {:?}", criteria_limits);

    // Convert user defined filters into limits to be able to filter out validators
    let criteria_filters: CriteriaFilters = filters.into();
    debug!("criteria_filters {:?}", criteria_filters);

    // If board is already cached do nothing
    if !force && is_board_cached(board_key.clone(), cache.clone()).await? {
        return Ok((criteria_weights, criteria_limits, criteria_filters));
    }

    // Only generate board if data for the session is already available
    if !is_session_data_available(session_index, cache.clone()).await? {
        let msg = format!("There is no data available for requested session: {session_index}");
        warn!("{}", msg);
        return Err(ApiError::NotFound(msg));
    }

    // load stashes
    let stashes = get_validator_stashes_by_session(session_index, cache.clone()).await?;

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
            // If the validator does not accept nominations or is currently chilled
            // score is not given
            if validator.is_blocked || validator.is_chilled {
                continue;
            }

            // Filter out user defined filters
            if criteria_filters.active && !validator.is_active {
                continue;
            }

            if criteria_filters.not_oversubscribed && validator.is_oversubscribed {
                continue;
            }

            if criteria_filters.identity && !validator.is_identified() {
                continue;
            }

            if criteria_filters.tvp && !validator.is_tvp() {
                continue;
            }

            // Skip validators that are outside the intervals
            if (validator.commission as u64) < criteria_limits.commission.min
                || (validator.commission as u64) > criteria_limits.commission.max
            {
                continue;
            }

            // Get chain token decimals
            let chain_token_decimals: u32 = redis::cmd("HGET")
                .arg(CacheKey::Network)
                .arg(String::from("token_decimals"))
                .query_async(&mut conn as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;

            if validator.own_stake_trimmed(chain_token_decimals) < criteria_limits.own_stake.min
                || validator.own_stake_trimmed(chain_token_decimals) > criteria_limits.own_stake.max
            {
                continue;
            }

            if validator.nominators_stake_trimmed(chain_token_decimals)
                < criteria_limits.nominators_stake.min
                || validator.nominators_stake_trimmed(chain_token_decimals)
                    > criteria_limits.nominators_stake.max
            {
                continue;
            }

            if validator.nominators_counter < criteria_limits.nominators_counter.min as u128
                || validator.nominators_counter > criteria_limits.nominators_counter.max as u128
            {
                continue;
            }

            if let Some(mvr) = validator.mvr {
                if mvr < criteria_limits.mvr.min || mvr > criteria_limits.mvr.max {
                    continue;
                }
            }

            // NOTE: Skip validators that have not been active or performance was not evaluated in the last 32 eras
            // when user weights performance higher than 0
            if criteria_weights.mvr > 0 && validator.mvr.is_none() {
                continue;
            }

            // Calculate scores
            let scores = calculate_scores(
                &validator,
                &criteria_limits,
                &criteria_weights,
                chain_token_decimals,
            )?;
            let total_score = scores.iter().fold(0_u64, |acc, x| acc + x);

            redis::pipe()
                .atomic()
                // Cache total score
                .cmd("ZADD")
                .arg(board_key.to_string())
                .arg(total_score)
                .arg(stash.to_string())
                // Cache partial scores
                .cmd("HSET")
                .arg(CacheKey::NomiBoardScoresBySessionAndHash(
                    session_index,
                    board_hash,
                ))
                .arg(stash.to_string())
                .arg(scores_to_string(scores))
                .cmd("EXPIRE")
                .arg(CacheKey::NomiBoardScoresBySessionAndHash(
                    session_index,
                    board_hash,
                ))
                .arg(config.cache_writer_prunning)
                .query_async::<_, ()>(&mut conn as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;
        }
    }
    // Cache board metadata
    let mut metadata: BTreeMap<String, String> = BTreeMap::new();
    let limits_serialized = serde_json::to_string(&criteria_limits)?;
    metadata.insert(String::from("limits"), limits_serialized.to_string());
    let weights_serialized = serde_json::to_string(&criteria_weights)?;
    metadata.insert(String::from("weights"), weights_serialized.to_string());

    redis::pipe()
        .atomic()
        // Cache total score
        .cmd("HSET")
        .arg(CacheKey::NomiBoardMetaBySessionAndHash(
            session_index,
            board_hash,
        ))
        .arg(metadata)
        .cmd("EXPIRE")
        .arg(CacheKey::NomiBoardMetaBySessionAndHash(
            session_index,
            board_hash,
        ))
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok((criteria_weights, criteria_limits, criteria_filters))
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

async fn is_session_data_available(
    session_index: EpochIndex,
    cache: Data<RedisPool>,
) -> Result<bool, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let key = CacheKey::NomiBoardEraBySession(session_index);
    let exists: bool = redis::cmd("EXISTS")
        .arg(key.clone())
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(exists)
}

pub async fn get_validator_stashes_by_session(
    session_index: EpochIndex,
    cache: Data<RedisPool>,
) -> Result<Vec<String>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let key = CacheKey::ValidatorAccountsBySession(session_index);
    let stashes: Vec<String> = redis::cmd("SMEMBERS")
        .arg(key.clone())
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(stashes)
}
