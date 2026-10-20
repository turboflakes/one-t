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
use crate::helpers::respond_json;
use actix_web::web::{Data, Json, Path, Query};
use onet_cache::{
    error::CacheError,
    provider::{get_conn, RedisPool},
    types::CacheKey,
};
use onet_prediction::{
    DesiredValidators, PredictionMetadata, PredictionNominator, PredictionValidator,
};
use redis::aio::Connection;
use serde::{Deserialize, Serialize};
use std::{result::Result, str::FromStr};
use subxt::utils::AccountId32;

const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 1000;

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    #[serde(default)]
    pub page: usize,
    #[serde(default)]
    pub size: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct PredictionValidatorResult {
    pub metadata: PredictionMetadata,
    #[serde(flatten)]
    pub validator: PredictionValidator,
}

#[derive(Debug, Serialize)]
pub struct PredictionNominatorsResult {
    pub total: usize,
    pub page: usize,
    pub size: usize,
    pub nominators: Vec<PredictionNominator>,
}

fn parse_stash(stash: &str) -> Result<AccountId32, ApiError> {
    AccountId32::from_str(stash)
        .map_err(|e| ApiError::BadRequest(format!("Invalid stash {}: {:?}", stash, e)))
}

async fn get_metadata(
    conn: &mut Connection,
    desired: DesiredValidators,
) -> Result<PredictionMetadata, ApiError> {
    let serialized: Option<String> = redis::cmd("GET")
        .arg(CacheKey::PredictionMetaByDesired(desired))
        .query_async(conn)
        .await
        .map_err(CacheError::RedisCMDError)?;
    match serialized {
        Some(s) => Ok(serde_json::from_str(&s)?),
        None => Err(ApiError::NotFound(format!(
            "Prediction for {} desired validators is not available.",
            desired
        ))),
    }
}

/// Handler to get the metadata of every prediction currently cached, one per `desired_validators`
pub async fn get_predictions(
    cache: Data<RedisPool>,
) -> Result<Json<Vec<PredictionMetadata>>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let mut indices: Vec<DesiredValidators> = redis::cmd("SMEMBERS")
        .arg(CacheKey::PredictionIndex)
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;
    indices.sort_unstable();

    let mut data: Vec<PredictionMetadata> = Vec::with_capacity(indices.len());
    for desired in indices {
        // entries expire independently, skip the ones that are gone
        if let Ok(metadata) = get_metadata(&mut conn, desired).await {
            data.push(metadata);
        }
    }
    respond_json(data)
}

/// Handler to get the metadata of the prediction for a given number of desired validators
pub async fn get_prediction_by_desired(
    path: Path<DesiredValidators>,
    cache: Data<RedisPool>,
) -> Result<Json<PredictionMetadata>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    respond_json(get_metadata(&mut conn, path.into_inner()).await?)
}

/// Handler to get every validator of the prediction for a given number of desired validators
pub async fn get_prediction_validators(
    path: Path<DesiredValidators>,
    cache: Data<RedisPool>,
) -> Result<Json<Vec<PredictionValidator>>, ApiError> {
    let desired = path.into_inner();
    let mut conn = get_conn(&cache).await?;
    // fail with not found if the prediction is not available
    get_metadata(&mut conn, desired).await?;

    let accounts: Vec<String> = redis::cmd("SMEMBERS")
        .arg(CacheKey::PredictionAccountsByDesired(desired))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    let mut keys: Vec<String> = Vec::with_capacity(accounts.len());
    for account in accounts {
        if let Ok(account_id) = AccountId32::from_str(&account) {
            keys.push(
                CacheKey::PredictionValidatorByDesiredAndAccount(desired, account_id).to_string(),
            );
        }
    }

    let mut data: Vec<PredictionValidator> = Vec::with_capacity(keys.len());
    if !keys.is_empty() {
        let values: Vec<Option<String>> = redis::cmd("MGET")
            .arg(keys)
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;
        for serialized in values.into_iter().flatten() {
            data.push(serde_json::from_str(&serialized)?);
        }
    }
    data.sort_by_key(|v| std::cmp::Reverse(v.total_stake.0));
    respond_json(data)
}

/// Handler to get the prediction of a single validator
pub async fn get_prediction_validator(
    path: Path<(DesiredValidators, String)>,
    cache: Data<RedisPool>,
) -> Result<Json<PredictionValidatorResult>, ApiError> {
    let (desired, stash) = path.into_inner();
    let stash = parse_stash(&stash)?;
    let mut conn = get_conn(&cache).await?;
    let metadata = get_metadata(&mut conn, desired).await?;

    let serialized: Option<String> = redis::cmd("GET")
        .arg(CacheKey::PredictionValidatorByDesiredAndAccount(
            desired, stash,
        ))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    match serialized {
        Some(s) => respond_json(PredictionValidatorResult {
            metadata,
            validator: serde_json::from_str(&s)?,
        }),
        None => Err(ApiError::NotFound(format!(
            "Validator {} is not part of the prediction for {} desired validators.",
            stash, desired
        ))),
    }
}

/// Handler to get a page of the predicted nominators of a single validator
pub async fn get_prediction_validator_nominators(
    path: Path<(DesiredValidators, String)>,
    params: Query<PaginationParams>,
    cache: Data<RedisPool>,
) -> Result<Json<PredictionNominatorsResult>, ApiError> {
    let (desired, stash) = path.into_inner();
    let stash = parse_stash(&stash)?;
    let mut conn = get_conn(&cache).await?;

    let serialized: Option<String> = redis::cmd("GET")
        .arg(CacheKey::PredictionNominatorsByDesiredAndAccount(
            desired, stash,
        ))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    let nominators: Vec<PredictionNominator> = match serialized {
        Some(s) => serde_json::from_str(&s)?,
        None => {
            return Err(ApiError::NotFound(format!(
                "Validator {} is not part of the prediction for {} desired validators.",
                stash, desired
            )))
        }
    };

    let size = params
        .size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);
    let total = nominators.len();
    let page: Vec<PredictionNominator> = nominators
        .into_iter()
        .skip(params.page.saturating_mul(size))
        .take(size)
        .collect();

    respond_json(PredictionNominatorsResult {
        total,
        page: params.page,
        size,
        nominators: page,
    })
}
