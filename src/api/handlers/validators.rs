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

use crate::api::{
    helpers::respond_json,
    responses::{AuthorityKey, AuthorityKeyCache, CacheMap, ValidatorResult, ValidatorsResult},
};
use crate::cache::{get_conn, CacheKey, Index, RedisPool};
use crate::errors::{ApiError, CacheError};
use crate::records::EpochIndex;
use actix_web::web::{Data, Json, Path, Query};
use log::warn;
use redis::aio::Connection;
use serde::Deserialize;
use std::str::FromStr;
use subxt::sp_runtime::AccountId32;

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Role {
    Authority = 1,
    ParaAuthority = 2,
    Waiting = 3,
    Other = 4,
    NotDefined = 5,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authority => write!(f, "authority"),
            Self::ParaAuthority => write!(f, "para_authority"),
            Self::Waiting => write!(f, "waiting"),
            Self::Other => write!(f, "other"),
            Self::NotDefined => write!(f, "not_defined"),
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Report {
    Validator = 1,
    ValGroups = 2,
    Parachains = 3,
    Other = 4,
    NotDefined = 5,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Params {
    #[serde(default = "default_role")]
    role: Role,
    #[serde(default = "default_report")]
    report: Report,
    #[serde(default)]
    session: EpochIndex,
}

fn default_role() -> Role {
    Role::NotDefined
}

fn default_report() -> Report {
    Report::NotDefined
}

/// Get active validators
async fn get_authorities(
    index: EpochIndex,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorsResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;

    let authority_keys: Vec<String> = redis::cmd("SMEMBERS")
        .arg(CacheKey::AuthorityKeysBySession(index))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    let mut data: Vec<ValidatorResult> = Vec::new();
    for key in authority_keys.iter() {
        let auth: CacheMap = redis::cmd("HGETALL")
            .arg(key)
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;

        data.push(auth.into());
    }

    respond_json(data.into())
}

/// Get active para_validators
async fn get_para_authorities(
    index: EpochIndex,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorsResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;

    let authority_keys: Vec<String> = redis::cmd("SMEMBERS")
        .arg(CacheKey::AuthorityKeysBySessionParaOnly(index))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    let mut data: Vec<ValidatorResult> = Vec::new();
    for key in authority_keys.iter() {
        let auth: CacheMap = redis::cmd("HGETALL")
            .arg(key)
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;

        data.push(auth.into());
    }

    respond_json(data.into())
}

/// Get a validators filtered by query params
pub async fn get_validators(
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorsResult>, ApiError> {
    match params.role {
        Role::Authority => {
            return get_authorities(params.session, cache).await;
        }
        Role::ParaAuthority => {
            return get_para_authorities(params.session, cache).await;
        }
        _ => {
            let msg = format!(
                "Parameter role={} must be equal to one of the options: [authority, para_authority]",
                params.role
            );
            warn!("{}", msg);
            return Err(ApiError::BadRequest(msg));
        }
    }
}

/// Get a validator by stash
pub async fn get_validator_by_stash(
    stash: Path<String>,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let stash = AccountId32::from_str(&*stash.to_string())?;

    let session_index: EpochIndex = redis::cmd("HGET")
        .arg(CacheKey::SessionByIndex(Index::Str(String::from(
            "current",
        ))))
        .arg("session")
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    if session_index == 0 {
        let msg = format!("Current session couldn't be found!");
        warn!("{}", msg);
        return Err(ApiError::InternalServerError(msg));
    }

    let data: AuthorityKeyCache = redis::cmd("HGETALL")
        .arg(CacheKey::AuthorityKeyByAccountAndSession(
            stash.clone(),
            session_index,
        ))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    warn!("__{:?}", data);
    if data.is_empty() {
        let msg = format!(
            "At session {} the validator address {} was not found.",
            session_index, stash
        );
        warn!("{}", msg);
        return Err(ApiError::NotFound(msg));
    }
    // TODO check if era and session are the current ones
    //
    let authority_key: AuthorityKey = data.into();

    let data: CacheMap = redis::cmd("HGETALL")
        .arg(authority_key.to_string())
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    respond_json(data.into())
}

pub async fn get_peer_by_authority(
    path: Path<(String, u32)>,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let (stash, peer_authority_index) = path.into_inner();

    let stash = AccountId32::from_str(&*stash.to_string())?;

    let session_index: EpochIndex = redis::cmd("HGET")
        .arg(CacheKey::SessionByIndex(Index::Str(String::from(
            "current",
        ))))
        .arg("session")
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    if session_index == 0 {
        let msg = format!("Current session couldn't be found!");
        warn!("{}", msg);
        return Err(ApiError::InternalServerError(msg));
    }

    let data: AuthorityKeyCache = redis::cmd("HGETALL")
        .arg(CacheKey::AuthorityKeyByAccountAndSession(
            stash.clone(),
            session_index,
        ))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    if data.is_empty() {
        let msg = format!(
            "At session {} the validator address {} was not found.",
            session_index, stash
        );
        warn!("{}", msg);
        return Err(ApiError::NotFound(msg));
    }

    let mut authority_key: AuthorityKey = data.into();
    // set peer authority index to authority key
    authority_key.authority_index = peer_authority_index;

    let data: CacheMap = redis::cmd("HGETALL")
        .arg(authority_key.to_string())
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    respond_json(data.into())
}
