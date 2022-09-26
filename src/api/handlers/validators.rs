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
    responses::{
        AuthorityKey, AuthorityKeyCache, CacheMap, ValidatorProfileResult, ValidatorResult,
        ValidatorsResult,
    },
};
use crate::cache::{get_conn, CacheKey, Index, RedisPool, Verbosity};
use crate::errors::{ApiError, CacheError};
use crate::records::EpochIndex;
use actix_web::web::{Data, Json, Path, Query};
use log::warn;
use redis::aio::Connection;
use serde::Deserialize;
use serde_json::Value;
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
    #[serde(default = "default_index")]
    session: Index,
    // show_stats indicates whether parachain details should be retrieved or not, default false
    #[serde(default)]
    show_stats: bool,
    // show_summary indicates whether parachain summary should be retrieved or not, default false
    #[serde(default)]
    show_summary: bool,
    // fetch_peers indicates whether peers should be also retrieved and included in the response, default false
    #[serde(default)]
    fetch_peers: bool,
    // address must be in combination with number_last_sessions
    #[serde(default)]
    address: String,
    #[serde(default)]
    number_last_sessions: u32,
}

fn default_role() -> Role {
    Role::NotDefined
}

fn default_report() -> Report {
    Report::NotDefined
}

fn default_index() -> Index {
    Index::Current
}

/// Get active validators
async fn get_session_authorities(
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

    respond_json(ValidatorsResult {
        session: index,
        data,
    })
}

/// Get active para_validators
async fn get_session_para_authorities(
    index: EpochIndex,
    show_stats: bool,
    show_summary: bool,
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
        let mut auth: CacheMap = redis::cmd("HGETALL")
            .arg(key)
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;

        if show_stats {
            let stats: CacheMap = redis::cmd("HGETALL")
                .arg(CacheKey::AuthorityRecordVerbose(
                    key.to_string(),
                    Verbosity::Stats,
                ))
                .query_async(&mut conn as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;
            auth.extend(stats);
        }

        if show_summary {
            let summary: CacheMap = redis::cmd("HGETALL")
                .arg(CacheKey::AuthorityRecordVerbose(
                    key.to_string(),
                    Verbosity::Summary,
                ))
                .query_async(&mut conn as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;
            auth.extend(summary);
        }

        data.push(auth.into());
    }

    respond_json(ValidatorsResult {
        session: index,
        data,
    })
}

/// Get validator by AuthorityKey
async fn get_validator_by_authority_key(
    auth_key: AuthorityKey,
    show_stats: bool,
    show_summary: bool,
    cache: Data<RedisPool>,
) -> Result<ValidatorResult, ApiError> {
    let mut conn = get_conn(&cache).await?;

    let mut data: CacheMap = redis::cmd("HGETALL")
        .arg(auth_key.to_string())
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    if show_stats {
        let stats: CacheMap = redis::cmd("HGETALL")
            .arg(CacheKey::AuthorityRecordVerbose(
                auth_key.to_string(),
                Verbosity::Stats,
            ))
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;
        data.extend(stats);
    }

    if show_summary {
        let summary: CacheMap = redis::cmd("HGETALL")
            .arg(CacheKey::AuthorityRecordVerbose(
                auth_key.to_string(),
                Verbosity::Summary,
            ))
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;
        data.extend(summary);
    }

    data.insert(String::from("session"), auth_key.epoch_index.to_string());

    Ok(data.into())
}

/// Get validator by stash addresss and index
async fn get_validator_by_stash_and_index(
    stash: AccountId32,
    session_index: EpochIndex,
    show_stats: bool,
    show_summary: bool,
    cache: Data<RedisPool>,
) -> Result<(ValidatorResult, AuthorityKey), ApiError> {
    let mut conn = get_conn(&cache).await?;

    let authority_key_data: AuthorityKeyCache = redis::cmd("HGETALL")
        .arg(CacheKey::AuthorityKeyByAccountAndSession(
            stash.clone(),
            session_index,
        ))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    if authority_key_data.is_empty() {
        let msg = format!(
            "At session {} the validator address {} was not found.",
            session_index, stash
        );
        warn!("{}", msg);
        return Ok((
            ValidatorResult {
                address: stash.to_string(),
                session: session_index,
                ..Default::default()
            },
            authority_key_data.into(),
        ));
    }

    // let authority_key: AuthorityKey = authority_key_data.into();
    let data = get_validator_by_authority_key(
        authority_key_data.clone().into(),
        show_stats,
        show_summary,
        cache,
    )
    .await?;
    Ok((data, authority_key_data.into()))
}

/// Get a validators filtered by query params
pub async fn get_validators(
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorsResult>, ApiError> {
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

    if &params.address != "" && params.number_last_sessions != 0 {
        let stash = AccountId32::from_str(&params.address)?;
        let mut data: Vec<ValidatorResult> = Vec::new();

        let mut last = Some(requested_session_index - params.number_last_sessions);

        while let Some(session_index) = last {
            if session_index >= requested_session_index {
                last = None;
            } else {
                let (validator_data, mut authority_key) = get_validator_by_stash_and_index(
                    stash.clone(),
                    session_index,
                    params.show_stats,
                    params.show_summary,
                    cache.clone(),
                )
                .await?;

                data.push(validator_data.clone().into());

                if params.fetch_peers && validator_data.is_para {
                    if let Some(peers_array) = validator_data.para.get("peers") {
                        match peers_array {
                            Value::Array(peers) => {
                                for peer in peers {
                                    if let Some(index) = peer.as_u64() {
                                        // set peer_authority_index into authority_key so that peer data
                                        // could be retrieved from cache from the exactly same session
                                        authority_key.authority_index = index as u32;
                                        let peer_data = get_validator_by_authority_key(
                                            authority_key.clone(),
                                            params.show_stats,
                                            params.show_summary,
                                            cache.clone(),
                                        )
                                        .await?;

                                        data.push(peer_data.into());
                                    }
                                }
                            }
                            _ => {
                                warn!(
                                    "Invalid peers Type for stash {} in session {}",
                                    stash.to_string(),
                                    session_index
                                );
                            }
                        };
                    }
                }

                last = Some(session_index + 1);
            }
        }

        return respond_json(ValidatorsResult {
            data,
            ..Default::default()
        });
    }

    match params.role {
        Role::Authority => get_session_authorities(requested_session_index, cache).await,
        Role::ParaAuthority => {
            get_session_para_authorities(
                requested_session_index,
                params.show_stats,
                params.show_summary,
                cache,
            )
            .await
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
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let stash = AccountId32::from_str(&*stash.to_string())?;

    let session_index: EpochIndex = match &params.session {
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

    let (data, _) = get_validator_by_stash_and_index(
        stash.clone(),
        session_index,
        params.show_stats,
        params.show_summary,
        cache,
    )
    .await?;

    respond_json(data.into())
}

pub async fn get_peer_by_authority(
    path: Path<(String, u32)>,
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let (stash, peer_authority_index) = path.into_inner();

    let stash = AccountId32::from_str(&*stash.to_string())?;

    let session_index: EpochIndex = match &params.session {
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

    let authority_key_data: AuthorityKeyCache = redis::cmd("HGETALL")
        .arg(CacheKey::AuthorityKeyByAccountAndSession(
            stash.clone(),
            session_index,
        ))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    if authority_key_data.is_empty() {
        let msg = format!(
            "At session {} the validator address {} was not found.",
            session_index, stash
        );
        warn!("{}", msg);
        return Err(ApiError::NotFound(msg));
    }

    let mut authority_key: AuthorityKey = authority_key_data.into();
    // set peer_authority_index into authority_key so that peer data
    // could be retrieved from cache from the exactly same session
    authority_key.authority_index = peer_authority_index;

    let data = get_validator_by_authority_key(
        authority_key,
        params.show_stats,
        params.show_summary,
        cache,
    )
    .await?;

    respond_json(data.into())
}

/// Get a validator profile by stash
pub async fn get_validator_profile_by_stash(
    stash: Path<String>,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorProfileResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let stash = AccountId32::from_str(&*stash.to_string())?;

    let serialized_data: String = redis::cmd("GET")
        .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    respond_json(serialized_data.into())
}
