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
        AuthorityKey, AuthorityKeyCache, CacheMap, ValidatorGradeResult, ValidatorProfileResult,
        ValidatorResult, ValidatorsResult,
    },
};
use crate::cache::{get_conn, CacheKey, Index, RedisPool, Verbosity};
use crate::errors::{ApiError, CacheError};
use crate::records::{grade, EpochIndex};
use actix_web::web::{Data, Json, Path, Query};
use log::warn;
use redis::aio::Connection;
use serde::{de::Deserializer, Deserialize};
use serde_json::Value;
use std::str::FromStr;
use subxt::ext::sp_runtime::AccountId32;

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
    // show_profile indicates whether validator identity should be retrieved or not, default false
    #[serde(default)]
    show_profile: bool,
    // fetch_peers indicates whether peers should be also retrieved and included in the response, default false
    #[serde(default)]
    fetch_peers: bool,
    // address must be in combination with number_last_sessions
    #[serde(default)]
    address: String,
    #[serde(default = "default_number_last_sessions")]
    number_last_sessions: u32,
    #[serde(default = "default_sessions")]
    #[serde(deserialize_with = "parse_sessions")]
    sessions: Sessions,
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

type Sessions = Vec<EpochIndex>;

fn default_sessions() -> Sessions {
    vec![]
}

fn default_number_last_sessions() -> u32 {
    6
}

fn parse_sessions<'de, D>(d: D) -> Result<Sessions, D::Error>
where
    D: Deserializer<'de>,
{
    Deserialize::deserialize(d).map(|x: Option<_>| {
        let sessions_as_csv = x.unwrap_or("".to_string());
        let sessions: Sessions = sessions_as_csv
            .split(",")
            .map(|x| x.parse::<EpochIndex>().unwrap_or_default())
            .collect();
        sessions
    })
}

/// Get active validators
async fn get_session_authorities(
    index: EpochIndex,
    cache: Data<RedisPool>,
) -> Result<ValidatorsResult, ApiError> {
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

    Ok(ValidatorsResult {
        session: index,
        data,
    })
}

/// Get active para_validators
async fn get_session_para_authorities(
    index: EpochIndex,
    show_stats: bool,
    show_summary: bool,
    show_profile: bool,
    cache: Data<RedisPool>,
) -> Result<ValidatorsResult, ApiError> {
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

        if show_profile {
            let address: String = redis::cmd("HGET")
                .arg(key.to_string())
                .arg(String::from("address"))
                .query_async(&mut conn as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;

            let profile: String = redis::cmd("GET")
                .arg(CacheKey::ValidatorProfileByAccount(AccountId32::from_str(
                    &address,
                )?))
                .query_async(&mut conn as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;

            auth.insert(String::from("profile"), profile);
        }

        data.push(auth.into());
    }

    Ok(ValidatorsResult {
        session: index,
        data,
    })
}

/// Get validator by AuthorityKey
async fn get_validator_by_authority_key(
    auth_key: AuthorityKey,
    show_stats: bool,
    show_summary: bool,
    _show_profile: bool,
    hide_address: bool,
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

    // if show_profile {
    //     let serialized_data: String = redis::cmd("GET")
    //     .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
    //     .query_async(&mut conn as &mut Connection)
    //     .await
    //     .map_err(CacheError::RedisCMDError)?;

    //     let summary: CacheMap = redis::cmd("HGETALL")
    //         .arg(CacheKey::AuthorityRecordVerbose(
    //             auth_key.to_string(),
    //             Verbosity::Summary,
    //         ))
    //         .query_async(&mut conn as &mut Connection)
    //         .await
    //         .map_err(CacheError::RedisCMDError)?;
    //     data.extend(summary);
    // }

    data.insert(String::from("session"), auth_key.epoch_index.to_string());

    // Hide address if requested
    if hide_address {
        data.remove("address");
    }

    Ok(data.into())
}

/// Get validator by stash addresss and index
async fn get_validator_by_stash_and_index(
    stash: AccountId32,
    session_index: EpochIndex,
    show_stats: bool,
    show_summary: bool,
    hide_address: bool,
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
        if hide_address {
            return Ok((
                ValidatorResult {
                    session: session_index,
                    ..Default::default()
                },
                authority_key_data.into(),
            ));
        }
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
        false,
        hide_address,
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
                    false,
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
                                            params.show_profile,
                                            false,
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

    // TODO: draft validators by session
    // 
    // if &params.sessions.len() > &0 {
    //     let mut data: Vec<ValidatorResult> = Vec::new();
    //     for session in &params.sessions {
    //         println!("{session}");
    //         let authority_keys: Vec<String> = redis::cmd("SMEMBERS")
    //             .arg(CacheKey::AuthorityKeysBySession(*session))
    //             .query_async(&mut conn as &mut Connection)
    //             .await
    //             .map_err(CacheError::RedisCMDError)?;

    //         for key in authority_keys.iter() {
    //             let auth: CacheMap = redis::cmd("HGETALL")
    //                 .arg(key)
    //                 .query_async(&mut conn as &mut Connection)
    //                 .await
    //                 .map_err(CacheError::RedisCMDError)?;

    //             // let val = get_validator_by_authority_key(
    //             //     *(key).into(),
    //             //     params.show_stats,
    //             //     params.show_summary,
    //             //     params.show_profile,
    //             //     cache,
    //             // ).await?;

    //             // data.push(val.into());
    //         }
    //     }
    //     return respond_json(ValidatorsResult {
    //         data,
    //         ..Default::default()
    //     });
    // }

    let res: ValidatorsResult = match params.role {
        Role::Authority => get_session_authorities(requested_session_index, cache).await?,
        Role::ParaAuthority => {
            get_session_para_authorities(
                requested_session_index,
                params.show_stats,
                params.show_summary,
                params.show_profile,
                cache,
            )
            .await?
        }
        _ => {
            let msg = format!(
                "Parameter role={} must be equal to one of the options: [authority, para_authority]",
                params.role
            );
            warn!("{}", msg);
            return Err(ApiError::BadRequest(msg));
        }
    };

    respond_json(res.into())
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
        false,
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
        params.show_profile,
        false,
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

/// Get a validator grade by stash
pub async fn get_validator_grade_by_stash(
    stash: Path<String>,
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorGradeResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let stash = AccountId32::from_str(&*stash.to_string())?;

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

    let mut data: Vec<ValidatorResult> = Vec::new();

    // NOTE: currently define max number of sessions up to 192 with default being 6 sessions
    // TODO: Add 'maximum_number_last_sessions' as configurable variable
    if params.number_last_sessions > 0 && params.number_last_sessions <= 192 {
        let mut last = Some(requested_session_index - params.number_last_sessions);

        while let Some(session_index) = last {
            if session_index >= requested_session_index {
                last = None;
            } else {
                let (validator_data, _) = get_validator_by_stash_and_index(
                    stash.clone(),
                    session_index,
                    false,
                    true,
                    true,
                    cache.clone(),
                )
                .await?;

                data.push(validator_data.clone().into());

                last = Some(session_index + 1);
            }
        }
    } else {
        let msg =
            format!("The value of parameter 'number_last_sessions' must be between 1 and 192.");
        warn!("{}", msg);
        return Err(ApiError::NotFound(msg));
    }

    // calculate auth_epochs and para_epochs
    let auth_epochs = data.iter().filter(|v| v.is_auth).count();
    let para_epochs = data.iter().filter(|v| v.is_para).count();

    if para_epochs == 0 {
        if params.show_summary {
            return respond_json(ValidatorGradeResult {
                address: stash.to_string(),
                grade: String::from("-"),
                authority_inclusion: auth_epochs as f64 / params.number_last_sessions as f64,
                para_authority_inclusion: para_epochs as f64 / params.number_last_sessions as f64,
                sessions_data: data.into(),
                ..Default::default()
            });
        }
        return respond_json(ValidatorGradeResult {
            address: stash.to_string(),
            grade: String::from("-"),
            authority_inclusion: auth_epochs as f64 / params.number_last_sessions as f64,
            para_authority_inclusion: para_epochs as f64 / params.number_last_sessions as f64,
            sessions: data.iter().map(|v| v.session).collect(),
            ..Default::default()
        });
    }

    // calculate mvr if para_epochs > 0
    let mvrs: Vec<f64> = data
        .iter()
        .filter(|v| v.is_para)
        .map(|v| {
            let partial = v.para_summary.explicit_votes
                + v.para_summary.implicit_votes
                + v.para_summary.missed_votes;
            if partial > 0 {
                v.para_summary.missed_votes as f64 / partial as f64
            } else {
                0.0_f64
            }
        })
        .collect();

    let mvr = mvrs.iter().sum::<f64>() / para_epochs as f64;

    if params.show_summary {
        return respond_json(ValidatorGradeResult {
            address: stash.to_string(),
            grade: grade(1.0 - mvr),
            authority_inclusion: auth_epochs as f64 / params.number_last_sessions as f64,
            para_authority_inclusion: para_epochs as f64 / params.number_last_sessions as f64,
            sessions_data: data.into(),
            ..Default::default()
        });
    }

    return respond_json(ValidatorGradeResult {
        address: stash.to_string(),
        grade: grade(1.0 - mvr),
        authority_inclusion: auth_epochs as f64 / params.number_last_sessions as f64,
        para_authority_inclusion: para_epochs as f64 / params.number_last_sessions as f64,
        sessions: data.iter().map(|v| v.session).collect(),
        ..Default::default()
    });
}
