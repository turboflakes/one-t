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

use crate::{
    helpers::respond_json,
    responses::{
        AuthorityKey, AuthorityKeyCache, CacheMap, CohortValidatorsGradesResult, CohortsResult,
        EraValidatorsGradesResult, ErasResult, RankingStats, ValidatorGradeResult,
        ValidatorProfileResult, ValidatorResult, ValidatorsResult,
    },
};
use actix_web::{
    web::{Data, Json, Path, Query},
    HttpRequest,
};
use log::warn;
use onet_cache::{
    provider::{get_conn, RedisPool},
    types::{CacheKey, Index, Verbosity},
};
use onet_config::CONFIG;
use onet_dn::try_fetch_stashes_from_remote_url;
use onet_errors::{ApiError, CacheError};
use onet_pools::{PoolId, PoolNominees};
use onet_records::{grade, BitfieldsRecord, EpochIndex, Grade, Subset};
use redis::aio::Connection;
use serde::{de::Deserializer, Deserialize};
use serde_json::Value;
use std::{collections::BTreeMap, str::FromStr};
use std::{convert::TryInto, iter::FromIterator};
use subxt::utils::AccountId32;

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
enum Ranking {
    Performance = 1,
    Pools = 2,
    NotDefined = 3,
}

impl std::fmt::Display for Ranking {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Performance => write!(f, "performance"),
            Self::Pools => write!(f, "pools"),
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
    // show_discovery indicates whether p2p data should be retrieved or not, default false
    #[serde(default)]
    show_discovery: bool,
    // show_profile indicates whether validator identity should be retrieved or not, default false
    #[serde(default)]
    show_profile: bool,
    // show_sessions indicates whether the list of sessions involved in the grade calculation should be retrieved or not, default false
    #[serde(default)]
    show_sessions: bool,
    // nominees_only indicates validators that are present on nomination pools as nominees, dafault false
    #[serde(default)]
    nominees_only: bool,
    // fetch_peers indicates whether peers should be also retrieved and included in the response, default false
    #[serde(default)]
    fetch_peers: bool,
    // address must be in combination with number_last_sessions
    #[serde(default)]
    address: String,
    #[serde(default = "default_number_last_sessions")]
    number_last_sessions: u32,
    // NOTE_DEPRECATED: _sessions_ param will be deprecated in favour of _from_ and _to_
    #[serde(default = "default_sessions")]
    #[serde(deserialize_with = "parse_sessions")]
    sessions: Sessions,
    #[serde(default)]
    #[serde(deserialize_with = "parse_session")]
    pub from: EpochIndex,
    #[serde(default)]
    #[serde(deserialize_with = "parse_session")]
    pub to: EpochIndex,
    // size indicates the number of validators requested, default 0
    #[serde(default)]
    size: u32,
    // ranking indicates which ranking should be pulled, default not_defined
    #[serde(default = "default_ranking")]
    ranking: Ranking,
    // ranking indicates which ranking should be pulled, default not_defined
    #[serde(default = "default_subset")]
    #[serde(deserialize_with = "deserialize_subset_from_any_case")]
    subset: Subset,
}
fn default_role() -> Role {
    Role::NotDefined
}

fn default_ranking() -> Ranking {
    Ranking::NotDefined
}

fn default_subset() -> Subset {
    Subset::NotDefined
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

fn parse_session<'de, D>(d: D) -> Result<EpochIndex, D::Error>
where
    D: Deserializer<'de>,
{
    Deserialize::deserialize(d).map(|x: Option<_>| {
        x.unwrap_or("".to_string())
            .parse::<EpochIndex>()
            .unwrap_or_default()
    })
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

fn deserialize_subset_from_any_case<'de, D>(deserializer: D) -> Result<Subset, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    match s.to_lowercase().as_str() {
        "tvp" | "dn" => Ok(Subset::TVP),
        "nontvp" | "nondn" => Ok(Subset::NONTVP),
        "c100" | "100%" => Ok(Subset::C100),
        &_ => Ok(Subset::NotDefined),
    }
}

/// Get active validators
async fn get_session_authorities(
    index: EpochIndex,
    role: Role,
    show_stats: bool,
    show_summary: bool,
    show_discovery: bool,
    show_profile: bool,
    cache: Data<RedisPool>,
) -> Result<ValidatorsResult, ApiError> {
    let mut conn = get_conn(&cache).await?;

    let authority_keys: Vec<String> = match role {
        Role::Authority => redis::cmd("SMEMBERS")
            .arg(CacheKey::AuthorityKeysBySession(index))
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?,
        Role::ParaAuthority => redis::cmd("SMEMBERS")
            .arg(CacheKey::AuthorityKeysBySessionParaOnly(index))
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?,
        _ => {
            let msg = format!(
                "Parameter role={} must be equal to one of the options: [authority, para_authority]",
                role
            );
            warn!("{}", msg);
            return Err(ApiError::BadRequest(msg));
        }
    };

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

        if show_discovery {
            let discovery = get_discovery_from_cache(key, &mut conn).await?;
            if discovery.is_empty() {
                // NOTE: try to get discovery data from the previous session
                let mut ak = AuthorityKey::from(key.to_string());
                ak.epoch_index = ak.epoch_index - 1;
                let discovery = get_discovery_from_cache(&ak.to_string(), &mut conn).await?;
                if discovery.is_empty() {
                    // NOTE: try to get discovery data from the previous session and previous era
                    let mut ak = AuthorityKey::from(key.to_string());
                    ak.era_index = ak.era_index - 1;
                    ak.epoch_index = ak.epoch_index - 1;
                    let discovery = get_discovery_from_cache(&ak.to_string(), &mut conn).await?;
                    if discovery.is_empty() {
                        warn!(
                            "Discovery data not found for authority key: {}",
                            key.to_string()
                        );
                    } else {
                        auth.extend(discovery);
                    }
                } else {
                    auth.extend(discovery);
                }
            } else {
                auth.extend(discovery);
            }
        }

        if show_profile {
            let address: String = redis::cmd("HGET")
                .arg(key.to_string())
                .arg(String::from("address"))
                .query_async(&mut conn as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;

            let acc = AccountId32::from_str(&address).map_err(|e| {
                ApiError::BadRequest(format!("Invalid account: {:?} error: {e:?}", &address))
            })?;

            let profile: String = redis::cmd("GET")
                .arg(CacheKey::ValidatorProfileByAccount(acc))
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

async fn get_discovery_from_cache(
    key: &str,
    conn: &mut Connection,
) -> Result<CacheMap, CacheError> {
    let mut discovery: CacheMap = redis::cmd("HGETALL")
        .arg(CacheKey::AuthorityRecordVerbose(
            key.to_string(),
            Verbosity::Discovery,
        ))
        .query_async(conn)
        .await
        .map_err(CacheError::RedisCMDError)?;

    // NOTE: discovery.ips is not needed to be available, so let's skip it.
    discovery.remove("ips");

    return Ok(discovery);
}

/// Get validator by AuthorityKey
async fn get_validator_by_authority_key(
    auth_key: AuthorityKey,
    show_stats: bool,
    show_summary: bool,
    show_discovery: bool,
    show_profile: bool,
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

    if show_discovery {
        let discovery: CacheMap =
            get_discovery_from_cache(&auth_key.to_string(), &mut conn).await?;
        data.extend(discovery);
    }

    if show_profile {
        if let Some(stash) = data.get("address") {
            if let Ok(stash) = AccountId32::from_str(&stash) {
                let profile: String = redis::cmd("GET")
                    .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
                    .query_async(&mut conn as &mut Connection)
                    .await
                    .map_err(CacheError::RedisCMDError)?;
                data.insert(String::from("profile"), profile);
            }
        }
    }

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
    show_discovery: bool,
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
        show_discovery,
        false,
        hide_address,
        cache,
    )
    .await?;
    Ok((data, authority_key_data.into()))
}

/// Get a validators filtered by query params
pub async fn get_validators(
    req: HttpRequest,
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorsResult>, ApiError> {
    let config = CONFIG.clone();
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

    let (start_session, end_session) = if params.from != 0 && params.from < params.to {
        (params.from, params.to)
    } else if params.number_last_sessions != 0 {
        (
            requested_session_index - params.number_last_sessions,
            requested_session_index - 1,
        )
    } else {
        (requested_session_index, requested_session_index)
    };

    // ******************
    //
    // validators by address and last sessions
    //
    if &params.address != "" && params.number_last_sessions != 0 {
        let stash = AccountId32::from_str(&params.address).map_err(|e| {
            ApiError::BadRequest(format!(
                "Invalid account: {:?} error: {e:?}",
                &params.address
            ))
        })?;
        let mut data: Vec<ValidatorResult> = Vec::new();

        let mut i = Some(start_session);
        while let Some(session_index) = i {
            if session_index > end_session {
                i = None;
            } else {
                let (validator_data, mut authority_key) = get_validator_by_stash_and_index(
                    stash.clone(),
                    session_index,
                    params.show_stats,
                    params.show_summary,
                    params.show_discovery,
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
                                            params.show_discovery,
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

                i = Some(session_index + 1);
            }
        }

        return respond_json(ValidatorsResult {
            data,
            ..Default::default()
        });
    }

    // ******************
    //
    // authorities by session
    //
    if params.from != 0 && params.from < params.to && params.role == Role::Authority {
        let mut data: Vec<ValidatorResult> = Vec::new();
        let mut i = Some(start_session);
        while let Some(session_index) = i {
            if session_index > end_session {
                i = None;
            } else {
                let authority_keys: Vec<String> = redis::cmd("SMEMBERS")
                    .arg(CacheKey::AuthorityKeysBySession(session_index))
                    .query_async(&mut conn as &mut Connection)
                    .await
                    .map_err(CacheError::RedisCMDError)?;

                for key in authority_keys.iter() {
                    let val = get_validator_by_authority_key(
                        (*key).clone().into(),
                        params.show_stats,
                        params.show_summary,
                        params.show_discovery,
                        params.show_profile,
                        false,
                        cache.clone(),
                    )
                    .await?;
                    data.push(val.into());
                }
                i = Some(session_index + 1);
            }
        }

        return respond_json(ValidatorsResult {
            data,
            ..Default::default()
        });
    }

    // ******************
    //
    // validators by performance ranking
    //
    // Calculate a score based on the formula
    // SCORE_1 = (1-MVR)*0.50 + BAR * 0.25 + ((AVG_PV_POINTS - MIN_AVG_PV_POINTS)/(MAX_AVG_PV_POINTS-MIN_AVG_PV_POINTS))*0.18 + (PV_SESSIONS/TOTAL_SESSIONS)*0.07
    //
    //
    if params.from != 0 && params.from < params.to && params.ranking == Ranking::Performance {
        // Check if query is already cached
        if let Ok(serialized_data) = redis::cmd("GET")
            .arg(CacheKey::QueryValidators(req.query_string().to_string()))
            .query_async::<Connection, String>(&mut conn)
            .await
        {
            let data: Vec<ValidatorResult> = serde_json::from_str(&serialized_data).unwrap();
            return respond_json(ValidatorsResult {
                data,
                ..Default::default()
            });
        } else {
            //
            // NOTE: the score is based on 7 key values, which will be aggregated in the following map tupple.
            // NOTE: the tuple has a subset, 7 counters plus the final score like: (subset, para_epochs, para_points, explicit_votes, implicit_votes, missed_votes, bitfields_availability, bitfields_unavailability, score)
            //
            let mut aggregator: BTreeMap<String, (Subset, u32, u32, u32, u32, u32, u64, u64, u32)> =
                BTreeMap::new();
            let mut validators: BTreeMap<String, ValidatorResult> = BTreeMap::new();
            let mut total_epochs: u32 = 0;
            let mut i = Some(start_session);
            while let Some(session_index) = i {
                if session_index > end_session {
                    i = None;
                } else {
                    let authority_keys: Vec<String> = redis::cmd("SMEMBERS")
                        .arg(CacheKey::AuthorityKeysBySessionParaOnly(session_index))
                        .query_async(&mut conn as &mut Connection)
                        .await
                        .map_err(CacheError::RedisCMDError)?;

                    for key in authority_keys.iter() {
                        let val = get_validator_by_authority_key(
                            (*key).clone().into(),
                            params.show_stats,
                            true,
                            false,
                            true,
                            false,
                            cache.clone(),
                        )
                        .await?;
                        // NOTE: the tupple has a subset, 7 counters plus the final score like: (subset, para_epochs, para_points, explicit_votes, implicit_votes, missed_vote, bitfields_availability, bitfields_unavailability, score)
                        aggregator
                            .entry(val.address.clone())
                            .and_modify(
                                |(subset, para_epochs, para_points, ev, iv, mv, ba, bu, _)| {
                                    *subset = val.profile.subset.clone();
                                    *para_epochs += 1;
                                    *para_points += val.auth.para_points();
                                    *ev += val.para_summary.explicit_votes();
                                    *iv += val.para_summary.implicit_votes();
                                    *mv += val.para_summary.missed_votes();

                                    if let Some(value) = val.para.get("bitfields") {
                                        if let Some(obj) = value.as_object() {
                                            obj["ba"]
                                                .as_number()
                                                .map(|v| *ba += v.as_u64().unwrap_or(0));
                                            obj["bu"]
                                                .as_number()
                                                .map(|v| *bu += v.as_u64().unwrap_or(0));
                                        }
                                    }
                                },
                            )
                            .or_insert((Subset::NotDefined, 0, 0, 0, 0, 0, 0, 0, 0));
                        validators.insert(val.address.clone(), val);
                    }
                    total_epochs += 1;
                    i = Some(session_index + 1);
                }
            }

            // Convert map to vec to be easily sortable and truncated
            let mut aggregator_vec = Vec::from_iter(aggregator);

            // Normalize avg_para_points
            let avg_para_points: Vec<u32> = aggregator_vec
                .iter()
                .filter(|(_, (_, para_epochs, _, _, _, _, _, _, _))| *para_epochs >= 1)
                .map(|(_, (_, para_epochs, para_points, _, _, _, _, _, _))| {
                    para_points / para_epochs
                })
                .collect();
            let max = avg_para_points.iter().max().unwrap_or_else(|| &0);
            let min = avg_para_points.iter().min().unwrap_or_else(|| &0);

            // Calculate scores & mutate validator result
            // NOTE: the tupple has a subset, 5 counters plus the final score like: (subset, para_epochs, para_points, explicit_votes, implicit_votes, missed_vote, score)
            //
            aggregator_vec
                .iter_mut()
                .filter(|(_, (_, para_epochs, _, _, _, _, _, _, _))| *para_epochs >= 1)
                .for_each(
                    |(stash, (_, para_epochs, para_points, ev, iv, mv, ba, bu, s))| {
                        let mvr = *mv as f64 / (*ev + *iv + *mv) as f64;
                        let bar = *ba as f64 / (*ba + *bu) as f64;
                        let avg_para_points = *para_points / *para_epochs;
                        let score = if max - min > 0 {
                            (((1.0_f64 - mvr) * 0.50_f64
                                + bar * 0.25_f64
                                + ((avg_para_points - *min) as f64 / (*max - *min) as f64)
                                    * 0.18_f64
                                + (*para_epochs as f64 / total_epochs as f64) * 0.07_f64)
                                * 1000000.0_f64) as u32
                        } else {
                            0
                        };
                        *s = score;
                        // Add ranking stats to the validator result
                        validators.entry(stash.clone()).and_modify(|v| {
                            v.ranking =
                                RankingStats::with(score, mvr, avg_para_points, *para_epochs);
                        });
                    },
                );

            // Filter by subset and min para epochs
            // min_para_epochs = 1 if total_full_epochs < 12;
            // min_para_epochs = 2 if total_full_epochs < 24;
            // min_para_epochs = 3 if total_full_epochs < 36;
            // min_para_epochs = 4 if total_full_epochs < 48;
            // min_para_epochs = 5 if total_full_epochs = 48;
            let min_para_epochs = (total_epochs / 12) + 1;

            let mut i = 0;
            while i < aggregator_vec.len() {
                let (_, (subset, para_epochs, _, _, _, _, _, _, _)) = &mut aggregator_vec[i];
                if (*subset != params.subset && params.subset != Subset::NotDefined)
                    || *para_epochs < min_para_epochs
                {
                    aggregator_vec.remove(i);
                } else {
                    i += 1;
                }
            }

            // Sort ranking validators by score
            aggregator_vec.sort_by(
                |(_, (_, _, _, _, _, _, _, _, a)), (_, (_, _, _, _, _, _, _, _, b))| b.cmp(&a),
            );

            // Truncate aggregator
            if params.size > 0 {
                aggregator_vec.truncate(params.size.try_into().unwrap());
            }

            // Create data response
            let mut data: Vec<ValidatorResult> = Vec::new();
            for (stash, _) in aggregator_vec {
                if let Some(val) = validators.get(&stash) {
                    data.push(val.clone().into());
                }
            }

            // Serialize data and cache for one session
            // 1 hour kusama, 4 hours polkadot
            let serialized = serde_json::to_string(&data)?;
            redis::cmd("SET")
                .arg(CacheKey::QueryValidators(req.query_string().to_string()))
                .arg(serialized.to_string())
                .arg("ex")
                .arg(config.blocks_per_session * 6)
                .query_async::<Connection, String>(&mut conn)
                .await
                .map_err(CacheError::RedisCMDError)?;

            return respond_json(ValidatorsResult {
                data,
                ..Default::default()
            });
        }
    }

    // ******************
    //
    // validators in pools (nominees)
    //
    if params.nominees_only || params.ranking == Ranking::Pools {
        let mut data: Vec<ValidatorResult> = Vec::new();
        let mut nominees: BTreeMap<AccountId32, u32> = BTreeMap::new();
        if let Ok(session_pool_ids) = redis::cmd("ZRANGE")
            .arg(CacheKey::NominationPoolIdsBySession(
                requested_session_index,
            ))
            .arg(0) // min
            .arg(-1) // max
            .query_async::<Connection, Vec<PoolId>>(&mut conn)
            .await
        {
            if !session_pool_ids.is_empty() {
                for id in session_pool_ids.iter() {
                    // pull pool nominees and build a unique set of stashes
                    if let Ok(serialized_data) = redis::cmd("GET")
                        .arg(CacheKey::NominationPoolNomineesByPoolAndSession(
                            *id,
                            requested_session_index,
                        ))
                        .query_async::<Connection, String>(&mut conn)
                        .await
                    {
                        let pool_nominees: PoolNominees =
                            serde_json::from_str(&serialized_data).unwrap_or_default();
                        for stash in pool_nominees.nominees {
                            nominees.entry(stash).and_modify(|s| *s += 1).or_insert(1);
                        }
                    }
                }
            }

            // Convert map to vec to be easily sortable and truncated
            let mut nominees_vec = Vec::from_iter(nominees);
            // Pool ranking is just based on how many times a validator is picked by pool operators has nominee
            if params.ranking == Ranking::Pools {
                nominees_vec.sort_by(|(_, a), (_, b)| b.cmp(&a));
            }
            // Truncate nominees
            if params.size > 0 {
                nominees_vec.truncate(params.size.try_into().unwrap());
            }
            //
            // Pull profiles
            //
            for (stash, counter) in nominees_vec {
                if let Ok(authority_key_data) = redis::cmd("HGETALL")
                    .arg(CacheKey::AuthorityKeyByAccountAndSession(
                        stash.clone(),
                        requested_session_index,
                    ))
                    .query_async::<Connection, AuthorityKeyCache>(&mut conn as &mut Connection)
                    .await
                {
                    if authority_key_data.is_empty() {
                        // pull only profile
                        if let Ok(serialized_data) = redis::cmd("GET")
                            .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
                            .query_async::<Connection, String>(&mut conn as &mut Connection)
                            .await
                        {
                            let mut v = ValidatorResult::with_address(stash.to_string());
                            v.session = requested_session_index;
                            v.profile = serde_json::from_str(&serialized_data).unwrap_or_default();
                            v.pool_counter = counter;
                            data.push(v);
                        }
                    } else {
                        let authority_key: AuthorityKey = authority_key_data.into();

                        if let Ok(mut v) = get_validator_by_authority_key(
                            authority_key,
                            params.show_stats,
                            params.show_summary,
                            params.show_discovery,
                            params.show_profile,
                            false,
                            cache.clone(),
                        )
                        .await
                        {
                            v.pool_counter = counter;
                            data.push(v);
                        }
                    }
                }
            }
        }

        return respond_json(ValidatorsResult {
            data,
            ..Default::default()
        });
    }

    // ******************
    //
    // (default) validators in current session
    //
    let res: ValidatorsResult = get_session_authorities(
        requested_session_index,
        params.role.clone(),
        params.show_stats,
        params.show_summary,
        params.show_discovery,
        params.show_profile,
        cache,
    )
    .await?;

    respond_json(res.into())
}

/// Get a validator by stash
pub async fn get_validator_by_stash(
    stash: Path<String>,
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let stash = AccountId32::from_str(&*stash.to_string()).map_err(|e| {
        ApiError::BadRequest(format!(
            "Invalid account: {:?} error: {e:?}",
            &*stash.to_string()
        ))
    })?;

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
        params.show_discovery,
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

    let stash = AccountId32::from_str(&*stash.to_string()).map_err(|e| {
        ApiError::BadRequest(format!(
            "Invalid account: {:?} error: {e:?}",
            &*stash.to_string()
        ))
    })?;

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
        params.show_discovery,
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
    let stash = AccountId32::from_str(&*stash.to_string()).map_err(|e| {
        ApiError::BadRequest(format!(
            "Invalid account: {:?} error: {e:?}",
            &*stash.to_string()
        ))
    })?;

    let serialized_data: String = redis::cmd("GET")
        .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    respond_json(serialized_data.into())
}

async fn calculate_validator_grade_by_stash(
    stash: String,
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<ValidatorGradeResult, ApiError> {
    let config = CONFIG.clone();
    let mut conn = get_conn(&cache).await?;
    let stash = AccountId32::from_str(&*stash.to_string()).map_err(|e| {
        ApiError::BadRequest(format!(
            "Invalid account: {:?} error: {e:?}",
            &*stash.to_string()
        ))
    })?;

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
        Index::Num(index) => (*index as u32).min(u32::MAX),
        _ => redis::cmd("GET")
            .arg(CacheKey::SessionByIndex(Index::Current))
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?,
    };

    let mut data: Vec<ValidatorResult> = Vec::new();

    if params.number_last_sessions > 0
        && params.number_last_sessions <= config.maximum_number_last_sessions
    {
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
                    false,
                    true,
                    cache.clone(),
                )
                .await?;

                data.push(validator_data.clone().into());

                last = Some(session_index + 1);
            }
        }
    } else {
        let msg = format!(
            "The value of parameter 'number_last_sessions' must be between 1 and {}.",
            config.maximum_number_last_sessions
        );
        warn!("{}", msg);
        return Err(ApiError::NotFound(msg));
    }

    // calculate auth_epochs and para_epochs
    let auth_epochs = data.iter().filter(|v| v.is_auth).count();
    let para_epochs = data.iter().filter(|v| v.is_para).count();

    if para_epochs == 0 {
        if params.show_summary {
            return Ok(ValidatorGradeResult {
                address: stash.to_string(),
                grade: Grade::NA.to_string(),
                authority_inclusion: auth_epochs as f64 / params.number_last_sessions as f64,
                para_authority_inclusion: para_epochs as f64 / params.number_last_sessions as f64,
                sessions_data: data.into(),
                ..Default::default()
            });
        }
        return Ok(ValidatorGradeResult {
            address: stash.to_string(),
            grade: Grade::NA.to_string(),
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

    // calculate bur if para_epochs > 0
    let burs: Vec<f64> = data
        .iter()
        .filter(|v| v.is_para)
        .filter_map(|v| v.para.get("bitfields"))
        .filter_map(|value| serde_json::from_value::<BitfieldsRecord>(value.clone()).ok())
        .map(|bitfields| {
            let partial = bitfields.availability() + bitfields.unavailability();
            if partial > 0 {
                bitfields.unavailability() as f64 / partial as f64
            } else {
                0.0_f64
            }
        })
        .collect();

    let bur = burs.iter().sum::<f64>() / para_epochs as f64;

    if params.show_summary {
        return Ok(ValidatorGradeResult {
            address: stash.to_string(),
            grade: grade(mvr, bur).to_string(),
            authority_inclusion: auth_epochs as f64 / params.number_last_sessions as f64,
            para_authority_inclusion: para_epochs as f64 / params.number_last_sessions as f64,
            explicit_votes_total: data
                .iter()
                .filter(|v| v.is_para)
                .map(|v| v.para_summary.explicit_votes)
                .sum(),
            implicit_votes_total: data
                .iter()
                .filter(|v| v.is_para)
                .map(|v| v.para_summary.implicit_votes)
                .sum(),
            missed_votes_total: data
                .iter()
                .filter(|v| v.is_para)
                .map(|v| v.para_summary.missed_votes)
                .sum(),
            bitfields_availability_total: data
                .iter()
                .filter(|v| v.is_para)
                .filter_map(|v| v.para.get("bitfields"))
                .filter_map(|value| serde_json::from_value::<BitfieldsRecord>(value.clone()).ok())
                .map(|bitfields| bitfields.availability())
                .sum(),
            bitfields_unavailability_total: data
                .iter()
                .filter(|v| v.is_para)
                .filter_map(|v| v.para.get("bitfields"))
                .filter_map(|value| serde_json::from_value::<BitfieldsRecord>(value.clone()).ok())
                .map(|bitfields| bitfields.unavailability())
                .sum(),
            sessions_data: data.into(),
            ..Default::default()
        });
    }

    return Ok(ValidatorGradeResult {
        address: stash.to_string(),
        grade: grade(mvr, bur).to_string(),
        authority_inclusion: auth_epochs as f64 / params.number_last_sessions as f64,
        para_authority_inclusion: para_epochs as f64 / params.number_last_sessions as f64,
        explicit_votes_total: data
            .iter()
            .filter(|v| v.is_para)
            .map(|v| v.para_summary.explicit_votes)
            .sum(),
        implicit_votes_total: data
            .iter()
            .filter(|v| v.is_para)
            .map(|v| v.para_summary.implicit_votes)
            .sum(),
        missed_votes_total: data
            .iter()
            .filter(|v| v.is_para)
            .map(|v| v.para_summary.missed_votes)
            .sum(),
        bitfields_availability_total: data
            .iter()
            .filter(|v| v.is_para)
            .filter_map(|v| v.para.get("bitfields"))
            .filter_map(|value| serde_json::from_value::<BitfieldsRecord>(value.clone()).ok())
            .map(|bitfields| bitfields.availability())
            .sum(),
        bitfields_unavailability_total: data
            .iter()
            .filter(|v| v.is_para)
            .filter_map(|v| v.para.get("bitfields"))
            .filter_map(|value| serde_json::from_value::<BitfieldsRecord>(value.clone()).ok())
            .map(|bitfields| bitfields.unavailability())
            .sum(),
        sessions: data.iter().map(|v| v.session).collect(),
        ..Default::default()
    });
}

/// Get a validator grade by stash
pub async fn get_validator_grade_by_stash(
    stash: Path<String>,
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<ValidatorGradeResult>, ApiError> {
    let data = calculate_validator_grade_by_stash(stash.to_string(), params, cache).await?;

    return respond_json(data);
}

/// Get list o cohorts
/// NOTE: currently is fixed to one cohort
pub async fn get_cohorts() -> Result<Json<CohortsResult>, ApiError> {
    let cohorts = CohortsResult { data: vec![1_u32] };
    respond_json(cohorts)
}

/// Get all validators grades assigned to the specific cohort
pub async fn get_cohort_validators_grades(
    cohort: Path<u32>,
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<CohortValidatorsGradesResult>, ApiError> {
    let cohort_number = cohort.into_inner();

    let stashes: Vec<AccountId32> =
        try_fetch_stashes_from_remote_url(false, Some(cohort_number)).await?;

    let mut data: Vec<ValidatorGradeResult> = Vec::new();
    for stash in stashes.iter() {
        let mut tmp =
            calculate_validator_grade_by_stash(stash.to_string(), params.clone(), cache.clone())
                .await?;
        // Note: sessions are empty by default
        if !params.show_sessions {
            tmp.sessions = vec![];
        }
        data.push(tmp);
    }

    return respond_json(CohortValidatorsGradesResult {
        cohort: cohort_number,
        data,
    });
}

/// Get list of available eras
/// TODO: Implement this function
pub async fn get_eras() -> Result<Json<ErasResult>, ApiError> {
    let eras = ErasResult { data: vec![] };
    respond_json(eras)
}

/// Get all validators grades assigned to the specific cohort
pub async fn get_era_validators_grades(
    era: Path<u32>,
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<EraValidatorsGradesResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;
    let era_index = era.into_inner();

    let session_index: u32 = redis::cmd("HGET")
        .arg(CacheKey::EraByIndex(Index::Num(era_index.into())))
        .arg(String::from("synced_session"))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    // Verify how many sessions are available for the specific era
    let era_session_index: u32 = redis::cmd("HGET")
        .arg(CacheKey::SessionByIndex(Index::Num(session_index.into())))
        .arg(String::from("era_session_index"))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    // Fetch latest synced session authorities
    let authorities: Vec<String> = redis::cmd("SMEMBERS")
        .arg(CacheKey::AuthorityKeysBySession(session_index))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    let mut stashes: Vec<String> = Vec::new();
    for key in authorities.iter() {
        let stash: String = redis::cmd("HGET")
            .arg(key)
            .arg("address")
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;
        stashes.push(stash.into());
    }

    // Update session params used to calculate validator grades with `fn calculate_validator_grade_by_stash`
    // NOTE: `session_index` is non inclusive so we need to add 1 to it
    let mut params = params.clone();
    params.session = Index::Num((session_index + 1).into());
    params.number_last_sessions = era_session_index;

    // Keep track of sessions from which we calculate validator grades
    let mut sessions: Vec<u32> = Vec::new();
    for i in 0..era_session_index {
        sessions.push(session_index - i);
    }

    // Calculate validator grades for each stash for the given era
    let mut data: Vec<ValidatorGradeResult> = Vec::new();
    for stash in stashes.iter() {
        let mut tmp =
            calculate_validator_grade_by_stash(stash.to_string(), params.clone(), cache.clone())
                .await?;
        // Note: sessions are empty by default
        if !params.show_sessions {
            tmp.sessions = vec![];
        }
        data.push(tmp);
    }

    return respond_json(EraValidatorsGradesResult {
        era: era_index,
        sessions: sessions,
        data,
    });
}
