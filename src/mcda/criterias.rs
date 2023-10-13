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

use crate::cache::{get_conn, CacheKey, RedisConn, RedisPool, Trait};
use crate::errors::{CacheError, OnetError};
use crate::records::EpochIndex;
use log::{error, warn};
use redis::aio::Connection;
use serde::{de::Deserializer, Deserialize, Serialize};
use std::{collections::BTreeMap, str::FromStr};

/// NOTE: Assumption of the number of decimals in scores or limits
pub const DECIMALS: u32 = 7;

/// Current weighs and limits capacity
pub const CAPACITY: usize = 2;

// TODO: get this constants from chain
const NOMINATORS_OVERSUBSCRIBED_THRESHOLD: u32 = 256;

/// Weight can be any value in a 10-point scale. Higher the weight more important
/// is the criteria to the user
type Weight = u8;

/// Weights represent an array of points, where the points in each position represents
/// the weight for the respective criteria
/// Position 0 - Lower Commission is preferrable
/// Position 1 - Higher own stake is preferrable
///
///
///
/// TODO:
/// Position 1 - Higher Inclusion rate is preferrable
/// Position 2 - Lower Nominators is preferrable (limit to 256 -> oversubscribed)
/// Position 3 - Higher Reward Points is preferrable
/// Position 4 - If reward is staked is preferrable
/// Position 5 - If in active set is preferrable
/// Position 7 - Lower total stake is preferrable
/// Position 8 - Higher number of Reasonable or KnownGood judgements is preferrable
/// Position 9 - Lower number of sub-accounts is preferrable
pub type Weights = Vec<Weight>;

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct CriteriaWeights {
    pub commission: Weight,
    pub own_stake: Weight,
}

impl From<&Weights> for CriteriaWeights {
    fn from(data: &Weights) -> Self {
        CriteriaWeights {
            commission: *data.get(0).unwrap_or(&0),
            own_stake: *data.get(1).unwrap_or(&0),
        }
    }
}

// NOTE: Intervals are considered unsigned integers bringing a 7 decimals representation
// ex1: 20% = 200000000
// ex2: 121.34 DOTs = 1213400000
#[derive(Debug, Serialize, PartialEq, Copy, Clone)]
pub struct Interval {
    pub min: u64,
    pub max: u64,
}

impl Default for Interval {
    fn default() -> Interval {
        Interval { min: 0, max: 0 }
    }
}

impl std::fmt::Display for Interval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.min, self.max)
    }
}

pub type Intervals = Vec<Interval>;

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct CriteriaLimits {
    pub commission: Interval,
    pub own_stake: Interval,
    // pub inclusion_rate: Interval,
    // pub nominators: Interval,
    // pub avg_reward_points: Interval,
    // pub reward_staked: Interval,
    // pub active: Interval,
    // pub total_stake: Interval,
    // pub judgements: Interval,
    // pub sub_accounts: Interval,
}

impl Default for CriteriaLimits {
    fn default() -> CriteriaLimits {
        let base = 10_u64;
        CriteriaLimits {
            commission: Interval {
                min: 0,
                max: 100 * base.pow(DECIMALS),
            },
            own_stake: Interval::default(),
            // inclusion_rate: Interval::default(),
            // nominators: Interval::default(),
            // avg_reward_points: Interval::default(),
            // reward_staked: Interval::default(),
            // active: Interval::default(),
            // total_stake: Interval::default(),
            // judgements: Interval::default(),
            // sub_accounts: Interval::default(),
        }
    }
}

impl std::fmt::Display for CriteriaLimits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Note: the position of the traits is important, it should be the same as the position in weights
        write!(
            f,
            "{},{}",
            self.commission.to_string(),
            self.own_stake.to_string(),
            // self.inclusion_rate.to_string(),
            // self.nominators.to_string(),
            // self.avg_reward_points.to_string(),
            // self.reward_staked.to_string(),
            // self.active.to_string(),
            // self.total_stake.to_string(),
            // self.judgements.to_string(),
            // self.sub_accounts.to_string()
        )
    }
}

impl From<&Intervals> for CriteriaLimits {
    fn from(data: &Intervals) -> Self {
        CriteriaLimits {
            commission: *data.get(0).unwrap_or(&Interval::default()),
            own_stake: *data.get(1).unwrap_or(&Interval::default()),
            // inclusion_rate: *data.get(1).unwrap_or(&Interval::default()),
            // nominators: *data.get(2).unwrap_or(&Interval::default()),
            // avg_reward_points: *data.get(3).unwrap_or(&Interval::default()),
            // reward_staked: *data.get(4).unwrap_or(&Interval::default()),
            // active: *data.get(5).unwrap_or(&Interval::default()),
            // total_stake: *data.get(7).unwrap_or(&Interval::default()),
            // judgements: *data.get(8).unwrap_or(&Interval::default()),
            // sub_accounts: *data.get(9).unwrap_or(&Interval::default()),
        }
    }
}

// pub type CriteriaLimitsCache = BTreeMap<String, u64>;

// impl From<CriteriaLimitsCache> for CriteriaLimits {
//     fn from(data: CriteriaLimitsCache) -> Self {
//         let default_min = 0_u64;
//         let default_max = 100_u64;
//         let base = 10_u64;
//         CriteriaLimits {
//             commission: Interval {
//                 min: 0,
//                 max: 100 * base.pow(DECIMALS),
//             },
//             own_stake: Interval {
//                 min: *data.get("min_own_stake").unwrap_or(&default_min),
//                 max: *data.get("max_own_stake").unwrap_or(&default_max),
//             },
//             // inclusion_rate: Interval {
//             //     min: 0.0_f64,
//             //     max: 1.0_f64,
//             // },
//             // nominators: Interval {
//             //     min: 0.0_f64,
//             //     max: NOMINATORS_OVERSUBSCRIBED_THRESHOLD as f64,
//             // },
//             // avg_reward_points: Interval {
//             //     min: *data.get("min_avg_reward_points").unwrap_or(&default_min),
//             //     max: *data.get("max_avg_reward_points").unwrap_or(&default_max),
//             // },
//             // reward_staked: Interval {
//             //     min: 0.0_f64,
//             //     max: 1.0_f64,
//             // },
//             // active: Interval {
//             //     min: 0.0_f64,
//             //     max: 1.0_f64,
//             // },
//             // total_stake: Interval {
//             //     min: *data.get("min_total_stake").unwrap_or(&default_min),
//             //     max: *data.get("max_total_stake").unwrap_or(&default_max),
//             // },
//             // judgements: Interval {
//             //     min: *data.get("min_judgements").unwrap_or(&default_min),
//             //     max: *data.get("max_judgements").unwrap_or(&default_max),
//             // },
//             // sub_accounts: Interval {
//             //     min: *data.get("min_sub_accounts").unwrap_or(&default_min),
//             //     max: *data.get("max_sub_accounts").unwrap_or(&default_max),
//             // },
//         }
//     }
// }

async fn calculate_min_limit(
    cache: &RedisPool,
    session_index: EpochIndex,
    attribute: Trait,
) -> Result<u64, OnetError> {
    let mut conn = get_conn(&cache).await?;
    let v: Vec<(String, u64)> = redis::cmd("ZRANGE")
        .arg(CacheKey::NomiBoardBySessionAndTrait(
            session_index,
            attribute,
        ))
        .arg("-inf")
        .arg("+inf")
        .arg("BYSCORE")
        .arg("LIMIT")
        .arg("0")
        .arg("1")
        .arg("WITHSCORES")
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;
    if v.len() == 0 {
        return Ok(0);
    }
    Ok(v[0].1)
}

async fn calculate_max_limit(
    cache: &RedisPool,
    session_index: EpochIndex,
    attribute: Trait,
) -> Result<u64, OnetError> {
    let mut conn = get_conn(&cache).await?;
    let v: Vec<(String, u64)> = redis::cmd("ZRANGE")
        .arg(CacheKey::NomiBoardBySessionAndTrait(
            session_index,
            attribute,
        ))
        .arg("+inf")
        .arg("-inf")
        .arg("BYSCORE")
        .arg("REV")
        .arg("LIMIT")
        .arg("0")
        .arg("1")
        .arg("WITHSCORES")
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;
    if v.len() == 0 {
        return Ok(0);
    }
    Ok(v[0].1)
}

async fn calculate_min_max_interval(
    cache: &RedisPool,
    session_index: EpochIndex,
    attribute: Trait,
) -> Result<Interval, OnetError> {
    let max = calculate_max_limit(&cache.clone(), session_index, attribute.clone()).await?;
    let min = calculate_min_limit(&cache.clone(), session_index, attribute).await?;
    Ok(Interval { min, max })
}

pub async fn build_limits_from_session(
    cache: &RedisPool,
    session_index: EpochIndex,
) -> Result<CriteriaLimits, OnetError> {
    let own_stake_interval =
        calculate_min_max_interval(&cache.clone(), session_index, Trait::OwnStake).await?;

    Ok(CriteriaLimits {
        own_stake: own_stake_interval,
        ..Default::default()
    })
    // limits.insert("min_own_stake".to_string(), own_stake_interval.0);
    // limits.insert("max_own_stake".to_string(), own_stake_interval.1);

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

    // Ok(limits.into())
}
