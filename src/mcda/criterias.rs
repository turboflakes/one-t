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

use crate::cache::{get_conn, CacheKey, RedisPool, Trait};
use crate::errors::{CacheError, OnetError};
use crate::mcda::scores::base_decimals;
use crate::records::EpochIndex;
use redis::aio::Connection;
use serde::{Deserialize, Serialize};
use subxt::ext::sp_core::H256;

/// NOTE: Assumption of the number of decimals in scores or limits
pub const DECIMALS: u32 = 7;

/// Current weighs and limits capacity
pub const WEIGHTS_CAPACITY: usize = 5;

/// Weights represent an array of points, where the points in each position represents
/// the weight for the respective criteria
///
/// Position 0 - Lower Commission is preferrable
/// Position 1 - Higher own stake is preferrable
/// Position 2 - Higher Nominators stake is preferrable (limit to 256 -> oversubscribed)
/// Position 3 - Lower Nominators is preferrable
/// Position 4 - Lower MVR is preferrable (MVR = Missed Votes Ratio)
///
/// UNDER CONSIDERATION
///
/// NICE TO HAVE:
/// - Higher Inclusion rate is preferrable
/// - Higher number of Reasonable or KnownGood judgements is preferrable
/// - Lower number of sub-accounts is preferrable
/// - Validator Continent/Country location
///
/// Weight can be any value in a 10-point scale. Higher the weight more important
/// is the criteria to the user
type Weight = u8;
///
pub type Weights = Vec<Weight>;

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct CriteriaWeights {
    pub commission: Weight,
    pub own_stake: Weight,
    pub nominators_stake: Weight,
    pub nominators_counter: Weight,
    pub mvr: Weight,
}

impl From<&Weights> for CriteriaWeights {
    fn from(data: &Weights) -> Self {
        CriteriaWeights {
            commission: *data.get(0).unwrap_or(&0),
            own_stake: *data.get(1).unwrap_or(&0),
            nominators_stake: *data.get(2).unwrap_or(&0),
            nominators_counter: *data.get(3).unwrap_or(&0),
            mvr: *data.get(4).unwrap_or(&0),
        }
    }
}

/// Current weighs and limits capacity
pub const FILTERS_CAPACITY: usize = 4;

/// Filters represent a binary array of possible filters to reduce the list of validators
/// used in the score calculation
///
/// Position 0 - active
/// Position 1 - identity
/// Position 2 - not_oversubscribed
/// Position 3 - tvp
///
/// UNDER CONSIDERATION
/// - only_reward_compounded
///
type Filter = bool;
pub type Filters = Vec<Filter>;

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct CriteriaFilters {
    pub active: Filter,
    pub identity: Filter,
    pub not_oversubscribed: Filter,
    pub tvp: Filter,
}

impl From<&Filters> for CriteriaFilters {
    fn from(data: &Filters) -> Self {
        CriteriaFilters {
            active: *data.get(0).unwrap_or(&(false)),
            identity: *data.get(1).unwrap_or(&(false)),
            not_oversubscribed: *data.get(2).unwrap_or(&(false)),
            tvp: *data.get(3).unwrap_or(&(false)),
        }
    }
}

// NOTE: Intervals are considered unsigned integers bringing a 7 decimals representation
// ex1: 20% = 200000000
// ex2: 121.34 DOTs = 1213400000
#[derive(Debug, Serialize, Deserialize, PartialEq, Copy, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct CriteriaLimits {
    pub commission: Interval,
    pub own_stake: Interval,
    pub nominators_stake: Interval,
    pub nominators_counter: Interval,
    pub mvr: Interval,
}

impl Default for CriteriaLimits {
    fn default() -> CriteriaLimits {
        CriteriaLimits {
            commission: Interval {
                min: 0,
                max: 100 * base_decimals(),
            },
            own_stake: Interval::default(),
            nominators_stake: Interval::default(),
            nominators_counter: Interval::default(),
            mvr: Interval {
                min: 0,
                max: base_decimals(),
            },
        }
    }
}

impl std::fmt::Display for CriteriaLimits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Note: the position of the traits is important, it should be the same as the position in weights
        write!(
            f,
            "{},{},{},{},{}",
            self.commission.to_string(),
            self.own_stake.to_string(),
            self.nominators_stake.to_string(),
            self.nominators_counter.to_string(),
            self.mvr.to_string(),
        )
    }
}

impl From<&Intervals> for CriteriaLimits {
    fn from(data: &Intervals) -> Self {
        CriteriaLimits {
            commission: *data.get(0).unwrap_or(&Interval::default()),
            own_stake: *data.get(1).unwrap_or(&Interval::default()),
            nominators_stake: *data.get(2).unwrap_or(&Interval::default()),
            nominators_counter: *data.get(3).unwrap_or(&Interval::default()),
            mvr: *data.get(4).unwrap_or(&Interval::default()),
        }
    }
}

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

    let nominators_stake_interval =
        calculate_min_max_interval(&cache.clone(), session_index, Trait::NominatorsStake).await?;

    let nominators_counter_interval =
        calculate_min_max_interval(&cache.clone(), session_index, Trait::NominatorsCounter).await?;

    Ok(CriteriaLimits {
        own_stake: own_stake_interval,
        nominators_stake: nominators_stake_interval,
        nominators_counter: nominators_counter_interval,
        ..Default::default()
    })
}

pub fn criterias_hash(weights: &Weights, intervals: &Intervals, filters: &Filters) -> H256 {
    let data = format!(
        "{}|{}|{}",
        weights.to_string(),
        intervals.to_string(),
        filters.to_string()
    );
    let hash = sp_core_hashing::blake2_256(data.as_bytes());
    H256::from(&hash)
}

pub trait ToString {
    fn to_string(&self) -> String;
}

impl ToString for Weights {
    fn to_string(&self) -> String {
        self.iter()
            .enumerate()
            .map(|(i, x)| {
                if i == 0 {
                    return format!("{}", x);
                }
                format!(",{}", x)
            })
            .collect()
    }
}

impl ToString for Intervals {
    fn to_string(&self) -> String {
        self.iter()
            .enumerate()
            .map(|(i, x)| {
                if i == 0 {
                    return format!("{}", x);
                }
                format!(",{}", x)
            })
            .collect()
    }
}

impl ToString for Filters {
    fn to_string(&self) -> String {
        self.iter()
            .enumerate()
            .map(|(i, x)| {
                if i == 0 {
                    return format!("{}", *x as i32);
                }
                format!(",{}", *x as i32)
            })
            .collect()
    }
}
