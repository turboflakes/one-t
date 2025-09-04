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
//

use crate::error::CacheError;
use crate::types::{CacheKey, Trait};
use onet_mcda::criterias::{CriteriaLimits, Interval};
use onet_records::EpochIndex;

use redis::aio::Connection;
use std::result::Result;

async fn calculate_min_limit(
    cache: &mut Connection,
    session_index: EpochIndex,
    attribute: Trait,
) -> Result<u64, CacheError> {
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
        .query_async(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;
    if v.len() == 0 {
        return Ok(0);
    }
    Ok(v[0].1)
}

async fn calculate_max_limit(
    cache: &mut Connection,
    session_index: EpochIndex,
    attribute: Trait,
) -> Result<u64, CacheError> {
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
        .query_async(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;
    if v.len() == 0 {
        return Ok(0);
    }
    Ok(v[0].1)
}

async fn calculate_min_max_interval(
    cache: &mut Connection,
    session_index: EpochIndex,
    attribute: Trait,
) -> Result<Interval, CacheError> {
    let max = calculate_max_limit(cache, session_index, attribute.clone()).await?;
    let min = calculate_min_limit(cache, session_index, attribute).await?;
    Ok(Interval { min, max })
}

pub async fn build_limits_from_session(
    cache: &mut Connection,
    session_index: EpochIndex,
) -> Result<CriteriaLimits, CacheError> {
    let own_stake_interval =
        calculate_min_max_interval(cache, session_index, Trait::OwnStake).await?;

    let nominators_stake_interval =
        calculate_min_max_interval(cache, session_index, Trait::NominatorsStake).await?;

    let nominators_counter_interval =
        calculate_min_max_interval(cache, session_index, Trait::NominatorsCounter).await?;

    Ok(CriteriaLimits {
        own_stake: own_stake_interval,
        nominators_stake: nominators_stake_interval,
        nominators_counter: nominators_counter_interval,
        ..Default::default()
    })
}
