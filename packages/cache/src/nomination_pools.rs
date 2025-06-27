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

use super::types::CacheKey;
use onet_config::Config;
use onet_errors::{CacheError, OnetError};
use onet_pools::{Pool, PoolId, PoolNominees, PoolStats};
use onet_records::EpochIndex;

use redis::aio::Connection;
use std::result::Result;

pub async fn cache_nomination_pool(
    cache: &mut Connection,
    config: &Config,
    pool: &Pool,
    pool_id: PoolId,
    current_epoch: EpochIndex,
) -> Result<(), OnetError> {
    let serialized = serde_json::to_string(&pool)?;
    redis::pipe()
        .atomic()
        .cmd("SET")
        .arg(CacheKey::NominationPoolRecord(pool_id))
        .arg(serialized)
        .cmd("EXPIRE")
        .arg(CacheKey::NominationPoolRecord(pool_id))
        .arg(config.cache_writer_prunning)
        .cmd("ZADD")
        .arg(CacheKey::NominationPoolIdsBySession(current_epoch))
        .arg(0)
        .arg(pool_id)
        .cmd("EXPIRE")
        .arg(CacheKey::NominationPoolIdsBySession(pool_id))
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

pub async fn cache_nomination_pool_nominees(
    cache: &mut Connection,
    config: &Config,
    pool_nominees: &PoolNominees,
    pool_id: PoolId,
    current_epoch: EpochIndex,
) -> Result<(), OnetError> {
    let serialized = serde_json::to_string(&pool_nominees)?;
    redis::pipe()
        .atomic()
        .cmd("SET")
        .arg(CacheKey::NominationPoolNomineesByPoolAndSession(
            pool_id,
            current_epoch,
        ))
        .arg(serialized)
        .cmd("EXPIRE")
        .arg(CacheKey::NominationPoolStatsByPoolAndSession(
            pool_id,
            current_epoch,
        ))
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

pub async fn cache_nomination_pool_stats(
    cache: &mut Connection,
    config: &Config,
    stats: &PoolStats,
    pool_id: PoolId,
    current_epoch: EpochIndex,
) -> Result<(), OnetError> {
    let serialized = serde_json::to_string(&stats)?;
    redis::pipe()
        .atomic()
        .cmd("SET")
        .arg(CacheKey::NominationPoolStatsByPoolAndSession(
            pool_id,
            current_epoch,
        ))
        .arg(serialized)
        .cmd("EXPIRE")
        .arg(CacheKey::NominationPoolStatsByPoolAndSession(
            pool_id,
            current_epoch,
        ))
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}
