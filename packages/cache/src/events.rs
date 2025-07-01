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

use super::types::{CacheKey, ChainKey};
use onet_config::Config;
use onet_errors::{CacheError, OnetError};
use onet_pools::{Pool, PoolId, PoolNominees, PoolStats};
use onet_records::{BlockNumber, EpochIndex};

use redis::aio::Connection;
use std::result::Result;

// Self::Event(chain, block_index) => {
//     write!(f, "ev:{}:{}", chain, block_index)
// }
// Self::EventsByEra(era_index) => {
//     write!(f, "evs:{}", era_index)
// }

pub async fn cache_event(
    cache: &mut Connection,
    config: &Config,
    chain_key: ChainKey,
    block_number: BlockNumber,
    data: String,
    current_epoch: EpochIndex,
) -> Result<(), OnetError> {
    // let serialized = serde_json::to_string(&pool)?;
    // redis::pipe()
    //     .atomic()
    //     .cmd("SET")
    //     .arg(CacheKey::NominationPoolRecord(pool_id))
    //     .arg(serialized)
    //     .cmd("EXPIRE")
    //     .arg(CacheKey::NominationPoolRecord(pool_id))
    //     .arg(config.cache_writer_prunning)
    //     .cmd("ZADD")
    //     .arg(CacheKey::NominationPoolIdsBySession(current_epoch))
    //     .arg(0)
    //     .arg(pool_id)
    //     .cmd("EXPIRE")
    //     .arg(CacheKey::NominationPoolIdsBySession(pool_id))
    //     .arg(config.cache_writer_prunning)
    //     .query_async::<_, ()>(cache)
    //     .await
    //     .map_err(CacheError::RedisCMDError)?;

    Ok(())
}
