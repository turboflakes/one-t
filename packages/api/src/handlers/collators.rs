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
use crate::{helpers::respond_json, responses::CollatorsResult};
use actix_web::web::{Data, Json, Query};
use log::warn;
use onet_cache::{
    error::CacheError,
    provider::{get_conn, RedisPool},
    types::{CacheKey, ChainKey, Index},
};
use onet_config::CONFIG;
use onet_records::{collators::CollatorRecord, EpochIndex};
use redis::aio::MultiplexedConnection as Connection;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Params {
    // parachain of the collators, `ah` or `pp` (people), default `ah`
    #[serde(default = "default_chain")]
    chain_key: ChainKey,
    // parachain session, default current
    #[serde(default = "default_index")]
    session: Index,
    // show_stats indicates wheter produced blocks and missed slots should be retrieved or not, default false
    #[serde(default)]
    show_stats: bool,
}

fn default_chain() -> ChainKey {
    ChainKey::AH
}

fn default_index() -> Index {
    Index::Current
}

/// Get the collators of a parachain session
pub async fn get_collators(
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<CollatorsResult>, ApiError> {
    if params.chain_key == ChainKey::RC {
        let msg = "Parameter chain_key must be equal to one of the options: [ah, pp]".to_string();
        warn!("{}", msg);
        return Err(ApiError::BadRequest(msg));
    }

    let mut conn = get_conn(&cache).await?;

    let session_index: EpochIndex = match &params.session {
        Index::Num(index) => *index as EpochIndex,
        Index::Str(index) if index != "current" => index.parse::<EpochIndex>().unwrap_or_default(),
        _ => redis::cmd("GET")
            .arg(CacheKey::CollatorCurrentSession(params.chain_key.clone()))
            .query_async::<Option<EpochIndex>>(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?
            .unwrap_or_default(),
    };

    let record_keys: Vec<String> = redis::cmd("SMEMBERS")
        .arg(CacheKey::CollatorKeysBySession(
            params.chain_key.clone(),
            session_index,
        ))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    let mut data: Vec<CollatorRecord> = Vec::new();
    for key in record_keys {
        let serialized: Option<String> = redis::cmd("HGET")
            .arg(&key)
            .arg("record")
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;
        match serialized.map(|s| serde_json::from_str::<CollatorRecord>(&s)) {
            Some(Ok(record)) => data.push(record),
            Some(Err(e)) => warn!("Collator record {key} could not be read: {e}"),
            None => {}
        }
    }

    let config = CONFIG.clone();
    let para_id = match params.chain_key {
        ChainKey::PEOPLE => config.people_para_id,
        _ => config.asset_hub_para_id,
    };

    respond_json(CollatorsResult::new(
        params.chain_key.to_string(),
        para_id,
        session_index,
        data,
        params.show_stats,
    ))
}
