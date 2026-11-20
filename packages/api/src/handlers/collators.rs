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
use crate::{
    helpers::respond_json,
    responses::{CollatorsResult, ValidatorResult},
};
use actix_web::web::{Data, Json, Query};
use log::warn;
use onet_cache::{
    error::CacheError,
    provider::{get_conn, RedisPool},
    types::{CacheKey, ChainKey, Index},
};
use onet_config::CONFIG;
use onet_records::{
    collators::{CollatorKind, CollatorRecord, CollatorSessionStats, LiveSlot},
    EpochIndex, ParaId,
};
use redis::aio::MultiplexedConnection as Connection;
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Params {
    // parachain of the collators, `ah` or `pp` (people), default `ah`
    #[serde(default = "default_chain")]
    chain_key: ChainKey,
    // parachain session, default current
    #[serde(default = "default_index")]
    session: Index,
    // stats indicates whether the session stats should be retrieved or not, default false
    // Note: `show_stats` is deprecated, use `stats`
    #[serde(default, alias = "show_stats")]
    stats: bool,
    // block_numbers indicates whether the produced block numbers (pbn) of each collator should be retrieved or not, default false
    // Note: `show_block_numbers` is deprecated, use `block_numbers`
    #[serde(default, alias = "show_block_numbers")]
    block_numbers: bool,
    // missed_slots indicates whether the missed slots (msl) of each collator should be retrieved or not, default false
    // Note: `show_missed_slots` is deprecated, use `missed_slots`
    #[serde(default, alias = "show_missed_slots")]
    missed_slots: bool,
    // slot indicates whether the slot the parachain is in right now should be retrieved or not, default false
    // Note: only available for the current session
    #[serde(default)]
    slot: bool,
    // kind of the collators to retrieve: `i` invulnerable, `p` permissionless, `v` validator or `u` unknown,
    // default all. Note: `kind_counter` always counts all collators
    #[serde(default)]
    kind: Option<CollatorKind>,
    // kind_counter indicates whether the number of collators by kind should be retrieved or not, default false
    #[serde(default)]
    kind_counter: bool,
    // kind_counter_only is the same as `kind_counter` but the collators (`data`) are not retrieved, default false
    #[serde(default)]
    kind_counter_only: bool,
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
    let mut result = get_collators_result(
        &mut conn as &mut Connection,
        &params.chain_key,
        &params.session,
        params.stats,
        params.block_numbers,
        params.missed_slots,
        params.slot,
    )
    .await?;

    if params.kind_counter || params.kind_counter_only {
        result.set_kind_counter(params.kind_counter_only);
    }
    if let Some(kind) = params.kind {
        result.retain_kind(kind);
    }

    respond_json(result)
}

/// Get the collators of a parachain session, the current one if `session` is current
pub async fn get_collators_result(
    conn: &mut Connection,
    chain_key: &ChainKey,
    session: &Index,
    show_stats: bool,
    show_block_numbers: bool,
    show_missed_slots: bool,
    show_slot: bool,
) -> Result<CollatorsResult, ApiError> {
    let current_session: Option<EpochIndex> = redis::cmd("GET")
        .arg(CacheKey::CollatorCurrentSession(chain_key.clone()))
        .query_async::<Option<EpochIndex>>(&mut *conn)
        .await
        .map_err(CacheError::RedisCMDError)?;

    let session_index: EpochIndex = match session {
        Index::Num(index) => *index as EpochIndex,
        Index::Str(index) if index != "current" => index.parse::<EpochIndex>().unwrap_or_default(),
        _ => current_session.unwrap_or_default(),
    };

    let record_keys: Vec<String> = redis::cmd("SMEMBERS")
        .arg(CacheKey::CollatorKeysBySession(
            chain_key.clone(),
            session_index,
        ))
        .query_async(&mut *conn)
        .await
        .map_err(CacheError::RedisCMDError)?;

    let mut data: Vec<CollatorRecord> = Vec::new();
    for key in record_keys {
        let serialized: Option<String> = redis::cmd("HGET")
            .arg(&key)
            .arg("record")
            .query_async(&mut *conn)
            .await
            .map_err(CacheError::RedisCMDError)?;
        match serialized.map(|s| serde_json::from_str::<CollatorRecord>(&s)) {
            Some(Ok(record)) => data.push(record),
            Some(Err(e)) => warn!("Collator record {key} could not be read: {e}"),
            None => {}
        }
    }

    let config = CONFIG.clone();
    let para_id = match chain_key {
        ChainKey::PEOPLE => config.people_para_id,
        _ => config.asset_hub_para_id,
    };

    // Note: session stats are only retrieved when requested
    let stats: CollatorSessionStats = if show_stats {
        redis::cmd("GET")
            .arg(CacheKey::CollatorStatsBySession(
                chain_key.clone(),
                session_index,
            ))
            .query_async::<Option<String>>(&mut *conn)
            .await
            .map_err(CacheError::RedisCMDError)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        CollatorSessionStats::default()
    };

    let mut result = CollatorsResult::new(
        chain_key.to_string(),
        para_id,
        session_index,
        stats,
        data,
        show_block_numbers,
        show_missed_slots,
    );

    // Note: the slot the parachain is in only makes sense for its current session
    if show_slot && current_session == Some(session_index) {
        result.slot = redis::cmd("GET")
            .arg(CacheKey::CollatorLiveSlot(chain_key.clone()))
            .query_async::<Option<String>>(&mut *conn)
            .await
            .map_err(CacheError::RedisCMDError)?
            .and_then(|s| serde_json::from_str(&s).ok());
    }

    Ok(result)
}

/// Slot a parachain is in right now.
pub async fn get_live_slot(
    conn: &mut Connection,
    chain_key: &ChainKey,
) -> Result<Option<LiveSlot>, ApiError> {
    Ok(redis::cmd("GET")
        .arg(CacheKey::CollatorLiveSlot(chain_key.clone()))
        .query_async::<Option<String>>(&mut *conn)
        .await
        .map_err(CacheError::RedisCMDError)?
        .and_then(|s| serde_json::from_str::<LiveSlot>(&s).ok()))
}

/// Slot each parachain is in right now, by parachain id.
/// Note: the slot a parachain is in changes with every block, so it is not cached with the stats
pub async fn get_live_slots(conn: &mut Connection) -> Result<BTreeMap<ParaId, LiveSlot>, ApiError> {
    let config = CONFIG.clone();
    let mut live: BTreeMap<ParaId, LiveSlot> = BTreeMap::new();
    for (chain_key, para_id) in [
        (ChainKey::AH, config.asset_hub_para_id),
        (ChainKey::PEOPLE, config.people_para_id),
    ] {
        let slot = redis::cmd("GET")
            .arg(CacheKey::CollatorLiveSlot(chain_key))
            .query_async::<Option<String>>(&mut *conn)
            .await
            .map_err(CacheError::RedisCMDError)?
            .and_then(|s| serde_json::from_str::<LiveSlot>(&s).ok());
        if let Some(slot) = slot {
            live.insert(para_id, slot);
        }
    }
    Ok(live)
}

/// Set the slot and the blocks produced so far on the validators that are collating right now.
pub async fn attach_collation_live(
    conn: &mut Connection,
    validators: &mut [ValidatorResult],
) -> Result<(), ApiError> {
    if validators.iter().all(|v| v.collation.is_empty()) {
        return Ok(());
    }
    let live = get_live_slots(conn).await?;
    for validator in validators.iter_mut() {
        for entry in validator.collation.iter_mut() {
            if let Some(slot) = live.get(&entry.para_id) {
                entry.set_live(slot);
            }
        }
    }
    Ok(())
}
