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

//! Cache of the collator records (missed slot ratio) of the parachains.
//!
//! Records are cached by parachain session and by relay chain session. The cursor
//! (`CacheKey::CollatorLastBlock`) is the last parachain block counted and is written
//! atomically with the records so both always agree.

use crate::error::CacheError;
use crate::types::{CacheKey, ChainKey, Verbosity};
use log::{info, warn};
use onet_config::{Config, CONFIG};
use onet_records::{
    collators::{CollationIndex, CollatorRecord, CollatorSessionStats, CollatorSummary},
    AuthorityIndex, BlockNumber, EpochIndex, ParaId, Records,
};
use redis::aio::MultiplexedConnection as Connection;
use std::{
    collections::{BTreeMap, BTreeSet},
    result::Result,
    str::FromStr,
};
use subxt::utils::AccountId32;

const RECORD_FIELD: &str = "record";
// field of the authority data with the collation index by parachain
const COLLATION_FIELD: &str = "collation";

/// Cache the collator records changed since the last call and the draw of validators as collators
pub async fn cache_collator_records(
    cache: &mut Connection,
    chain_key: ChainKey,
    para_id: ParaId,
    records: &mut Records,
) -> Result<(), CacheError> {
    let config = CONFIG.clone();
    if !config.cache_writer_enabled {
        return Ok(());
    }

    cache_collator_live_slot(cache, chain_key.clone(), para_id, records).await?;
    // Note: the draw does not depend on closed slots, so it is cached even if there are no records
    cache_collator_draw(cache, para_id, records).await?;

    let dirty = records.dirty_collators(para_id);
    if dirty.is_empty() {
        return Ok(());
    }
    let Some(last_block) = records.para_slots(para_id).and_then(|t| t.last_block()) else {
        return Ok(());
    };
    let Some(current_session) = records.para_slots(para_id).and_then(|t| t.session()) else {
        return Ok(());
    };

    let mut pipe = redis::pipe();
    pipe.atomic();
    for (session, epoch, address) in dirty.iter() {
        let Ok(account) = AccountId32::from_str(address) else {
            warn!("Collator address {address} could not be parsed, skipping cache");
            continue;
        };
        if let Some(record) = records.get_collator_record(para_id, *session, address) {
            let key = CacheKey::CollatorRecord(chain_key.clone(), *session, account);
            add_record(
                &mut pipe,
                &config,
                &key,
                &CacheKey::CollatorKeysBySession(chain_key.clone(), *session),
                record,
            )?;
        }
        if let Some(record) = records.get_collator_epoch_record(para_id, *epoch, address) {
            let key = CacheKey::CollatorEpochRecord(chain_key.clone(), *epoch, account);
            add_record(
                &mut pipe,
                &config,
                &key,
                &CacheKey::CollatorKeysByEpoch(chain_key.clone(), *epoch),
                record,
            )?;
        }
    }
    // Note: stats are recomputed from all the records of the session
    let sessions: BTreeSet<EpochIndex> = dirty.iter().map(|(session, _, _)| *session).collect();
    for session in sessions {
        let key = CacheKey::CollatorStatsBySession(chain_key.clone(), session);
        pipe.cmd("SET")
            .arg(&key)
            .arg(serde_json::to_string(
                &records.collator_session_stats(para_id, session),
            )?)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(config.cache_writer_prunning);
    }
    // Note: one field by parachain, so they are written independently
    let epochs: BTreeSet<EpochIndex> = dirty.iter().map(|(_, epoch, _)| *epoch).collect();
    for epoch in epochs {
        let key = CacheKey::CollatorStatsByEpoch(epoch);
        pipe.cmd("HSET")
            .arg(&key)
            .arg(para_id.to_string())
            .arg(serde_json::to_string(
                &records.collator_epoch_stats(para_id, epoch),
            )?)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(config.cache_writer_prunning);
    }
    // Note: the cursor and the current session are written with the records
    pipe.cmd("SET")
        .arg(CacheKey::CollatorCurrentSession(chain_key.clone()))
        .arg(current_session.to_string())
        .cmd("EXPIRE")
        .arg(CacheKey::CollatorCurrentSession(chain_key.clone()))
        .arg(config.cache_writer_prunning)
        .cmd("SET")
        .arg(CacheKey::CollatorLastBlock(chain_key.clone()))
        .arg(last_block.to_string())
        .cmd("EXPIRE")
        .arg(CacheKey::CollatorLastBlock(chain_key.clone()))
        .arg(config.cache_writer_prunning)
        .query_async::<()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    // Note: records are marked as cached only after being successfully written
    records.clear_dirty_collators(para_id);

    // Cache the relay chain session summary alongside the authority
    for (_, epoch, address) in dirty.iter() {
        if *epoch != records.current_epoch() {
            continue;
        }
        let (Some(authority_idx), Some(record)) = (
            records.get_authority_index_by_address(address, *epoch),
            records.get_collator_epoch_record(para_id, *epoch, address),
        ) else {
            continue;
        };
        // Note: collators that did not own any slot yet have nothing to add to the authority
        if record.owned_slots() == 0 {
            continue;
        }
        let authority_key = CacheKey::AuthorityRecord(records.current_era(), *epoch, authority_idx);
        cache_authority_collator_data(cache, &config, &authority_key, para_id, record).await?;
    }

    Ok(())
}

/// Seconds the slot a parachain is in is kept, it is written with every block
const LIVE_SLOT_EXPIRE: u64 = 60;

/// Cache the slot a parachain is currently in, to tell which validator is collating right now
async fn cache_collator_live_slot(
    cache: &mut Connection,
    chain_key: ChainKey,
    para_id: ParaId,
    records: &Records,
) -> Result<(), CacheError> {
    let Some(live) = records.para_slots(para_id).and_then(|t| t.live_slot()) else {
        return Ok(());
    };
    let key = CacheKey::CollatorLiveSlot(chain_key);
    redis::cmd("SET")
        .arg(&key)
        .arg(serde_json::to_string(&live)?)
        .arg("EX")
        .arg(LIVE_SLOT_EXPIRE)
        .query_async::<()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;
    Ok(())
}

/// Cache the position of the validators drawn as collators of a parachain in the main authority
/// data of the current relay session, so it is known before they own any slot.
/// Note: it is only written when the parachain session or the relay session change
async fn cache_collator_draw(
    cache: &mut Connection,
    para_id: ParaId,
    records: &mut Records,
) -> Result<(), CacheError> {
    let config = CONFIG.clone();
    if !config.cache_writer_enabled {
        return Ok(());
    }
    let Some(session) = records.para_slots(para_id).and_then(|t| t.session()) else {
        return Ok(());
    };
    let epoch = records.current_epoch();
    // Note: the draw only changes with the parachain session, and it is written into the
    // authorities of the relay session, so there is nothing to do until one of them changes.
    // This is checked first since finding the authorities of hundreds of collators is not free.
    let cached = records.cached_collator_draw(para_id);
    if cached.is_some_and(|(cached_session, cached_epoch, _)| {
        *cached_session == session && *cached_epoch == epoch
    }) {
        return Ok(());
    }
    // Note: wait for the authorities of the relay session, otherwise nobody would be found
    if !records.has_authorities() {
        return Ok(());
    }
    let draw = records.collator_draw(para_id);
    let authorities: BTreeSet<AuthorityIndex> = draw.iter().map(|(index, _)| *index).collect();

    // Note: validators that left the draw in the same relay session have to be removed
    let left: BTreeSet<AuthorityIndex> = match cached {
        Some((_, cached_epoch, cached)) if *cached_epoch == epoch => {
            cached.difference(&authorities).copied().collect()
        }
        _ => BTreeSet::new(),
    };

    for (authority_index, cix) in draw.iter() {
        set_authority_collation(
            cache,
            &config,
            records,
            *authority_index,
            para_id,
            Some(*cix),
        )
        .await?;
    }
    for authority_index in left {
        set_authority_collation(cache, &config, records, authority_index, para_id, None).await?;
    }

    records.set_cached_collator_draw(para_id, session, epoch, authorities);
    Ok(())
}

/// Set, or remove with `None`, the collation index of a parachain in the authority data.
/// Note: the field holds one entry per parachain, so the current ones are read and merged
async fn set_authority_collation(
    cache: &mut Connection,
    config: &Config,
    records: &Records,
    authority_index: AuthorityIndex,
    para_id: ParaId,
    cix: Option<u32>,
) -> Result<(), CacheError> {
    let key = CacheKey::AuthorityRecord(
        records.current_era(),
        records.current_epoch(),
        authority_index,
    );
    let mut list: Vec<CollationIndex> = redis::cmd("HGET")
        .arg(&key)
        .arg(COLLATION_FIELD)
        .query_async::<Option<String>>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    CollationIndex::set(&mut list, para_id, cix);

    let mut pipe = redis::pipe();
    pipe.atomic();
    if list.is_empty() {
        pipe.cmd("HDEL").arg(&key).arg(COLLATION_FIELD);
    } else {
        pipe.cmd("HSET")
            .arg(&key)
            .arg(COLLATION_FIELD)
            .arg(serde_json::to_string(&list)?)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(config.cache_writer_prunning);
    }
    pipe.query_async::<()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;
    Ok(())
}

fn add_record(
    pipe: &mut redis::Pipeline,
    config: &Config,
    key: &CacheKey,
    keys: &CacheKey,
    record: &CollatorRecord,
) -> Result<(), CacheError> {
    pipe.cmd("HSET")
        .arg(key)
        .arg(RECORD_FIELD)
        .arg(serde_json::to_string(record)?)
        .cmd("EXPIRE")
        .arg(key)
        .arg(config.cache_writer_prunning)
        .cmd("SADD")
        .arg(keys)
        .arg(key.to_string())
        .cmd("EXPIRE")
        .arg(keys)
        .arg(config.cache_writer_prunning);
    Ok(())
}

/// Add the collation of a parachain to the authority summary (all parachains) and stats
/// (by parachain). Note: stats hold one entry per parachain, so the current ones are read and merged
async fn cache_authority_collator_data(
    cache: &mut Connection,
    config: &Config,
    authority_key: &CacheKey,
    para_id: ParaId,
    record: &CollatorRecord,
) -> Result<(), CacheError> {
    let summary_key =
        CacheKey::AuthorityRecordVerbose(authority_key.to_string(), Verbosity::Summary);
    let stats_key = CacheKey::AuthorityRecordVerbose(authority_key.to_string(), Verbosity::Stats);

    // Note: collation stats are by parachain and the summary aggregates all of them,
    // collators in the authority data are always validators, so kind is omitted
    let mut stats: BTreeMap<ParaId, CollatorSummary> =
        read_map(cache, &stats_key, "collation_stats").await?;
    stats.insert(para_id, record.summary_without_kind());
    let mut summary = CollatorSummary::default();
    for para_stats in stats.values() {
        summary.add(para_stats);
    }

    redis::pipe()
        .atomic()
        .cmd("HSET")
        .arg(&summary_key)
        .arg("collation_summary")
        .arg(serde_json::to_string(&summary)?)
        .cmd("EXPIRE")
        .arg(&summary_key)
        .arg(config.cache_writer_prunning)
        .cmd("HSET")
        .arg(&stats_key)
        .arg("collation_stats")
        .arg(serde_json::to_string(&stats)?)
        .cmd("EXPIRE")
        .arg(&stats_key)
        .arg(config.cache_writer_prunning)
        .query_async::<()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

async fn read_map<K: Ord + serde::de::DeserializeOwned, T: serde::de::DeserializeOwned>(
    cache: &mut Connection,
    key: &CacheKey,
    field: &str,
) -> Result<BTreeMap<K, T>, CacheError> {
    let serialized: Option<String> = redis::cmd("HGET")
        .arg(key)
        .arg(field)
        .query_async(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;
    Ok(serialized
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default())
}

/// Load the cached collator records of the current sessions and the cursor into the records.
/// Note: records and cursor are only loaded together, the cursor alone would skip blocks
/// that were never counted.
pub async fn rehydrate_collator_records(
    cache: &mut Connection,
    chain_key: ChainKey,
    para_id: ParaId,
    records: &mut Records,
) -> Result<(), CacheError> {
    let config = CONFIG.clone();
    if !config.cache_writer_enabled {
        return Ok(());
    }

    let last_block: Option<BlockNumber> =
        get_parsed(cache, &CacheKey::CollatorLastBlock(chain_key.clone())).await?;
    let session: Option<EpochIndex> =
        get_parsed(cache, &CacheKey::CollatorCurrentSession(chain_key.clone())).await?;
    let (Some(last_block), Some(session)) = (last_block, session) else {
        return Ok(());
    };

    let epoch = records.current_epoch();
    let mut loaded = 0;
    for record in read_records(
        cache,
        &CacheKey::CollatorKeysBySession(chain_key.clone(), session),
    )
    .await?
    {
        records.insert_collator_record(para_id, session, record);
        loaded += 1;
    }
    for record in read_records(
        cache,
        &CacheKey::CollatorKeysByEpoch(chain_key.clone(), epoch),
    )
    .await?
    {
        records.insert_collator_epoch_record(para_id, epoch, record);
        loaded += 1;
    }
    // Resume the block ranges so the start of the sessions is not lost
    let session_stats: Option<CollatorSessionStats> = redis::cmd("GET")
        .arg(CacheKey::CollatorStatsBySession(chain_key.clone(), session))
        .query_async::<Option<String>>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?
        .and_then(|s| serde_json::from_str(&s).ok());
    if let Some(stats) = session_stats.filter(|s| s.sbix > 0) {
        records.seed_para_session_blocks(para_id, session, stats.sbix, stats.ebix);
    }
    let epoch_stats: Option<CollatorSessionStats> = redis::cmd("HGET")
        .arg(CacheKey::CollatorStatsByEpoch(epoch))
        .arg(para_id.to_string())
        .query_async::<Option<String>>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?
        .and_then(|s| serde_json::from_str(&s).ok());
    if let Some(stats) = epoch_stats.filter(|s| s.sbix > 0) {
        records.seed_para_epoch_blocks(para_id, epoch, stats.sbix, stats.ebix);
    }
    records.para_slots_mut(para_id).set_last_block(last_block);

    info!(
        "{} Block #{last_block} resumed with {loaded} collator records (session {session}, relay session {epoch})", chain_key.to_string().to_uppercase()
    );
    Ok(())
}

async fn get_parsed<T: FromStr>(
    cache: &mut Connection,
    key: &CacheKey,
) -> Result<Option<T>, CacheError> {
    let value: Option<String> = redis::cmd("GET")
        .arg(key)
        .query_async(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;
    Ok(value.and_then(|v| v.parse().ok()))
}

async fn read_records(
    cache: &mut Connection,
    keys: &CacheKey,
) -> Result<Vec<CollatorRecord>, CacheError> {
    let record_keys: Vec<String> = redis::cmd("SMEMBERS")
        .arg(keys)
        .query_async(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;
    let mut records = Vec::new();
    for key in record_keys {
        let serialized: Option<String> = redis::cmd("HGET")
            .arg(&key)
            .arg(RECORD_FIELD)
            .query_async(cache)
            .await
            .map_err(CacheError::RedisCMDError)?;
        match serialized.map(|s| serde_json::from_str::<CollatorRecord>(&s)) {
            Some(Ok(record)) => records.push(record),
            Some(Err(e)) => warn!("Collator record {key} could not be read: {e}"),
            None => {}
        }
    }
    Ok(records)
}
