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

use super::limits::build_limits_from_session;
use super::types::{CacheKey, ChainKey, Index, Trait, Verbosity};
use log::info;
use onet_config::{Config, CONFIG};
use onet_errors::{CacheError, OnetError};
use onet_pools::{PoolId, PoolStats};
use onet_records::{
    AuthorityIndex, AuthorityRecord, BlockNumber, EpochIndex, EraIndex, NetworkSessionStats,
    ParaId, ParaRecord, ParaStats, ParachainRecord, Records, SessionStats, ValidatorProfileRecord,
};
use onet_report::Network;
use redis::aio::Connection;
use std::{collections::BTreeMap, result::Result, time::Instant};
use subxt::utils::AccountId32;

// Cache records at every block
pub async fn cache_records(cache: &mut Connection, records: &Records) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if !config.cache_writer_enabled {
        return Ok(());
    }

    let Some(current_block) = records.current_block() else {
        return Ok(());
    };

    let mut session_stats = SessionStats::default();
    let mut parachains: BTreeMap<ParaId, ParachainRecord> = BTreeMap::new();

    let current_epoch = records.current_epoch();

    // Process authority records and collect statistics
    process_authority_records(cache, &config, records, &mut session_stats, &mut parachains).await?;

    // Cache session statistics
    cache_session_stats(cache, &config, current_epoch, current_block, &session_stats).await?;

    // Cache parachain statistics
    cache_parachain_stats(cache, &config, current_epoch, &parachains).await?;

    // Cache current block
    cache_current_block(cache, &config, records, current_block).await?;

    Ok(())
}

async fn process_authority_records(
    cache: &mut Connection,
    config: &Config,
    records: &Records,
    session_stats: &mut SessionStats,
    parachains: &mut BTreeMap<ParaId, ParachainRecord>,
) -> Result<(), OnetError> {
    let Some(authorities) = records.get_authorities(None) else {
        return Ok(());
    };

    for authority_idx in authorities {
        process_authority(
            cache,
            config,
            records,
            session_stats,
            parachains,
            authority_idx,
        )
        .await?;
    }

    Ok(())
}

async fn process_authority(
    cache: &mut Connection,
    config: &Config,
    records: &Records,
    session_stats: &mut SessionStats,
    parachains: &mut BTreeMap<ParaId, ParachainRecord>,
    authority_idx: AuthorityIndex,
) -> Result<(), OnetError> {
    let Some(authority_record) = records.get_authority_record(authority_idx, None) else {
        return Ok(());
    };

    let _ = update_session_stats_with_authority_record_data(session_stats, &authority_record);

    // TODO: deprecate records.current_era() from CacheKey::AuthorityRecord
    let authority_key = CacheKey::AuthorityRecord(
        records.current_era(),
        records.current_epoch(),
        authority_idx,
    );

    let mut data = BTreeMap::new();
    data.insert(
        "auth".to_string(),
        serde_json::to_string(&authority_record)?,
    );

    if let Some(para_record) = records.get_para_record(authority_idx, None) {
        let _ = update_session_stats_with_para_record_data(session_stats, para_record);
        cache_para_stats_data(cache, config, &authority_key, &para_record).await?;
        cache_para_summary_data(cache, config, &authority_key, &para_record).await?;
        let _ = update_parachains_with_para_record_data(parachains, &para_record, authority_idx);

        data.insert("para".to_string(), serde_json::to_string(&para_record)?);
    }

    cache_authority_data(cache, config, &authority_key, &data).await?;

    Ok(())
}

fn update_session_stats_with_authority_record_data(
    stats: &mut SessionStats,
    authority_record: &AuthorityRecord,
) {
    stats.authorities += 1;
    stats.points += authority_record.points();
    stats.authored_blocks += authority_record.total_authored_blocks();
}

fn update_session_stats_with_para_record_data(stats: &mut SessionStats, para_record: &ParaRecord) {
    // aggregate para_authority session_stats counters
    stats.para_authorities += 1;
    stats.core_assignments += para_record.total_core_assignments();
    stats.explicit_votes += para_record.total_explicit_votes();
    stats.implicit_votes += para_record.total_implicit_votes();
    stats.missed_votes += para_record.total_missed_votes();
    stats.disputes += para_record.total_disputes();
    // bitfields availability
    stats.bitfields_availability += para_record.total_availability();
    stats.bitfields_unavailability += para_record.total_unavailability();
}

fn update_parachains_with_para_record_data(
    parachains: &mut BTreeMap<ParaId, ParachainRecord>,
    para_record: &ParaRecord,
    authority_idx: AuthorityIndex,
) -> Result<(), OnetError> {
    // aggregate parachains counters
    for (para_id, stats) in para_record.para_stats().iter() {
        let pm = parachains
            .entry(*para_id)
            .or_insert(ParachainRecord::default());
        pm.stats.implicit_votes += stats.implicit_votes();
        pm.stats.explicit_votes += stats.explicit_votes();
        pm.stats.missed_votes += stats.missed_votes();
        pm.stats.authored_blocks += stats.authored_blocks();
        pm.stats.points += stats.points();
        // NOTE: parachain core_assignments is related to the val_group
        // to calculate the core_assignments, just take into consideration that each authority in the val_group
        // has 1 core_assignment which means that 5 validators ca in the same group represent 1 core_assignment for the parachain.
        // The total of core_assignments will be given in cents meaning 100 = 1
        let ca: u32 = (100 / (para_record.peers().len() + 1)) as u32 * stats.core_assignments();
        pm.stats.core_assignments += ca;
        pm.para_id = *para_id;
    }

    if let Some(para_id) = para_record.para_id() {
        let pm = parachains
            .entry(para_id)
            .or_insert(ParachainRecord::default());
        pm.current_group = para_record.group();
        let mut authorities: Vec<AuthorityIndex> = vec![authority_idx];
        authorities.append(&mut para_record.peers());
        pm.current_authorities = authorities;
    }

    Ok(())
}

async fn cache_para_stats_data(
    cache: &mut Connection,
    config: &Config,
    authority_key: &CacheKey,
    para_record: &ParaRecord,
) -> Result<(), OnetError> {
    // cache para.stats as a different cache key
    let serialized = serde_json::to_string(&para_record.para_stats())?;
    redis::pipe()
        .atomic()
        .cmd("HSET")
        .arg(CacheKey::AuthorityRecordVerbose(
            authority_key.to_string(),
            Verbosity::Stats,
        ))
        .arg(String::from("para_stats"))
        .arg(serialized)
        .cmd("EXPIRE")
        .arg(CacheKey::AuthorityRecordVerbose(
            authority_key.to_string(),
            Verbosity::Stats,
        ))
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

async fn cache_para_summary_data(
    cache: &mut Connection,
    config: &Config,
    authority_key: &CacheKey,
    para_record: &ParaRecord,
) -> Result<(), OnetError> {
    // cache para.summary as a different cache key
    let summary = ParaStats {
        points: para_record.total_points(),
        authored_blocks: para_record.total_authored_blocks(),
        core_assignments: para_record.total_core_assignments(),
        explicit_votes: para_record.total_explicit_votes(),
        implicit_votes: para_record.total_implicit_votes(),
        missed_votes: para_record.total_missed_votes(),
    };
    let serialized = serde_json::to_string(&summary)?;
    redis::pipe()
        .atomic()
        .cmd("HSET")
        .arg(CacheKey::AuthorityRecordVerbose(
            authority_key.to_string(),
            Verbosity::Summary,
        ))
        .arg(String::from("para_summary"))
        .arg(serialized)
        .cmd("EXPIRE")
        .arg(CacheKey::AuthorityRecordVerbose(
            authority_key.to_string(),
            Verbosity::Summary,
        ))
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

async fn cache_current_block(
    cache: &mut Connection,
    config: &Config,
    records: &Records,
    current_block: &BlockNumber,
) -> Result<(), OnetError> {
    let Some(start_block) = records.start_block(None) else {
        return Ok(());
    };

    if current_block == start_block {
        return Ok(());
    }

    let mut data: BTreeMap<String, String> = BTreeMap::new();
    data.insert(String::from("current_block"), (*current_block).to_string());
    // by `epoch_index`
    redis::pipe()
        .atomic()
        .cmd("HSET")
        .arg(CacheKey::SessionByIndex(Index::Num(
            records.current_epoch().into(),
        )))
        .arg(data)
        .cmd("EXPIRE")
        .arg(CacheKey::SessionByIndex(Index::Num(
            records.current_epoch().into(),
        )))
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

async fn cache_authority_data(
    cache: &mut Connection,
    config: &Config,
    authority_key: &CacheKey,
    authority_data: &BTreeMap<String, String>,
) -> Result<(), OnetError> {
    let data = authority_data.clone();
    redis::pipe()
        .atomic()
        .cmd("HSET")
        .arg(authority_key.to_string())
        .arg(data)
        .cmd("EXPIRE")
        .arg(authority_key.to_string())
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

async fn cache_session_stats(
    cache: &mut Connection,
    config: &Config,
    current_epoch: EpochIndex,
    current_block: &BlockNumber,
    session_stats: &SessionStats,
) -> Result<(), OnetError> {
    let serialized = serde_json::to_string(session_stats)?;
    redis::pipe()
        .atomic()
        // cache current_block / finalized block
        .cmd("SET")
        .arg(CacheKey::FinalizedBlock(ChainKey::RC))
        .arg(*current_block)
        // cache current_block / finalized block into a sorted set by session
        .cmd("ZADD")
        .arg(CacheKey::BlocksBySession(Index::Num(current_epoch.into())))
        .arg(0)
        .arg(*current_block)
        .cmd("EXPIRE")
        .arg(CacheKey::BlocksBySession(Index::Num(current_epoch.into())))
        .arg(config.cache_writer_prunning)
        // cache session_stats at every block
        .cmd("SET")
        .arg(CacheKey::BlockByIndexStats(Index::Num(*current_block)))
        .arg(serialized)
        .arg("EX")
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

async fn cache_parachain_stats(
    cache: &mut Connection,
    config: &Config,
    current_epoch: EpochIndex,
    parachains: &BTreeMap<ParaId, ParachainRecord>,
) -> Result<(), OnetError> {
    for (para_id, records) in parachains.iter() {
        let serialized = serde_json::to_string(&records)?;
        redis::pipe()
            .atomic()
            .cmd("HSET")
            .arg(CacheKey::ParachainsBySession(current_epoch))
            .arg(para_id.to_string())
            .arg(serialized)
            .cmd("EXPIRE")
            .arg(CacheKey::ParachainsBySession(current_epoch))
            .arg(config.cache_writer_prunning)
            .query_async::<_, ()>(cache)
            .await
            .map_err(CacheError::RedisCMDError)?;
    }

    Ok(())
}

// Cache records at every new session
pub async fn cache_records_at_session(
    cache: &mut Connection,
    records: &Records,
    start_session_index: EpochIndex,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if !config.cache_writer_enabled {
        return Ok(());
    }

    let start = Instant::now();

    // --- Cache SessionByIndex -> `current` or `epoch_index` (to be able to search history)
    cache_session_by_index(cache, &config, records, start_session_index).await?;

    process_authority_records_at_session(cache, &config, records).await?;

    // Log sesssion cache processed duration time
    info!(
        "Session #{} cached ({:?})",
        records.current_epoch(),
        start.elapsed()
    );

    Ok(())
}

async fn process_authority_records_at_session(
    cache: &mut Connection,
    config: &Config,
    records: &Records,
) -> Result<(), OnetError> {
    let Some(authorities) = records.get_authorities(None) else {
        return Ok(());
    };

    for authority_idx in authorities {
        process_authority_at_session(cache, config, records, authority_idx).await?;
    }

    Ok(())
}

async fn process_authority_at_session(
    cache: &mut Connection,
    config: &Config,
    records: &Records,
    authority_idx: AuthorityIndex,
) -> Result<(), OnetError> {
    let Some(authority_record) = records.get_authority_record(authority_idx, None) else {
        return Ok(());
    };

    let Some(stash) = authority_record.address() else {
        return Ok(());
    };

    // TODO: deprecate records.current_era() from CacheKey::AuthorityRecord
    let authority_key = CacheKey::AuthorityRecord(
        records.current_era(),
        records.current_epoch(),
        authority_idx,
    );

    cache_authority_stash(cache, config, &authority_key, stash).await?;
    cache_authority_key(
        cache,
        config,
        records.current_era(),
        records.current_epoch(),
        authority_idx,
        stash,
    )
    .await?;
    cache_authority_key_into_authorities(cache, config, records.current_epoch(), &authority_key)
        .await?;

    if records.get_para_record(authority_idx, None).is_some() {
        cache_para_authority_key_into_authorities(
            cache,
            config,
            records.current_epoch(),
            &authority_key,
        )
        .await?;
    }

    Ok(())
}

// cache authority stash account
async fn cache_authority_stash(
    cache: &mut Connection,
    config: &Config,
    authority_key: &CacheKey,
    stash: &AccountId32,
) -> Result<(), OnetError> {
    let mut data: BTreeMap<String, String> = BTreeMap::new();
    data.insert(String::from("address"), stash.to_string());
    redis::pipe()
        .atomic()
        .cmd("HSET")
        .arg(authority_key.to_string())
        .arg(data)
        .cmd("EXPIRE")
        .arg(authority_key.to_string())
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

// cache authority key by stash account
async fn cache_authority_key(
    cache: &mut Connection,
    config: &Config,
    current_era: EraIndex,
    current_epoch: EpochIndex,
    authority_idx: AuthorityIndex,
    stash: &AccountId32,
) -> Result<(), OnetError> {
    let mut data: BTreeMap<String, String> = BTreeMap::new();
    data.insert(String::from("era"), current_era.to_string());
    data.insert(String::from("session"), current_epoch.to_string());
    data.insert(String::from("authority"), authority_idx.to_string());
    redis::pipe()
        .atomic()
        .cmd("HSET")
        .arg(CacheKey::AuthorityKeyByAccountAndSession(
            stash.clone(),
            current_epoch,
        ))
        .arg(data)
        .cmd("EXPIRE")
        .arg(CacheKey::AuthorityKeyByAccountAndSession(
            stash.clone(),
            current_epoch,
        ))
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

// cache authority key into authorities by session to be easily filtered
async fn cache_authority_key_into_authorities(
    cache: &mut Connection,
    config: &Config,
    current_epoch: EpochIndex,
    authority_key: &CacheKey,
) -> Result<(), OnetError> {
    redis::pipe()
        .atomic()
        .cmd("SADD")
        .arg(CacheKey::AuthorityKeysBySession(current_epoch))
        .arg(authority_key.to_string())
        .cmd("EXPIRE")
        .arg(CacheKey::AuthorityKeysBySession(current_epoch))
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

// cache authority key into authorities by session (only para_validators) to be easily filtered
async fn cache_para_authority_key_into_authorities(
    cache: &mut Connection,
    config: &Config,
    current_epoch: EpochIndex,
    authority_key: &CacheKey,
) -> Result<(), OnetError> {
    redis::pipe()
        .atomic()
        .cmd("SADD")
        .arg(CacheKey::AuthorityKeysBySessionParaOnly(current_epoch))
        .arg(authority_key.to_string())
        .cmd("EXPIRE")
        .arg(CacheKey::AuthorityKeysBySessionParaOnly(current_epoch))
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

async fn cache_session_by_index(
    cache: &mut Connection,
    config: &Config,
    records: &Records,
    start_session_index: u32,
) -> Result<(), OnetError> {
    let Some(start_block) = records.start_block(None) else {
        return Ok(());
    };

    let Some(current_block) = records.current_block() else {
        return Ok(());
    };

    // era session index
    let current_epoch = records.current_epoch();
    let era_session_index = 1 + current_epoch - start_session_index;

    let mut data: BTreeMap<String, String> = BTreeMap::new();
    data.insert(String::from("era"), records.current_era().to_string());
    data.insert(String::from("session"), current_epoch.to_string());
    data.insert(String::from("start_block"), (*start_block).to_string());
    data.insert(String::from("current_block"), (*current_block).to_string());
    data.insert(
        String::from("era_session_index"),
        era_session_index.to_string(),
    );

    redis::pipe()
        .atomic()
        // by `epoch_index`
        .cmd("HSET")
        .arg(CacheKey::SessionByIndex(Index::Num(current_epoch.into())))
        .arg(data)
        .cmd("EXPIRE")
        .arg(CacheKey::SessionByIndex(Index::Num(current_epoch.into())))
        .arg(config.cache_writer_prunning)
        // by `current`
        .cmd("SET")
        .arg(CacheKey::SessionByIndex(Index::Str(String::from(
            "current",
        ))))
        .arg(current_epoch.to_string())
        //NOTE: make session_stats available to previous session by copying stats from previous block
        .cmd("COPY")
        .arg(CacheKey::BlockByIndexStats(Index::Num(*current_block - 1)))
        .arg(CacheKey::SessionByIndexStats(Index::Num(
            (current_epoch - 1).into(),
        )))
        .cmd("EXPIRE")
        .arg(CacheKey::SessionByIndexStats(Index::Num(
            (current_epoch - 1).into(),
        )))
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

pub async fn cache_validator_profile(
    cache: &mut Connection,
    config: &Config,
    profile: &ValidatorProfileRecord,
    network: &Network,
    stash: &AccountId32,
    current_epoch: EpochIndex,
) -> Result<(), OnetError> {
    let serialized = serde_json::to_string(&profile)?;
    redis::pipe()
        .atomic()
        .cmd("SET")
        .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
        .arg(serialized)
        .cmd("EXPIRE")
        .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
        .arg(config.cache_writer_prunning)
        .cmd("SADD")
        .arg(CacheKey::ValidatorAccountsBySession(current_epoch))
        .arg(stash.to_string())
        .cmd("EXPIRE")
        .arg(CacheKey::ValidatorAccountsBySession(current_epoch))
        .arg(config.cache_writer_prunning)
        // cache own_stake rank
        .cmd("ZADD")
        .arg(CacheKey::NomiBoardBySessionAndTrait(
            current_epoch,
            Trait::OwnStake,
        ))
        .arg(
            profile
                .own_stake_trimmed(network.token_decimals as u32)
                .to_string(),
        ) // score
        .arg(stash.to_string())
        .cmd("EXPIRE")
        .arg(CacheKey::NomiBoardBySessionAndTrait(
            current_epoch,
            Trait::OwnStake,
        ))
        .arg(config.cache_writer_prunning)
        // cache nominators_stake rank
        .cmd("ZADD")
        .arg(CacheKey::NomiBoardBySessionAndTrait(
            current_epoch,
            Trait::NominatorsStake,
        ))
        .arg(
            profile
                .nominators_stake_trimmed(network.token_decimals as u32)
                .to_string(),
        ) // score
        .arg(stash.to_string())
        .cmd("EXPIRE")
        .arg(CacheKey::NomiBoardBySessionAndTrait(
            current_epoch,
            Trait::NominatorsStake,
        ))
        .arg(config.cache_writer_prunning)
        // cache nominators_counter rank
        .cmd("ZADD")
        .arg(CacheKey::NomiBoardBySessionAndTrait(
            current_epoch,
            Trait::NominatorsCounter,
        ))
        .arg(profile.nominators_counter.to_string()) // score
        .arg(stash.to_string())
        .cmd("EXPIRE")
        .arg(CacheKey::NomiBoardBySessionAndTrait(
            current_epoch,
            Trait::NominatorsCounter,
        ))
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

pub async fn cache_validator_profile_only(
    cache: &mut Connection,
    config: &Config,
    profile: &ValidatorProfileRecord,
    stash: &AccountId32,
) -> Result<(), OnetError> {
    let serialized = serde_json::to_string(&profile)?;
    redis::pipe()
        .atomic()
        .cmd("SET")
        .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
        .arg(serialized)
        .cmd("EXPIRE")
        .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

pub async fn cache_network_stats_at_session(
    cache: &mut Connection,
    config: &Config,
    stats: &NetworkSessionStats,
    current_epoch: EpochIndex,
) -> Result<(), OnetError> {
    let serialized = serde_json::to_string(&stats)?;
    redis::pipe()
        .atomic()
        .cmd("SET")
        .arg(CacheKey::NetworkStatsBySession(Index::Num(
            current_epoch.into(),
        )))
        .arg(serialized)
        .cmd("EXPIRE")
        .arg(CacheKey::NetworkStatsBySession(Index::Num(
            current_epoch.into(),
        )))
        .arg(config.cache_writer_prunning)
        .query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}

pub async fn cache_board_limits_at_session(
    cache: &mut Connection,
    config: &Config,
    rc_block_number: BlockNumber,
    current_era: EraIndex,
    current_epoch: EpochIndex,
) -> Result<(), OnetError> {
    // Set synced session associated with era (useful for nomi boards)
    let mut era_data: BTreeMap<String, String> = BTreeMap::new();
    era_data.insert(String::from("synced_session"), current_epoch.to_string());
    era_data.insert(
        String::from(format!("synced_at_block:{}", current_epoch)),
        rc_block_number.to_string(),
    );

    // Build session limits
    let limits = build_limits_from_session(cache, current_epoch).await?;
    let limits_serialized = serde_json::to_string(&limits)?;

    // Set era and limits associated with session (useful for nomi boards)
    let mut session_data: BTreeMap<String, String> = BTreeMap::new();
    session_data.insert(String::from("era"), current_era.to_string());
    session_data.insert(String::from("limits"), limits_serialized.to_string());

    // by `current_epoch`
    redis::pipe()
        .atomic()
        .cmd("HSET")
        .arg(CacheKey::EraByIndex(Index::Num(current_era.into())))
        .arg(era_data)
        .cmd("EXPIRE")
        .arg(CacheKey::EraByIndex(Index::Num(current_era.into())))
        .arg(config.cache_writer_prunning)
        .cmd("HSET")
        .arg(CacheKey::NomiBoardEraBySession(current_epoch))
        .arg(session_data)
        .cmd("EXPIRE")
        .arg(CacheKey::NomiBoardEraBySession(current_epoch))
        .arg(config.cache_writer_prunning)
        .cmd("SET")
        .arg(CacheKey::EraByIndex(Index::Current))
        .arg(current_era.to_string())
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
