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
use crate::cache::{CacheKey, Index, Trait, Verbosity};
use crate::config::CONFIG;
use crate::errors::{CacheError, OnetError};
use crate::matrix::FileInfo;
use crate::mcda::criterias::build_limits_from_session;
use crate::onet::{
    get_account_id_from_storage_key, get_latest_block_number_processed, get_signer_from_seed,
    get_subscribers, get_subscribers_by_epoch, try_fetch_stashes_from_remote_url,
    write_latest_block_number_processed, Onet, ReportType, EPOCH_FILENAME,
};
use crate::records::{
    AuthorityIndex, AuthorityRecord, BlockNumber, EpochIndex, EpochKey, EraIndex, Identity,
    NetworkSessionStats, ParaId, ParaRecord, ParaStats, ParachainRecord, Points, Records,
    SessionStats, Subscribers, SubsetStats, ValidatorProfileRecord,
};
use crate::report::{
    group_by_points, position, Callout, Metadata, Network, RawData, RawDataGroup, RawDataPara,
    RawDataParachains, RawDataRank, Report, Subset, Validator, Validators,
};
use crate::{
    pools,
    pools::{
        nomination_pool_account, Account, AccountType, ActiveNominee, Pool, PoolNominees,
        PoolStats, Roles,
    },
};
use async_recursion::async_recursion;
use log::{debug, error, info, warn};
use redis::aio::Connection;

use codec::Decode;
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    fs,
    iter::FromIterator,
    result::Result,
    thread, time,
    time::Instant,
};

use subxt::{
    config::{
        substrate::{Digest, DigestItem},
        Header,
    },
    events::Events,
    ext::sp_core::H256,
    utils::AccountId32,
};

use subxt_signer::sr25519::Keypair;

#[subxt::subxt(
    runtime_metadata_path = "metadata/kusama_metadata.scale",
    derive_for_all_types = "PartialEq, Clone"
)]
mod node_runtime {}

use node_runtime::{
    runtime_types::{
        bounded_collections::bounded_vec::BoundedVec, pallet_identity::types::Data,
        pallet_nomination_pools::PoolState, polkadot_parachain_primitives::primitives::Id,
        polkadot_primitives::v5::CoreOccupied, polkadot_primitives::v5::DisputeStatement,
        polkadot_primitives::v5::ValidatorIndex, polkadot_primitives::v5::ValidityAttestation,
        sp_arithmetic::per_things::Perbill, sp_consensus_babe::digests::PreDigest,
    },
    session::events::NewSession,
    // Event,
    system::events::ExtrinsicFailed,
};

type Call = node_runtime::runtime_types::staging_kusama_runtime::RuntimeCall;
type NominationPoolsCall = node_runtime::runtime_types::pallet_nomination_pools::pallet::Call;

pub async fn init_and_subscribe_on_chain_events(onet: &Onet) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let api = onet.client().clone();

    // Initialize from the first block of the session of last block processed
    let latest_block_number = get_latest_block_number_processed()?;
    let latest_block_hash = onet
        .rpc()
        .chain_get_block_hash(Some(latest_block_number.into()))
        .await?
        .unwrap();

    // Fetch ParaSession start block for the latest block processed
    let session_start_block_addr = node_runtime::storage()
        .para_scheduler()
        .session_start_block();
    let mut start_block_number = api
        .storage()
        .at(latest_block_hash)
        .fetch(&session_start_block_addr)
        .await?
        .unwrap();

    // Note: We want to start sync in the first block of a session.
    // For that we get the first block of a ParaSession and remove 1 block,
    // since ParaSession starts always at the the second block of a new session
    start_block_number -= 1;
    // Load into memory the minimum initial eras defined (default=0)

    start_block_number -= config.minimum_initial_eras * 6 * config.blocks_per_session;

    info!(
        "Start loading blocks since block number: {}",
        start_block_number
    );

    // get block hash from the start block
    let block_hash = onet
        .rpc()
        .chain_get_block_hash(Some(start_block_number.into()))
        .await?
        .unwrap();

    // Fetch active era index
    let active_era_addr = node_runtime::storage().staking().active_era();
    let era_index = match api.storage().at(block_hash).fetch(&active_era_addr).await? {
        Some(info) => info.index,
        None => return Err(format!("Active Era not found for block_hash: {block_hash}").into()),
    };

    // Cache Nomination pools
    // try_run_cache_pools_era(era_index, false).await?;

    // Fetch current session index
    let session_index_addr = node_runtime::storage().session().current_index();
    let session_index = match api
        .storage()
        .at(block_hash)
        .fetch(&session_index_addr)
        .await?
    {
        Some(session_index) => session_index,
        None => return Err(format!("Session Index not found for block_hash: {block_hash}").into()),
    };

    // Cache current epoch
    let epoch_filename = format!("{}{}", config.data_path, EPOCH_FILENAME);
    fs::write(&epoch_filename, session_index.to_string())?;

    // Subscribers
    let mut subscribers = Subscribers::with_era_and_epoch(era_index, session_index);
    // Initialized subscribers
    if let Ok(subs) = get_subscribers() {
        for (account, user_id, param) in subs.iter() {
            subscribers.subscribe(account.clone(), user_id.to_string(), param.clone());
        }
    }

    // Records
    let mut records =
        Records::with_era_epoch_and_block(era_index, session_index, start_block_number.into());

    // Initialize subscribers records
    initialize_records(&onet, &mut records, block_hash).await?;

    // Initialize cache
    cache_session_records(&records, block_hash).await?;
    cache_track_records(&onet, &records).await?;

    // Start indexing from the start_block_number
    let mut latest_block_number_processed: Option<u64> = Some(start_block_number.into());
    let mut is_loading = true;

    // Subscribe head
    // NOTE: the reason why we subscribe head and not finalized_head,
    // is just because head is in sync more frequently.
    // finalized_head can always be queried so as soon as it changes we process th repective block_hash
    let mut blocks_sub = api.blocks().subscribe_best().await?;
    while let Some(Ok(best_block)) = blocks_sub.next().await {
        debug!("block head {:?} received", best_block.number());
        // update records best_block number
        process_best_block(&onet, &mut records, best_block.number().into()).await?;

        // fetch latest finalized block
        let finalized_block_hash = onet.rpc().chain_get_finalized_head().await?;
        if let Some(block) = onet
            .rpc()
            .chain_get_header(Some(finalized_block_hash))
            .await?
        {
            debug!("finalized block head {:?} in storage", block.number);
            // process older blocks that have not been processed first
            while let Some(processed_block_number) = latest_block_number_processed {
                if block.number as u64 == processed_block_number {
                    latest_block_number_processed = None;
                    is_loading = false;
                } else {
                    // process the next block
                    let block_number = processed_block_number + 1;

                    // if finalized_head process block otherwise fetch block_hash and process the pending block
                    if block.number as u64 == block_number {
                        process_finalized_block(
                            &onet,
                            &mut subscribers,
                            &mut records,
                            block_number,
                            block.hash(),
                            is_loading,
                        )
                        .await?;
                    } else {
                        // fetch block_hash if not the finalized head
                        if let Some(block_hash) = onet
                            .rpc()
                            .chain_get_block_hash(Some(block_number.into()))
                            .await?
                        {
                            process_finalized_block(
                                &onet,
                                &mut subscribers,
                                &mut records,
                                block_number,
                                block_hash,
                                is_loading,
                            )
                            .await?;
                        }
                    };

                    //
                    latest_block_number_processed = Some(block_number);
                }
            }
        }
        latest_block_number_processed = Some(get_latest_block_number_processed()?);
    }

    Err(OnetError::SubscriptionFinished)
}

pub async fn process_best_block(
    onet: &Onet,
    records: &mut Records,
    block_number: BlockNumber,
) -> Result<(), OnetError> {
    // update best block number
    records.set_best_block_number(block_number.into());

    // if api enabled cache best block
    let config = CONFIG.clone();
    if config.cache_writer_enabled {
        let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;
        redis::cmd("SET")
            .arg(CacheKey::BestBlock)
            .arg(block_number.to_string())
            .query_async(&mut cache as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;
    }

    Ok(())
}

pub async fn process_finalized_block(
    onet: &Onet,
    subscribers: &mut Subscribers,
    records: &mut Records,
    block_number: BlockNumber,
    block_hash: H256,
    is_loading: bool,
) -> Result<(), OnetError> {
    let start = Instant::now();
    let config = CONFIG.clone();
    let api = onet.client().clone();

    let exceptional_blocks: Vec<String> =
        config.blocks_where_metadata_is_fetched_from_previous_block;

    // NOTE: this exceptional cases handle the cases where the events of a certain block is
    // only able to be decoded if metadata presented is from previous block
    // an example is the block_number 15426015 in Kusama
    let block_hash_metadata = if exceptional_blocks.contains(&block_number.to_string()) {
        onet.rpc()
            .chain_get_block_hash(Some((block_number - 1).into()))
            .await?
    } else {
        Some(block_hash)
    };

    let metadata = onet.rpc().state_get_metadata(block_hash_metadata).await?;
    debug!("metadata_legacy: {:?}", metadata);

    let events = Events::new_from_client(metadata, block_hash, api.clone()).await?;
    if let Some(new_session_event) = events.find_first::<NewSession>()? {
        info!("{:?}", new_session_event);

        switch_new_session(
            &onet,
            block_number,
            new_session_event.session_index,
            subscribers,
            records,
            block_hash,
            is_loading,
        )
        .await?;

        // Network public report
        try_run_network_report(new_session_event.session_index, &records, is_loading).await?;

        // Cache session records every new session
        try_run_cache_session_records(&records, block_hash).await?;

        // Cache session stats records every new session
        try_run_cache_session_stats_records(block_hash, is_loading).await?;

        // Cache nomination pools every new session
        try_run_cache_nomination_pools(block_number, block_hash).await?;
    }

    // Update records
    // Note: this records should be updated after the switch of session
    track_records(&onet, records, block_number, block_hash).await?;

    // Cache pool stats every 10 minutes
    try_run_cache_nomination_pools_stats(block_number, block_hash).await?;

    // Cache records at every block
    cache_track_records(&onet, &records).await?;

    // Cache block processed
    write_latest_block_number_processed(block_number)?;

    // Log block processed duration time
    info!("Block #{} processed ({:?})", block_number, start.elapsed());

    Ok(())
}

// cache_track_records is called once at every block
pub async fn cache_track_records(onet: &Onet, records: &Records) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.cache_writer_enabled {
        let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

        // cache records every new block
        if let Some(current_block) = records.current_block() {
            let current_era = records.current_era();
            let current_epoch = records.current_epoch();

            let mut parachains_map: BTreeMap<ParaId, ParachainRecord> = BTreeMap::new();
            let mut session_stats = SessionStats::default();

            if let Some(authorities) = records.get_authorities(None) {
                for authority_idx in authorities.iter() {
                    if let Some(authority_record) =
                        records.get_authority_record(*authority_idx, None)
                    {
                        // aggregate authority session_stats counters
                        session_stats.authorities += 1;
                        session_stats.points += authority_record.points();
                        // info!("___block: {} points: {}", current_block, session_stats.points);
                        session_stats.authored_blocks += authority_record.total_authored_blocks();

                        //
                        let authority_key =
                            CacheKey::AuthorityRecord(current_era, current_epoch, *authority_idx);

                        let mut data: BTreeMap<String, String> = BTreeMap::new();
                        if let Some(para_record) = records.get_para_record(*authority_idx, None) {
                            // aggregate para_authority session_stats counters
                            session_stats.para_authorities += 1;
                            session_stats.core_assignments += para_record.total_core_assignments();
                            session_stats.explicit_votes += para_record.total_explicit_votes();
                            session_stats.implicit_votes += para_record.total_implicit_votes();
                            session_stats.missed_votes += para_record.total_missed_votes();
                            session_stats.disputes += para_record.total_disputes();

                            //
                            let serialized = serde_json::to_string(&para_record)?;
                            data.insert(String::from("para"), serialized);

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
                                .query_async(&mut cache as &mut Connection)
                                .await
                                .map_err(CacheError::RedisCMDError)?;

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
                                .query_async(&mut cache as &mut Connection)
                                .await
                                .map_err(CacheError::RedisCMDError)?;

                            // aggregate parachains counters
                            for (para_id, stats) in para_record.para_stats().iter() {
                                let pm = parachains_map
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
                                let ca: u32 = (100 / (para_record.peers().len() + 1)) as u32
                                    * stats.core_assignments();
                                pm.stats.core_assignments += ca;
                                pm.para_id = *para_id;
                            }

                            if let Some(para_id) = para_record.para_id() {
                                let pm = parachains_map
                                    .entry(para_id)
                                    .or_insert(ParachainRecord::default());
                                pm.current_group = para_record.group();
                                let mut authorities: Vec<AuthorityIndex> = vec![*authority_idx];
                                authorities.append(&mut para_record.peers());
                                pm.current_authorities = authorities;
                            }
                        }
                        let serialized = serde_json::to_string(&authority_record)?;
                        data.insert(String::from("auth"), serialized);
                        redis::pipe()
                            .atomic()
                            .cmd("HSET")
                            .arg(authority_key.to_string())
                            .arg(data)
                            .cmd("EXPIRE")
                            .arg(authority_key.to_string())
                            .arg(config.cache_writer_prunning)
                            .query_async(&mut cache as &mut Connection)
                            .await
                            .map_err(CacheError::RedisCMDError)?;
                    }
                }
            }
            let serialized = serde_json::to_string(&session_stats)?;

            redis::pipe()
                .atomic()
                // cache current_block / finalized block
                .cmd("SET")
                .arg(CacheKey::FinalizedBlock)
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
                .query_async(&mut cache as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;

            // cache parachains stats
            for (para_id, records) in parachains_map.iter() {
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
                    .query_async(&mut cache as &mut Connection)
                    .await
                    .map_err(CacheError::RedisCMDError)?;
            }

            // cache current_block for the current_session
            if let Some(start_block) = records.start_block(None) {
                if current_block != start_block {
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
                        .query_async(&mut cache as &mut Connection)
                        .await
                        .map_err(CacheError::RedisCMDError)?;
                }
            }
        }
    }

    Ok(())
}

pub async fn try_run_cache_session_records(
    records: &Records,
    block_hash: H256,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.cache_writer_enabled {
        let records_cloned = records.clone();
        async_std::task::spawn(async move {
            if let Err(e) = cache_session_records(&records_cloned, block_hash).await {
                error!("try_run_cache_session_records error: {:?}", e);
            }
        });
    }

    Ok(())
}

// cache_session_records is called once at every new session
pub async fn cache_session_records(records: &Records, block_hash: H256) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.cache_writer_enabled {
        let start = Instant::now();
        let onet: Onet = Onet::new().await;
        let api = onet.client().clone();
        let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

        // cache records every new session
        let current_era = records.current_era();
        let current_epoch = records.current_epoch();

        // --- Cache SessionByIndex -> `current` or `epoch_index` (to be able to search history)
        if let Some(start_block) = records.start_block(None) {
            if let Some(current_block) = records.current_block() {
                // get start session index
                let eras_start_session_index_addr = node_runtime::storage()
                    .staking()
                    .eras_start_session_index(&current_era);
                let start_session_index = match api
                    .storage()
                    .at(block_hash)
                    .fetch(&eras_start_session_index_addr)
                    .await?
                {
                    Some(index) => index,
                    None => return Err(OnetError::Other("Start session index not defined".into())),
                };

                // era session index
                let era_session_index = 1 + current_epoch - start_session_index;

                let mut data: BTreeMap<String, String> = BTreeMap::new();
                data.insert(String::from("era"), records.current_era().to_string());
                data.insert(String::from("session"), records.current_epoch().to_string());
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
                    .arg(CacheKey::SessionByIndex(Index::Num(
                        records.current_epoch().into(),
                    )))
                    .arg(data)
                    .cmd("EXPIRE")
                    .arg(CacheKey::SessionByIndex(Index::Num(
                        records.current_epoch().into(),
                    )))
                    .arg(config.cache_writer_prunning)
                    // by `current`
                    .cmd("SET")
                    .arg(CacheKey::SessionByIndex(Index::Str(String::from(
                        "current",
                    ))))
                    .arg(records.current_epoch().to_string())
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
                    .query_async(&mut cache as &mut Connection)
                    .await
                    .map_err(CacheError::RedisCMDError)?;
            }
        }

        // ---
        // cache authorities every new session
        if let Some(authorities) = records.get_authorities(None) {
            for authority_idx in authorities.iter() {
                if let Some(authority_record) = records.get_authority_record(*authority_idx, None) {
                    if let Some(stash) = authority_record.address() {
                        // cache authority key for the current era and session
                        // along with data_type and identity
                        let mut data: BTreeMap<String, String> = BTreeMap::new();
                        data.insert(String::from("address"), stash.to_string());
                        redis::pipe()
                            .atomic()
                            .cmd("HSET")
                            .arg(CacheKey::AuthorityRecord(
                                current_era,
                                current_epoch,
                                *authority_idx,
                            ))
                            .arg(data)
                            .cmd("EXPIRE")
                            .arg(CacheKey::AuthorityRecord(
                                current_era,
                                current_epoch,
                                *authority_idx,
                            ))
                            .arg(config.cache_writer_prunning)
                            .query_async(&mut cache as &mut Connection)
                            .await
                            .map_err(CacheError::RedisCMDError)?;

                        // cache authority key by stash account
                        let mut data: BTreeMap<String, String> = BTreeMap::new();
                        data.insert(String::from("era"), current_era.to_string());
                        data.insert(String::from("session"), current_epoch.to_string());
                        data.insert(String::from("authority"), (*authority_idx).to_string());
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
                            .query_async(&mut cache as &mut Connection)
                            .await
                            .map_err(CacheError::RedisCMDError)?;

                        // cache authority key into authorities by session to be easily filtered
                        let _: () = redis::pipe()
                            .atomic()
                            .cmd("SADD")
                            .arg(CacheKey::AuthorityKeysBySession(current_epoch))
                            .arg(
                                CacheKey::AuthorityRecord(
                                    current_era,
                                    current_epoch,
                                    *authority_idx,
                                )
                                .to_string(),
                            )
                            .cmd("EXPIRE")
                            .arg(CacheKey::AuthorityKeysBySession(current_epoch))
                            .arg(config.cache_writer_prunning)
                            .query_async(&mut cache as &mut Connection)
                            .await
                            .map_err(CacheError::RedisCMDError)?;

                        if records.get_para_record(*authority_idx, None).is_some() {
                            // cache authority key into authorities by session (only para_validators) to be easily filtered
                            let _: () = redis::pipe()
                                .atomic()
                                .cmd("SADD")
                                .arg(CacheKey::AuthorityKeysBySessionParaOnly(current_epoch))
                                .arg(
                                    CacheKey::AuthorityRecord(
                                        current_era,
                                        current_epoch,
                                        *authority_idx,
                                    )
                                    .to_string(),
                                )
                                .cmd("EXPIRE")
                                .arg(CacheKey::AuthorityKeysBySessionParaOnly(current_epoch))
                                .arg(config.cache_writer_prunning)
                                .query_async(&mut cache as &mut Connection)
                                .await
                                .map_err(CacheError::RedisCMDError)?;
                        }
                    }
                }
            }
        }
        // Log sesssion cache processed duration time
        info!("Session #{} cached ({:?})", current_epoch, start.elapsed());
    }

    Ok(())
}

pub async fn initialize_records(
    onet: &Onet,
    records: &mut Records,
    block_hash: H256,
) -> Result<(), OnetError> {
    let api = onet.client().clone();

    // Fetch Era reward points
    let era_reward_points_addr = node_runtime::storage()
        .staking()
        .eras_reward_points(&records.current_era());
    let era_reward_points = api
        .storage()
        .at(block_hash)
        .fetch(&era_reward_points_addr)
        .await?;

    if era_reward_points.is_none() {
        warn!(
            "At block hash: {:?} - None reward points were found for era {}.",
            block_hash,
            &records.current_era()
        );
    }

    // Fetch active validators
    let authorities_addr = node_runtime::storage().session().validators();
    if let Some(authorities) = api
        .storage()
        .at(block_hash)
        .fetch(&authorities_addr)
        .await?
    {
        // Fetch para validator groups
        let validator_groups_addr = node_runtime::storage().para_scheduler().validator_groups();
        if let Some(validator_groups) = api
            .storage()
            .at(block_hash)
            .fetch(&validator_groups_addr)
            .await?
        {
            // Fetch para validator indices
            let active_validator_indices_addr = node_runtime::storage()
                .paras_shared()
                .active_validator_indices();
            if let Some(active_validator_indices) = api
                .storage()
                .at(block_hash)
                .fetch(&active_validator_indices_addr)
                .await?
            {
                // Update records groups with respective authorities
                for (group_idx, group) in validator_groups.iter().enumerate() {
                    let auths: Vec<AuthorityIndex> = group
                        .iter()
                        .map(|ValidatorIndex(i)| {
                            let ValidatorIndex(auth_idx) =
                                active_validator_indices.get(*i as usize).unwrap();
                            *auth_idx
                        })
                        .collect();

                    records.insert_group(group_idx.try_into().unwrap(), auths);
                }

                // Find groupIdx and peers for each authority
                for (auth_idx, stash) in authorities.iter().enumerate() {
                    let auth_idx: AuthorityIndex = auth_idx.try_into().unwrap();

                    // Verify if is a para validator
                    if let Some(auth_para_idx) = active_validator_indices
                        .iter()
                        .position(|i| *i == ValidatorIndex(auth_idx))
                    {
                        for (group_idx, group) in validator_groups.iter().enumerate() {
                            // group = [ValidatorIndex(115), ValidatorIndex(116), ValidatorIndex(117), ValidatorIndex(118), ValidatorIndex(119)]
                            if group.contains(&ValidatorIndex(auth_para_idx.try_into().unwrap())) {
                                // Identify peers and collect respective points

                                for ValidatorIndex(para_idx) in group {
                                    if let Some(ValidatorIndex(auth_idx)) =
                                        active_validator_indices.get(*para_idx as usize)
                                    {
                                        if let Some(address) = authorities.get(*auth_idx as usize) {
                                            // Collect peer points
                                            let points = if let Some(ref erp) = era_reward_points {
                                                if let Some((_s, points)) = erp
                                                    .individual
                                                    .iter()
                                                    .find(|(s, _p)| s == address)
                                                {
                                                    *points
                                                } else {
                                                    0
                                                }
                                            } else {
                                                0
                                            };

                                            // Define AuthorityRecord
                                            let authority_record =
                                                AuthorityRecord::with_index_address_and_points(
                                                    *auth_idx,
                                                    address.clone(),
                                                    points,
                                                );

                                            // Find authority indexes for peers
                                            let peers: Vec<AuthorityIndex> = group
                                                .into_iter()
                                                .filter(|ValidatorIndex(i)| i != para_idx)
                                                .map(|ValidatorIndex(i)| {
                                                    let ValidatorIndex(peer_auth_idx) =
                                                        active_validator_indices
                                                            .get(*i as usize)
                                                            .unwrap();
                                                    *peer_auth_idx
                                                })
                                                .collect();

                                            // Define ParaRecord
                                            let para_record =
                                                ParaRecord::with_index_group_and_peers(
                                                    *para_idx,
                                                    group_idx.try_into().unwrap(),
                                                    peers,
                                                );

                                            // Insert a record for each validator in group
                                            records.insert(
                                                address,
                                                *auth_idx,
                                                authority_record,
                                                Some(para_record),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        // Fetch current points
                        let points = if let Some(ref erp) = era_reward_points {
                            if let Some((_s, points)) =
                                erp.individual.iter().find(|(s, _p)| s == stash)
                            {
                                *points
                            } else {
                                0
                            }
                        } else {
                            0
                        };

                        let authority_record = AuthorityRecord::with_index_address_and_points(
                            auth_idx,
                            stash.clone(),
                            points,
                        );

                        records.insert(stash, auth_idx, authority_record, None);
                    }
                }
                // debug!("records {:?}", records);
            } else {
                warn!(
                    "At block hash: {:?} - None authorities defined for era {}.",
                    block_hash,
                    &records.current_era()
                );
            }
        } else {
            warn!(
                "At block hash: {:?} - None validator groups defined.",
                block_hash
            );
        }
    } else {
        warn!(
            "At block hash: {:?} - None active validator indices defined.",
            block_hash
        );
    }

    Ok(())
}

pub async fn switch_new_session(
    onet: &Onet,
    block_number: u64,
    new_session_index: EpochIndex,
    subscribers: &mut Subscribers,
    records: &mut Records,
    block_hash: H256,
    is_loading: bool,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let api = onet.client().clone();

    // keep previous era in context
    let previous_era_index = records.current_era().clone();

    // Fetch active era index
    let active_era_addr = node_runtime::storage().staking().active_era();
    let current_era_index = match api.storage().at(block_hash).fetch(&active_era_addr).await? {
        Some(info) => info.index,
        None => return Err("Active era not defined".into()),
    };

    // Update records current Era and Epoch
    records.start_new_epoch(current_era_index, new_session_index);
    // Update records current block number
    records.set_current_block_number(block_number.into());

    // Update subscribers current Era and Epoch
    subscribers.start_new_epoch(current_era_index, new_session_index);

    if let Ok(subs) = get_subscribers() {
        for (account, user_id, param) in subs.iter() {
            subscribers.subscribe(account.clone(), user_id.to_string(), param.clone());
        }
    }

    // Initialize records for new epoch
    initialize_records(&onet, records, block_hash).await?;

    // Remove older keys, default is maximum_history_eras + 1
    records.remove(EpochKey(
        records.current_era() - (config.maximum_history_eras + 1),
        records.current_epoch() - ((config.maximum_history_eras + 1) * 6),
    ));
    subscribers.remove(EpochKey(
        records.current_era() - (config.maximum_history_eras + 1),
        records.current_epoch() - ((config.maximum_history_eras + 1) * 6),
    ));

    // Try to run matrix reports
    if !config.matrix_disabled && !is_loading {
        // Send reports from previous session (verify if era_index is the same or previous)
        let era_index: u32 = if current_era_index != previous_era_index {
            previous_era_index
        } else {
            current_era_index
        };

        let records_cloned = records.clone();
        let subscribers_cloned = subscribers.clone();
        async_std::task::spawn(async move {
            let epoch_index = records_cloned.current_epoch() - 1;
            if let Err(e) =
                run_val_perf_report(era_index, epoch_index, &records_cloned, &subscribers_cloned)
                    .await
            {
                error!(
                    "run_val_perf_report error: {:?} ({}//{})",
                    e, era_index, epoch_index
                );
            }
            if let Err(e) = run_groups_report(era_index, epoch_index, &records_cloned).await {
                error!(
                    "run_groups_report error: {:?} ({}//{})",
                    e, era_index, epoch_index
                );
            }
            if let Err(e) = run_parachains_report(era_index, epoch_index, &records_cloned).await {
                error!(
                    "run_parachains_report error: {:?} ({}//{})",
                    e, era_index, epoch_index
                );
            }
        });
    }

    // Cache current epoch
    let epoch_filename = format!("{}{}", config.data_path, EPOCH_FILENAME);
    fs::write(&epoch_filename, new_session_index.to_string())?;

    Ok(())
}

pub async fn track_records(
    onet: &Onet,
    records: &mut Records,
    block_number: BlockNumber,
    block_hash: H256,
) -> Result<(), OnetError> {
    let api = onet.client().clone();

    // Update records current block number
    records.set_current_block_number(block_number.into());

    // Extract authority from the block header
    if let Some(authority_index) = get_authority_index(&onet, Some(block_hash)).await? {
        // Fetch session index for the specified
        let current_index_addr = node_runtime::storage().session().current_index();
        let session_index = match api
            .storage()
            .at(block_hash)
            .fetch(&current_index_addr)
            .await?
        {
            Some(index) => index,
            None => return Err("Current session index not defined".into()),
        };

        // Track block authored
        if let Some(authority_record) =
            records.get_mut_authority_record(authority_index, Some(session_index))
        {
            authority_record.push_authored_block(block_number);
        }

        //
        // NOTE: Fetch currently scheduled cores as been DEPRECATED
        //
        // let scheduled_cores_addr = node_runtime::storage().para_scheduler().scheduled();
        // if let Some(scheduled_cores) = api
        //     .storage()
        //     .at(block_hash)
        //     .fetch(&scheduled_cores_addr)
        //     .await?
        // {
        //     // Update records para_group
        //     for core_assignment in scheduled_cores.iter() {
        //         debug!("core_assignment: {:?}", core_assignment);
        //         // CoreAssignment { core: CoreIndex(16), para_id: Id(2087), kind: Parachain, group_idx: GroupIndex(31) }

        //         // Destructure GroupIndex
        //         let GroupIndex(group_idx) = core_assignment.group_idx;
        //         // Destructure CoreIndex
        //         let CoreIndex(core) = core_assignment.core;
        //         // Destructure Id
        //         let Id(para_id) = core_assignment.para_id;

        //         records.update_para_group(para_id, core, group_idx, Some(session_index));
        //     }
        // }

        // Fetch Era reward points
        let era_reward_points_addr = node_runtime::storage()
            .staking()
            .eras_reward_points(&records.current_era());
        if let Some(era_reward_points) = api
            .storage()
            .at(block_hash)
            .fetch(&era_reward_points_addr)
            .await?
        {
            // Fetch para validator groups
            let validator_groups_addr = node_runtime::storage().para_scheduler().validator_groups();
            if let Some(validator_groups) = api
                .storage()
                .at(block_hash)
                .fetch(&validator_groups_addr)
                .await?
            {
                // Fetch para validator indices
                let active_validator_indices_addr = node_runtime::storage()
                    .paras_shared()
                    .active_validator_indices();
                if let Some(active_validator_indices) = api
                    .storage()
                    .at(block_hash)
                    .fetch(&active_validator_indices_addr)
                    .await?
                {
                    // Fetch on chain votes
                    let on_chain_votes_addr =
                        node_runtime::storage().para_inherent().on_chain_votes();

                    if let Some(backing_votes) = api
                        .storage()
                        .at(block_hash)
                        .fetch(&on_chain_votes_addr)
                        .await?
                    {
                        // *******************************************
                        // Track latest points collected per authority
                        // *******************************************
                        if let Some(&era_idx) = records.get_era_index(Some(backing_votes.session)) {
                            if let Some(authorities) = records
                                .get_authorities(Some(EpochKey(era_idx, backing_votes.session)))
                            {
                                // Find groupIdx and peers for each authority
                                for authority_idx in authorities.iter() {
                                    let mut latest_points_collected: u32 = 0;

                                    if let Some(authority_record) = records
                                        .get_mut_authority_record(
                                            *authority_idx,
                                            Some(backing_votes.session),
                                        )
                                    {
                                        if authority_record.address().is_some() {
                                            // Collect current points
                                            let current_points = if let Some((_s, points)) =
                                                era_reward_points.individual.iter().find(
                                                    |(s, _p)| {
                                                        s == authority_record.address().unwrap()
                                                    },
                                                ) {
                                                *points
                                            } else {
                                                0
                                            };

                                            // Update authority current points and get the difference
                                            latest_points_collected = authority_record
                                                .update_current_points(current_points);
                                        }
                                    }

                                    // Get para_record for the same on chain votes session
                                    if let Some(para_record) = records.get_mut_para_record(
                                        *authority_idx,
                                        Some(backing_votes.session),
                                    ) {
                                        // Increment current para_id latest_points_collected
                                        // and authored blocks if is the author of the finalized block
                                        // and the backing_votes session is the same as the current session
                                        // NOTE: At the first block of a session the backing_votes.session still references session().current_index - 1
                                        para_record.update_points(
                                            latest_points_collected,
                                            authority_index == *authority_idx
                                                && backing_votes.session == session_index,
                                        );
                                    }
                                }
                            }
                        }

                        // ***********************************************************************
                        // Track explicit/implicit/missed votes new approach since runtime 1000000
                        // ***********************************************************************
                        //
                        // Iterate over each validator_groups and find if one of the members show up at backing.group_authorities
                        // If yes, iterate again and increase implicit/explicit vote or increase missed vote if member is not present in backing.group_authorities
                        // TODO: Edge case of all members missing from backing.group_authorities

                        for (group_idx, group) in validator_groups.iter().enumerate() {
                            // NOTE: authorities_present vec will contain the authorities present in a group where someone is missing
                            let mut authorities_present = Vec::new();
                            let mut para_id_flagged: Option<ParaId> = None;

                            'outer: for ValidatorIndex(group_para_val_idx) in group {
                                for (candidate_receipt, group_authorities) in
                                    backing_votes.backing_validators_per_candidate.iter()
                                {
                                    // destructure para_id
                                    let Id(para_id) = candidate_receipt.descriptor.para_id;

                                    if let Some((_, vote)) = group_authorities.iter().find(
                                        |(ValidatorIndex(para_idx), _)| {
                                            *para_idx == *group_para_val_idx
                                        },
                                    ) {
                                        // get authority index from active_validator_indices
                                        if let Some(ValidatorIndex(auth_idx)) =
                                            active_validator_indices
                                                .get(*group_para_val_idx as usize)
                                        {
                                            // NOTE: in case there are less backing authorities than the original group len it means that someone is missing.
                                            // keep track of the ones present so that the ones missing could be identified later
                                            if group_authorities.len() < group.len() {
                                                authorities_present.push(*auth_idx);
                                                para_id_flagged = Some(para_id);
                                            }

                                            // get para_record for the same on chain votes session
                                            if let Some(para_record) = records.get_mut_para_record(
                                                *auth_idx,
                                                Some(backing_votes.session),
                                            ) {
                                                match vote {
                                                    ValidityAttestation::Explicit(_) => {
                                                        para_record.inc_explicit_votes(para_id);
                                                    }
                                                    ValidityAttestation::Implicit(_) => {
                                                        para_record.inc_implicit_votes(para_id);
                                                    }
                                                }
                                            }
                                        }
                                        // assign current para_id to the group
                                        records.update_para_id_by_group(
                                            para_id,
                                            u32::try_from(group_idx).unwrap(),
                                            Some(backing_votes.session),
                                        );
                                        continue 'outer;
                                    }
                                }
                            }
                            if authorities_present.len() > 0 && para_id_flagged.is_some() {
                                records.inc_missing_vote_for_the_missing_authorities(
                                    authorities_present,
                                    para_id_flagged.unwrap(),
                                    u32::try_from(group_idx).unwrap(),
                                    Some(backing_votes.session),
                                );
                            }
                        }

                        // ***********************************************************************
                        // Track Core Assignments only after specVersion > 1000000
                        // ***********************************************************************
                        // Fetch last_runtime_upgrade
                        let last_runtime_upgrade_addr =
                            node_runtime::storage().system().last_runtime_upgrade();

                        if let Some(info) = api
                            .storage()
                            .at(block_hash)
                            .fetch(&last_runtime_upgrade_addr)
                            .await?
                        {
                            if info.spec_version >= 1000000 {
                                // Fetch availability_cores
                                let availability_cores_addr = node_runtime::storage()
                                    .para_scheduler()
                                    .availability_cores();

                                if let Some(availability_cores) = api
                                    .storage()
                                    .at(block_hash)
                                    .fetch(&availability_cores_addr)
                                    .await?
                                {
                                    for (i, core_occupied) in availability_cores.iter().enumerate()
                                    {
                                        let core_idx = u32::try_from(i).unwrap();
                                        match &core_occupied {
                                            CoreOccupied::Free => records.update_core_free(
                                                core_idx,
                                                Some(backing_votes.session),
                                            ),
                                            CoreOccupied::Paras(paras_entry) => {
                                                // destructure para_id
                                                let Id(para_id) = paras_entry.assignment.para_id;
                                                records.update_core_by_para_id(
                                                    para_id,
                                                    core_idx,
                                                    Some(backing_votes.session),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // ***********************************************************************
                        // Track Initiated Disputes
                        // ***********************************************************************
                        for dispute_statement_set in backing_votes.disputes.iter() {
                            for (statement, ValidatorIndex(para_idx), _) in
                                dispute_statement_set.statements.iter()
                            {
                                match statement {
                                    DisputeStatement::Invalid(_) => {
                                        if let Some(ValidatorIndex(auth_idx)) =
                                            active_validator_indices.get(*para_idx as usize)
                                        {
                                            // Log stash address for the initiated dispute
                                            if let Some(authority_record) = records
                                                .get_mut_authority_record(
                                                    *auth_idx,
                                                    Some(backing_votes.session),
                                                )
                                            {
                                                if let Some(stash) = authority_record.address() {
                                                    warn!(
                                                        "Dispute initiated for stash: {} ({}) {:?}",
                                                        stash, auth_idx, statement
                                                    );
                                                }
                                            }
                                            // Get para_record for the same on chain votes session
                                            if let Some(para_record) = records.get_mut_para_record(
                                                *auth_idx,
                                                Some(backing_votes.session),
                                            ) {
                                                para_record.push_dispute(
                                                    block_number,
                                                    format!("{:?}", statement),
                                                );
                                            }
                                        } else {
                                            warn!("Dispute initiated at block {block_number} but authority record for para_idx: {para_idx} not found!");
                                        }
                                    }
                                    _ => continue,
                                }
                            }
                        }
                    } else {
                        warn!("None on chain voted recorded.");
                    }
                } else {
                    warn!("None para validator indices defined.");
                }
            } else {
                warn!("None validator groups defined.");
            }
        } else {
            warn!("None reward points at era {}.", &records.current_era());
        }
        debug!("records {:?}", records);
    }

    Ok(())
}

pub async fn run_val_perf_report(
    era_index: EraIndex,
    epoch_index: EpochIndex,
    records: &Records,
    subscribers: &Subscribers,
) -> Result<(), OnetError> {
    let onet: Onet = Onet::new().await;
    let api = onet.client().clone();

    let network = Network::load(onet.rpc()).await?;
    // Set era/session details
    let start_block = records
        .start_block(Some(EpochKey(era_index, epoch_index)))
        .unwrap_or(&0);
    let end_block = records
        .end_block(Some(EpochKey(era_index, epoch_index)))
        .unwrap_or(&0);
    let metadata = Metadata {
        active_era_index: era_index,
        current_session_index: epoch_index,
        blocks_interval: Some((*start_block, *end_block)),
        ..Default::default()
    };

    // Fetch parachains list
    // TODO: get parachains names
    let mut parachains: Vec<ParaId> = Vec::new();
    let parachains_addr = node_runtime::storage().paras().parachains();
    if let Some(paras) = api
        .storage()
        .at_latest()
        .await?
        .fetch(&parachains_addr)
        .await?
    {
        for Id(para_id) in paras {
            parachains.push(para_id);
        }
    }

    // Populate map to get group authority ranks
    let mut group_authorities_by_points_map: BTreeMap<u32, Points> = BTreeMap::new();
    // Populate vec to get all para authority ranks
    let mut para_authorities_by_points = Vec::<(AuthorityIndex, Points)>::new();

    if let Some(authorities) = records.get_authorities(Some(EpochKey(era_index, epoch_index))) {
        for authority_idx in authorities.iter() {
            if let Some(para_record) =
                records.get_para_record(*authority_idx, Some(EpochKey(era_index, epoch_index)))
            {
                if let Some(group_idx) = para_record.group() {
                    if let Some(authority_record) = records.get_authority_record(
                        *authority_idx,
                        Some(EpochKey(era_index, epoch_index)),
                    ) {
                        let ga = group_authorities_by_points_map
                            .entry(group_idx)
                            .or_insert(authority_record.points());
                        *ga += authority_record.points();
                        // push into para_authorities_by_points
                        para_authorities_by_points.push((
                            authority_record.authority_index().unwrap(),
                            authority_record.points(),
                        ));
                    }
                }
            }
        }
    }

    // Convert map to vec
    let group_authorities_by_points = Vec::from_iter(group_authorities_by_points_map);

    // Prepare data for each validator subscriber
    if let Some(subs) = subscribers.get(Some(EpochKey(era_index, epoch_index))) {
        for (stash, user_id, param) in subs.iter() {
            let mut validator = Validator::new(stash.clone());
            validator.name = get_display_name(&onet, &stash).await?;
            let mut data = RawDataPara {
                network: network.clone(),
                meta: metadata.clone(),
                report_type: ReportType::Validator(param.clone()),
                is_first_record: records.is_first_epoch(epoch_index),
                parachains: parachains.clone(),
                validator,
                authority_record: None,
                para_record: None,
                peers: Vec::new(),
                para_validator_rank: None,
                group_rank: None,
            };

            if let Some(authority_record) = records
                .get_authority_record_with_address(&stash, Some(EpochKey(era_index, epoch_index)))
            {
                data.authority_record = Some(authority_record.clone());

                if let Some(para_record) = records
                    .get_para_record_with_address(&stash, Some(EpochKey(era_index, epoch_index)))
                {
                    data.para_record = Some(para_record.clone());

                    // Get para validator rank position
                    data.para_validator_rank = Some((
                        position(
                            authority_record.authority_index().unwrap(),
                            group_by_points(para_authorities_by_points.clone()),
                        )
                        .unwrap_or_default(),
                        para_authorities_by_points.iter().count(),
                    ));

                    // Get group_rank position
                    data.group_rank = Some((
                        position(
                            para_record.group().unwrap(),
                            group_by_points(group_authorities_by_points.clone()),
                        )
                        .unwrap_or_default(),
                        group_authorities_by_points.iter().count(),
                    ));

                    // Collect peers information
                    for peer_authority_index in para_record.peers().iter() {
                        if let Some(peer_authority_record) = records.get_authority_record(
                            *peer_authority_index,
                            Some(EpochKey(era_index, epoch_index)),
                        ) {
                            if let Some(peer_stash) = peer_authority_record.address() {
                                let peer_name = get_display_name(&onet, &peer_stash).await?;

                                if let Some(peer_para_record) = records.get_para_record(
                                    *peer_authority_index,
                                    Some(EpochKey(era_index, epoch_index)),
                                ) {
                                    data.peers.push((
                                        peer_name,
                                        peer_authority_record.clone(),
                                        peer_para_record.clone(),
                                    ))
                                }
                            }
                        }
                    }

                    // Send report only if para records available
                    let report = Report::from(data);

                    onet.matrix()
                        .send_private_message(
                            user_id,
                            &report.message(),
                            Some(&report.formatted_message()),
                        )
                        .await?;
                    // NOTE: To not overflow matrix with messages just send maximum 2 per second
                    thread::sleep(time::Duration::from_millis(500));
                }
            }
        }
    }

    Ok(())
}

pub async fn run_groups_report(
    era_index: EraIndex,
    epoch_index: EpochIndex,
    records: &Records,
) -> Result<(), OnetError> {
    let onet: Onet = Onet::new().await;
    let _client = onet.client();

    let network = Network::load(onet.rpc()).await?;

    // Set era/session details
    let start_block = records
        .start_block(Some(EpochKey(era_index, epoch_index)))
        .unwrap_or(&0);
    let end_block = records
        .end_block(Some(EpochKey(era_index, epoch_index)))
        .unwrap_or(&0);
    let metadata = Metadata {
        active_era_index: era_index,
        current_session_index: epoch_index,
        blocks_interval: Some((*start_block, *end_block)),
        ..Default::default()
    };

    // Populate some maps to get ranks
    let mut group_authorities_map: BTreeMap<u32, Vec<(AuthorityRecord, ParaRecord, String)>> =
        BTreeMap::new();

    if let Some(authorities) = records.get_authorities(Some(EpochKey(era_index, epoch_index))) {
        for authority_idx in authorities.iter() {
            if let Some(para_record) =
                records.get_para_record(*authority_idx, Some(EpochKey(era_index, epoch_index)))
            {
                if let Some(group_idx) = para_record.group() {
                    if let Some(authority_record) = records.get_authority_record(
                        *authority_idx,
                        Some(EpochKey(era_index, epoch_index)),
                    ) {
                        if let Some(stash) = authority_record.address() {
                            // get validator name
                            let name = get_display_name(&onet, &stash).await?;

                            //
                            let auths =
                                group_authorities_map.entry(group_idx).or_insert(Vec::new());
                            auths.push((authority_record.clone(), para_record.clone(), name));
                            auths.sort_by(|(a, _, _), (b, _, _)| b.points().cmp(&a.points()));
                            // auths.sort_by(|(a, _, _), (b, _, _)| {
                            //     b.para_points().cmp(&a.para_points())
                            // });
                        }
                    }
                }
            }
        }
    }

    // Convert map to vec and sort group by points
    let mut group_authorities_sorted = Vec::from_iter(group_authorities_map);
    group_authorities_sorted.sort_by(|(_, a), (_, b)| {
        b.iter()
            .map(|x| x.0.para_points())
            .sum::<Points>()
            .cmp(&a.iter().map(|x| x.0.para_points()).sum::<Points>())
    });

    let data = RawDataGroup {
        network: network.clone(),
        meta: metadata.clone(),
        report_type: ReportType::Groups,
        is_first_record: records.is_first_epoch(epoch_index),
        groups: group_authorities_sorted.clone(),
    };

    let report = Report::from(data);

    if let Ok(subs) = get_subscribers_by_epoch(ReportType::Groups, Some(epoch_index)) {
        for user_id in subs.iter() {
            onet.matrix()
                .send_private_message(
                    user_id,
                    &report.message(),
                    Some(&report.formatted_message()),
                )
                .await?;
            // NOTE: To not overflow matrix with messages just send maximum 2 per second
            thread::sleep(time::Duration::from_millis(500));
        }
    }

    Ok(())
}

pub async fn run_parachains_report(
    era_index: EraIndex,
    epoch_index: EpochIndex,
    records: &Records,
) -> Result<(), OnetError> {
    let onet: Onet = Onet::new().await;

    let network = Network::load(onet.rpc()).await?;

    // Set era/session details
    let start_block = records
        .start_block(Some(EpochKey(era_index, epoch_index)))
        .unwrap_or(&0);
    let end_block = records
        .end_block(Some(EpochKey(era_index, epoch_index)))
        .unwrap_or(&0);
    let metadata = Metadata {
        active_era_index: era_index,
        current_session_index: epoch_index,
        blocks_interval: Some((*start_block, *end_block)),
        ..Default::default()
    };

    // Populate some maps to get ranks
    let mut parachains_map: BTreeMap<ParaId, ParaStats> = BTreeMap::new();

    if let Some(authorities) = records.get_authorities(Some(EpochKey(era_index, epoch_index))) {
        for authority_idx in authorities.iter() {
            if let Some(para_record) =
                records.get_para_record(*authority_idx, Some(EpochKey(era_index, epoch_index)))
            {
                for (para_id, stats) in para_record.para_stats().iter() {
                    let s = parachains_map
                        .entry(*para_id)
                        .or_insert(ParaStats::default());
                    s.implicit_votes += stats.implicit_votes();
                    s.explicit_votes += stats.explicit_votes();
                    s.missed_votes += stats.missed_votes();
                    s.core_assignments += stats.core_assignments();
                    s.authored_blocks += stats.authored_blocks();
                    s.points += stats.points();
                }
            }
        }
    }

    // Convert map to vec and sort group by points
    let mut parachains_sorted = Vec::from_iter(parachains_map);
    parachains_sorted.sort_by(|(_, a), (_, b)| b.para_points().cmp(&a.para_points()));

    let data = RawDataParachains {
        network: network.clone(),
        meta: metadata.clone(),
        report_type: ReportType::Parachains,
        is_first_record: records.is_first_epoch(epoch_index),
        parachains: parachains_sorted.clone(),
    };

    // Send report only if para records available
    let report = Report::from(data);

    if let Ok(subs) = get_subscribers_by_epoch(ReportType::Parachains, Some(epoch_index)) {
        for user_id in subs.iter() {
            onet.matrix()
                .send_private_message(
                    user_id,
                    &report.message(),
                    Some(&report.formatted_message()),
                )
                .await?;
            // NOTE: To not overflow matrix with messages just send maximum 2 per second
            thread::sleep(time::Duration::from_millis(500));
        }
    }

    Ok(())
}

pub async fn try_run_network_report(
    epoch_index: EpochIndex,
    records: &Records,
    is_loading: bool,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if !config.matrix_disabled && !is_loading {
        if (epoch_index as f64 % config.matrix_network_report_epoch_rate as f64)
            == config.epoch_rate_threshold as f64
        {
            if records.total_full_epochs() > 0 {
                let records_cloned = records.clone();
                async_std::task::spawn(async move {
                    if let Err(e) = run_network_report(&records_cloned).await {
                        error!("try_run_network_report error: {:?}", e);
                    }
                });
            } else {
                warn!("No full sessions yet to run the network report.")
            }
        }
    }

    Ok(())
}

pub async fn run_network_report(records: &Records) -> Result<(), OnetError> {
    let onet: Onet = Onet::new().await;
    let config = CONFIG.clone();
    let api = onet.client().clone();

    let network = Network::load(onet.rpc()).await?;

    // Fetch active era index
    let active_era_addr = node_runtime::storage().staking().active_era();
    let active_era_index = match api
        .storage()
        .at_latest()
        .await?
        .fetch(&active_era_addr)
        .await?
    {
        Some(info) => info.index,
        None => return Err("Active era not defined".into()),
    };

    // Fetch current epoch
    let current_index_addr = node_runtime::storage().session().current_index();
    let current_session_index = match api
        .storage()
        .at_latest()
        .await?
        .fetch(&current_index_addr)
        .await?
    {
        Some(index) => index,
        None => return Err("Current session index not defined".into()),
    };

    // Fetch active era total stake
    let eras_total_stake_addr = node_runtime::storage()
        .staking()
        .eras_total_stake(&active_era_index);
    let active_era_total_stake = match api
        .storage()
        .at_latest()
        .await?
        .fetch(&eras_total_stake_addr)
        .await?
    {
        Some(total_stake) => total_stake,
        None => return Err("Current session index not defined".into()),
    };

    // Set era/session details
    let metadata = Metadata {
        active_era_index,
        current_session_index,
        active_era_total_stake,
        ..Default::default()
    };

    let mut validators: Validators = Vec::new();

    // Load TVP stashes
    let tvp_stashes: Vec<AccountId32> = try_fetch_stashes_from_remote_url(false).await?;

    // Fetch active validators
    let authorities_addr = node_runtime::storage().session().validators();
    if let Some(authorities) = api
        .storage()
        .at_latest()
        .await?
        .fetch(&authorities_addr)
        .await?
    {
        // Fetch all validators
        let validators_addr = node_runtime::storage().staking().validators_iter();
        let mut iter = api
            .storage()
            .at_latest()
            .await?
            .iter(validators_addr)
            .await?;
        while let Some(Ok((key, validator_prefs))) = iter.next().await {
            let stash = get_account_id_from_storage_key(key);
            let mut v = Validator::new(stash.clone());
            if validator_prefs.commission != Perbill(1000000000) {
                if !tvp_stashes.contains(&stash) {
                    v.subset = Subset::NONTVP;
                } else {
                    v.subset = Subset::TVP;
                }
                v.is_oversubscribed =
                    verify_oversubscribed(&onet, active_era_index, &stash, None).await?;
            } else {
                v.subset = Subset::C100;
            }
            // Commisssion
            let Perbill(commission) = validator_prefs.commission;
            v.commission = commission as f64 / 1_000_000_000.0_f64;
            // Check if validator is in active set
            v.is_active = authorities.contains(&stash);

            // Fetch own stake
            v.own_stake = get_own_stake_via_stash(&onet, &stash).await?;

            // Get performance data from all eras available
            if let Some(((active_epochs, authored_blocks, mut pattern), para_data)) =
                records.get_data_from_all_full_epochs(&stash)
            {
                v.active_epochs = active_epochs;
                v.authored_blocks = authored_blocks;
                v.pattern.append(&mut pattern);
                if let Some((
                    para_epochs,
                    para_points,
                    explicit_votes,
                    implicit_votes,
                    missed_votes,
                    core_assignments,
                )) = para_data
                {
                    // Note: If Para data exists than get node identity to be visible in the report
                    v.name = get_display_name(&onet, &stash).await?;
                    //
                    v.para_epochs = para_epochs;
                    v.explicit_votes = explicit_votes;
                    v.implicit_votes = implicit_votes;
                    v.missed_votes = missed_votes;
                    v.core_assignments = core_assignments;
                    if explicit_votes + implicit_votes + missed_votes > 0 {
                        let mvr = missed_votes as f64
                            / (explicit_votes + implicit_votes + missed_votes) as f64;
                        v.missed_ratio = Some(mvr);
                    }
                    if para_epochs >= 1 {
                        v.avg_para_points = para_points / para_epochs;
                    }
                }
            }

            //
            validators.push(v);
        }
    }

    // Collect era points for maximum_history_eras
    let start_era_index = active_era_index - config.maximum_history_eras;
    for era_index in start_era_index..active_era_index {
        // Fetch Era reward points
        let era_reward_points_addr = node_runtime::storage()
            .staking()
            .eras_reward_points(&era_index);
        if let Some(era_reward_points) = api
            .storage()
            .at_latest()
            .await?
            .fetch(&era_reward_points_addr)
            .await?
        {
            for (stash, points) in era_reward_points.individual.iter() {
                validators
                    .iter_mut()
                    .filter(|v| v.stash == *stash)
                    .for_each(|v| {
                        (*v).maximum_history_total_eras += 1;
                        (*v).maximum_history_total_points += points;
                    });
            }
        }
    }

    // Calculate a score based on the formula
    // SCORE_1 = (1-MVR)*0.75 + ((AVG_PV_POINTS - MIN_AVG_POINTS)/(MAX_AVG_PV_POINTS-MIN_AVG_PV_POINTS))*0.18 + (PV_SESSIONS/TOTAL_SESSIONS)*0.07
    // SCORE_2 = SCORE*0.25 + (1-COMMISSION)*0.75

    // Normalize avg_para_points
    let avg_para_points: Vec<u32> = validators
        .iter()
        .filter(|v| v.para_epochs >= 1 && v.missed_ratio.is_some())
        .map(|v| v.avg_para_points)
        .collect();
    let max = avg_para_points.iter().max().unwrap_or_else(|| &0);
    let min = avg_para_points.iter().min().unwrap_or_else(|| &0);

    // Log maximum and minimum as it's useful to debug the repart score if nedeed
    info!(
        "Avg. para_points max: {} min: {} for the last {} sessions.",
        max,
        min,
        records.total_full_epochs()
    );

    validators
        .iter_mut()
        .filter(|v| v.para_epochs >= 1 && v.missed_ratio.is_some())
        .for_each(|v| {
            let score = if max - min > 0 {
                (1.0_f64 - v.missed_ratio.unwrap()) * 0.75_f64
                    + ((v.avg_para_points as f64 - *min as f64) / (*max as f64 - *min as f64))
                        * 0.18_f64
                    + (v.para_epochs as f64 / records.total_full_epochs() as f64) * 0.07_f64
            } else {
                0.0_f64
            };
            (*v).score = score;
            (*v).commission_score = score * 0.25 + (1.0 - v.commission) * 0.75;
        });

    debug!("validators {:?}", validators);

    // Count TVP validators
    let tvp_validators_total = validators
        .iter()
        .filter(|v| v.subset == Subset::TVP && v.para_epochs >= 1 && v.missed_ratio.is_some())
        .count();

    if tvp_validators_total > 0 {
        // Network report data
        let data = RawData {
            network: network.clone(),
            meta: metadata.clone(),
            validators: validators.clone(),
            records_total_full_epochs: records.total_full_epochs(),
        };

        let report = Report::from(data.clone());
        onet.matrix()
            .send_public_message(&report.message(), Some(&report.formatted_message()))
            .await?;

        // Trigger callout message to public rooms at the rate defined in config
        let r = current_session_index as f64 % config.matrix_callout_epoch_rate as f64;
        if r == 0.0_f64 {
            let callout = Report::callout(data);
            onet.matrix()
                .send_callout_message(&callout.message(), Some(&callout.formatted_message()))
                .await?;
        }

        // ---- Validators Performance Ranking Report data ----

        // Set era/session details
        let start_epoch = current_session_index - records.total_full_epochs();
        if let Some(start_era) = records.get_era_index(Some(start_epoch)) {
            let start_block = records
                .start_block(Some(EpochKey(*start_era, start_epoch)))
                .unwrap_or(&0);

            let end_epoch = current_session_index - 1;
            if let Some(end_era) = records.get_era_index(Some(end_epoch)) {
                let end_block = records
                    .end_block(Some(EpochKey(*end_era, current_session_index - 1)))
                    .unwrap_or(&0);
                let metadata = Metadata {
                    interval: Some(((*start_era, start_epoch), (*end_era, end_epoch))),
                    blocks_interval: Some((*start_block, *end_block)),
                    ..Default::default()
                };

                let data = RawDataRank {
                    network: network.clone(),
                    meta: metadata.clone(),
                    report_type: ReportType::Insights,
                    validators: validators.clone(),
                    records_total_full_epochs: records.total_full_epochs(),
                };

                let report = Report::from(data);

                // Save file
                let filename = format!(
                    "onet_{}_{}{}_{}{}.txt.gz",
                    config.chain_name.to_lowercase(),
                    start_era,
                    start_epoch,
                    end_era,
                    end_epoch
                );
                report.save(&filename)?;

                // Get upload file and send message DM
                let path_filename = format!("{}{}", config.data_path, filename);
                let file_size = fs::metadata(&path_filename)?.len();

                if let Some(url) = onet.matrix().upload_file(&path_filename)? {
                    if let Ok(subs) = get_subscribers_by_epoch(ReportType::Insights, None) {
                        for user_id in subs.iter() {
                            onet.matrix()
                                .send_private_file(
                                    user_id,
                                    &filename,
                                    &url,
                                    Some(FileInfo::with_size(file_size)),
                                )
                                .await?;
                            // NOTE: To not overflow matrix with messages just send maximum 2 per second
                            thread::sleep(time::Duration::from_millis(500));
                        }
                    }
                }
            }
        }

        // Trigger nomination at the rate defined in config
        if config.pools_enabled {
            if (current_session_index as f64 % config.pools_nominate_rate as f64)
                == config.epoch_rate_threshold as f64
            {
                if records.total_full_epochs() >= config.pools_minimum_sessions {
                    match try_run_nomination(&onet, &records, validators).await {
                        Ok(message) => {
                            onet.matrix()
                                .send_public_message(&message, Some(&message))
                                .await?;
                        }
                        Err(e) => error!("{}", e),
                    }
                } else {
                    warn!(
                        "Only {} full sessions recorded, at least {} are needed to trigger a nomination.",
                        records.total_full_epochs(),
                        config.pools_minimum_sessions
                    );
                }
            }
        }
    } else {
        let message = format!(
            "💤 Skipping Network Report for {} // {} due to the status of the TVP validators not being successfully obtained.",
                network.name,
                metadata.active_era_index,
        );
        onet.matrix()
            .send_public_message(&message, Some(&message))
            .await?;
    }

    Ok(())
}

fn define_first_pool_call(
    validators: &mut Vec<&Validator>,
    maximum_nominations: Option<u32>,
) -> Result<Call, OnetError> {
    let config = CONFIG.clone();
    let pool_id = config.pool_id_1;
    if pool_id == 0 {
        return Err(OnetError::PoolError(format!(
            "Nomination Pool ID {} not defined.",
            pool_id
        )));
    }

    if validators.len() > 0 {
        // Sort validators by score for Pool 1
        validators.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        // Limit maximum nomination candidates to be included in the call
        let max: usize = if let Some(max) = maximum_nominations {
            if validators.len() as u32 > max {
                usize::try_from(max).unwrap()
            } else {
                validators.len()
            }
        } else {
            if validators.len() as u32 > config.pools_maximum_nominations {
                usize::try_from(config.pools_maximum_nominations).unwrap()
            } else {
                validators.len()
            }
        };

        validators.truncate(max);

        let accounts = validators
            .iter()
            .map(|v| v.stash.clone())
            .collect::<Vec<AccountId32>>();

        // Define call
        let call = Call::NominationPools(NominationPoolsCall::nominate {
            pool_id: pool_id,
            validators: accounts,
        });
        return Ok(call);
    }
    Err(OnetError::PoolError(format!(
        "Call for nomination pool {} could not be defined since there are No validators to select",
        pool_id
    )))
}

fn define_second_pool_call(
    validators: &mut Vec<&Validator>,
    maximum_nominations: Option<u32>,
) -> Result<Call, OnetError> {
    let config = CONFIG.clone();
    let pool_id = config.pool_id_2;
    if pool_id == 0 {
        return Err(OnetError::PoolError(format!(
            "Nomination Pool ID {} not defined.",
            pool_id
        )));
    }

    if validators.len() > 0 {
        // Sort validators by score for Pool 1
        validators.sort_by(|a, b| b.commission_score.partial_cmp(&a.commission_score).unwrap());

        // Limit maximum nomination candidates to be included in the call
        let max: usize = if let Some(max) = maximum_nominations {
            if validators.len() as u32 > max {
                usize::try_from(max).unwrap()
            } else {
                validators.len()
            }
        } else {
            if validators.len() as u32 > config.pools_maximum_nominations {
                usize::try_from(config.pools_maximum_nominations).unwrap()
            } else {
                validators.len()
            }
        };

        validators.truncate(max);

        let accounts = validators
            .iter()
            .map(|v| v.stash.clone())
            .collect::<Vec<AccountId32>>();

        // Define call
        let call = Call::NominationPools(NominationPoolsCall::nominate {
            pool_id: pool_id,
            validators: accounts,
        });
        return Ok(call);
    }
    Err(OnetError::PoolError(format!(
        "Call for nomination pool {} could not be defined since there are No validators to select",
        pool_id
    )))
}

// * APR is the annualized average of all stashes from the last X eras.
pub async fn calculate_apr_from_stashes(
    onet: &Onet,
    stashes: Vec<AccountId32>,
    block_hash: H256,
) -> Result<f64, OnetError> {
    let start = Instant::now();
    let api = onet.client().clone();
    let config = CONFIG.clone();

    // Fetch active era index
    let active_era_addr = node_runtime::storage().staking().active_era();
    let active_era_index = match api.storage().at(block_hash).fetch(&active_era_addr).await? {
        Some(info) => info.index,
        None => return Err("Active era not defined".into()),
    };

    let mut total_eras: u128 = 0;
    let mut total_points: u128 = 0;
    let mut total_reward: u128 = 0;
    let mut nominees_total_eras: u128 = 0;
    let mut nominees_total_points: u128 = 0;
    let mut nominees_total_stake: u128 = 0;
    let mut nominees_total_commission: u128 = 0;

    // Collect stash commission
    for stash in stashes.iter() {
        let validator_addr = node_runtime::storage().staking().validators(stash);
        if let Some(validator) = api.storage().at(block_hash).fetch(&validator_addr).await? {
            let Perbill(commission) = validator.commission;
            nominees_total_commission += commission as u128;
        }
    }

    // Collect chain data for maximum_history_eras
    // let start_era_index = active_era_index - config.maximum_history_eras;
    let start_era_index = active_era_index - 84;
    for era_index in start_era_index..active_era_index {
        // Fetch Era reward points
        let era_reward_points_addr = node_runtime::storage()
            .staking()
            .eras_reward_points(&era_index);
        if let Some(era_reward_points) = api
            .storage()
            .at(block_hash)
            .fetch(&era_reward_points_addr)
            .await?
        {
            for (stash, points) in era_reward_points.individual.iter() {
                if stashes.contains(stash) {
                    nominees_total_eras += 1;
                    nominees_total_points += *points as u128;

                    // Fetch Era stakers
                    let eras_stakers_addr = node_runtime::storage()
                        .staking()
                        .eras_stakers(&era_index, stash);
                    if let Some(eras_stakers) = api
                        .storage()
                        .at(block_hash)
                        .fetch(&eras_stakers_addr)
                        .await?
                    {
                        nominees_total_stake += eras_stakers.total;
                    }
                }
            }
            total_points += era_reward_points.total as u128;
            total_eras += 1;

            // Fetch Era validator reward
            let eras_validator_reward_addr = node_runtime::storage()
                .staking()
                .eras_validator_reward(&era_index);
            if let Some(eras_validator_reward) = api
                .storage()
                .at(block_hash)
                .fetch(&eras_validator_reward_addr)
                .await?
            {
                total_reward += eras_validator_reward;
            }
        }
    }

    debug!(
        "nominees_total_eras: {} nominees_total_points: {} nominees_total_stake: {}",
        nominees_total_eras, nominees_total_points, nominees_total_stake
    );
    debug!(
        "total_eras: {} total_points: {} total_reward: {}",
        total_eras, total_points, total_reward
    );

    if nominees_total_eras > 0 {
        let avg_points_per_nominee_per_era = nominees_total_points / nominees_total_eras;
        debug!(
            "avg_points_per_nominee_per_era: {}",
            avg_points_per_nominee_per_era
        );
        let avg_stake_per_nominee_per_era = nominees_total_stake / nominees_total_eras;
        debug!(
            "avg_stake_per_nominee_per_era: {}",
            avg_stake_per_nominee_per_era
        );
        let avg_reward_per_era = total_reward / total_eras;
        debug!("avg_reward_per_era: {}", avg_reward_per_era);
        let avg_points_per_era = total_points / total_eras;
        debug!("avg_points_per_era: {}", avg_points_per_era);

        let avg_reward_per_nominee_per_era =
            (avg_points_per_nominee_per_era * avg_reward_per_era) / avg_points_per_era;
        debug!(
            "avg_reward_per_nominee_per_era: {}",
            avg_reward_per_nominee_per_era
        );

        let avg_commission_per_nominee = nominees_total_commission / stashes.len() as u128;
        debug!("avg_commission_per_nominee: {}", avg_commission_per_nominee);

        let commission = avg_commission_per_nominee as f64 / 1_000_000_000.0_f64;
        let apr: f64 = (avg_reward_per_nominee_per_era as f64 * (1.0 - commission))
            * (1.0 / avg_stake_per_nominee_per_era as f64)
            * config.eras_per_day as f64
            * 365.0;
        debug!("APR: {} calculated ({:?})", apr, start.elapsed());
        Ok(apr)
    } else {
        Ok(0.0_f64)
    }
}

pub async fn try_run_cache_nomination_pools(
    block_number: BlockNumber,
    block_hash: H256,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.cache_writer_enabled && config.pools_enabled {
        async_std::task::spawn(async move {
            if let Err(e) = cache_nomination_pools(block_number, block_hash).await {
                error!("cache_nomination_pools error: {:?}", e);
            }
        });

        async_std::task::spawn(async move {
            if let Err(e) = cache_nomination_pools_stats(block_number, block_hash).await {
                error!("cache_nomination_pools_stats error: {:?}", e);
            }
        });

        // NOTE: network_report is issued every era we could use the same config to cache nomination pools APR
        // but since the APR is based on the current nominees and these can be changed within the session
        // we calculate the APR every new session for now
        async_std::task::spawn(async move {
            if let Err(e) = cache_nomination_pools_nominees(block_number, block_hash).await {
                error!("cache_nomination_pools_stats error: {:?}", e);
            }
        });
    }
    Ok(())
}

pub async fn try_run_cache_nomination_pools_stats(
    block_number: BlockNumber,
    block_hash: H256,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.cache_writer_enabled && config.pools_enabled {
        // collect nomination stats every minute
        if (block_number as f64 % 10.0_f64) == 0.0_f64 {
            async_std::task::spawn(async move {
                if let Err(e) = cache_nomination_pools_stats(block_number, block_hash).await {
                    error!("cache_nomination_pools_stats error: {:?}", e);
                }
            });
        }
    }
    Ok(())
}

pub async fn cache_nomination_pools_nominees(
    block_number: BlockNumber,
    block_hash: H256,
) -> Result<(), OnetError> {
    let start = Instant::now();
    let onet: Onet = Onet::new().await;
    let api = onet.client().clone();
    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

    // fetch last pool id
    let last_pool_id_addr = node_runtime::storage().nomination_pools().last_pool_id();
    if let Some(last_pool_id) = api
        .storage()
        .at(block_hash)
        .fetch(&last_pool_id_addr)
        .await?
    {
        let active_era_addr = node_runtime::storage().staking().active_era();
        let era_index = match api.storage().at(block_hash).fetch(&active_era_addr).await? {
            Some(info) => info.index,
            None => return Err("Active era not defined".into()),
        };
        let current_index_addr = node_runtime::storage().session().current_index();
        let epoch_index = match api
            .storage()
            .at(block_hash)
            .fetch(&current_index_addr)
            .await?
        {
            Some(index) => index,
            None => return Err("Current session index not defined".into()),
        };

        let mut valid_pool = Some(1);
        while let Some(pool_id) = valid_pool {
            if pool_id > last_pool_id {
                valid_pool = None;
            } else {
                let mut pool_nominees = PoolNominees::new();
                pool_nominees.block_number = block_number;

                // fetch pool nominees
                let pool_stash_account = nomination_pool_account(AccountType::Bonded, pool_id);
                let nominators_addr = node_runtime::storage()
                    .staking()
                    .nominators(&pool_stash_account);
                if let Some(nominations) =
                    api.storage().at(block_hash).fetch(&nominators_addr).await?
                {
                    // deconstruct targets
                    let BoundedVec(stashes) = nominations.targets;

                    // calculate APR
                    pool_nominees.apr =
                        calculate_apr_from_stashes(&onet, stashes.clone(), block_hash).await?;

                    pool_nominees.nominees = stashes.clone();

                    let mut active = Vec::<ActiveNominee>::new();
                    // check active nominees
                    for stash in stashes {
                        let eras_stakers_addr = node_runtime::storage()
                            .staking()
                            .eras_stakers(era_index, &stash);
                        if let Some(exposure) = api
                            .storage()
                            .at(block_hash)
                            .fetch(&eras_stakers_addr)
                            .await?
                        {
                            if let Some(individual) =
                                exposure.others.iter().find(|x| x.who == pool_stash_account)
                            {
                                active.push(ActiveNominee::with(stash.clone(), individual.value));
                            }
                        }
                    }
                    pool_nominees.active = active;

                    // serialize and cache pool
                    let serialized = serde_json::to_string(&pool_nominees)?;
                    redis::cmd("SET")
                        .arg(CacheKey::NominationPoolNomineesByPoolAndSession(
                            pool_id,
                            epoch_index,
                        ))
                        .arg(serialized)
                        .query_async(&mut cache as &mut Connection)
                        .await
                        .map_err(CacheError::RedisCMDError)?;
                }

                valid_pool = Some(pool_id + 1);
            }
        }
        // Log cache processed duration time
        info!(
            "Pools nominees #{} cached ({:?})",
            epoch_index,
            start.elapsed()
        );
    }

    Ok(())
}

pub async fn cache_nomination_pools_stats(
    block_number: BlockNumber,
    block_hash: H256,
) -> Result<(), OnetError> {
    let start = Instant::now();
    let onet: Onet = Onet::new().await;
    let api = onet.client().clone();
    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

    // fetch last pool id
    let last_pool_id_addr = node_runtime::storage().nomination_pools().last_pool_id();
    if let Some(last_pool_id) = api
        .storage()
        .at(block_hash)
        .fetch(&last_pool_id_addr)
        .await?
    {
        let current_index_addr = node_runtime::storage().session().current_index();
        let epoch_index = match api
            .storage()
            .at(block_hash)
            .fetch(&current_index_addr)
            .await?
        {
            Some(index) => index,
            None => return Err("Current session index not defined".into()),
        };

        let mut valid_pool = Some(1);
        while let Some(pool_id) = valid_pool {
            if pool_id > last_pool_id {
                valid_pool = None;
            } else {
                let mut pool_stats = PoolStats::new();
                pool_stats.block_number = block_number;

                let bonded_pools_addr = node_runtime::storage()
                    .nomination_pools()
                    .bonded_pools(&pool_id);
                if let Some(bonded) = api
                    .storage()
                    .at(block_hash)
                    .fetch(&bonded_pools_addr)
                    .await?
                {
                    pool_stats.points = bonded.points;
                    pool_stats.member_counter = bonded.member_counter;

                    // fetch pool stash account staked amount
                    // let stash_account = nomination_pool_account(AccountType::Bonded, pool_id);
                    // let account_addr = node_runtime::storage().system().account(&stash_account);
                    // if let Some(account_info) =
                    //     api.storage().fetch(&account_addr, block_hash).await?
                    // {
                    //     pool_stats.staked = account_info.data.fee_frozen;
                    // }

                    // fetch pool stash account staked amount from staking pallet
                    let stash_account = nomination_pool_account(AccountType::Bonded, pool_id);
                    let ledger_addr = node_runtime::storage().staking().ledger(&stash_account);
                    if let Some(data) = api.storage().at(block_hash).fetch(&ledger_addr).await? {
                        pool_stats.staked = data.active;
                        pool_stats.unbonding = data.total - data.active;
                    }

                    // fetch pool reward account free amount
                    let stash_account = nomination_pool_account(AccountType::Reward, pool_id);
                    let account_addr = node_runtime::storage().system().account(&stash_account);
                    if let Some(account_info) =
                        api.storage().at(block_hash).fetch(&account_addr).await?
                    {
                        pool_stats.reward = account_info.data.free;
                    }

                    // serialize and cache pool
                    let serialized = serde_json::to_string(&pool_stats)?;
                    redis::cmd("SET")
                        .arg(CacheKey::NominationPoolStatsByPoolAndSession(
                            pool_id,
                            epoch_index,
                        ))
                        .arg(serialized)
                        .query_async(&mut cache as &mut Connection)
                        .await
                        .map_err(CacheError::RedisCMDError)?;
                }

                valid_pool = Some(pool_id + 1);
            }
        }
        // Log cache processed duration time
        info!(
            "Pools stats #{} cached ({:?})",
            epoch_index,
            start.elapsed()
        );
    }
    Ok(())
}

pub async fn cache_nomination_pools(
    block_number: BlockNumber,
    block_hash: H256,
) -> Result<(), OnetError> {
    let start = Instant::now();
    let onet: Onet = Onet::new().await;
    let api = onet.client().clone();
    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

    // fetch last pool id
    let last_pool_id_addr = node_runtime::storage().nomination_pools().last_pool_id();
    if let Some(last_pool_id) = api
        .storage()
        .at(block_hash)
        .fetch(&last_pool_id_addr)
        .await?
    {
        let current_index_addr = node_runtime::storage().session().current_index();
        let epoch_index = match api
            .storage()
            .at(block_hash)
            .fetch(&current_index_addr)
            .await?
        {
            Some(index) => index,
            None => return Err("Current session index not defined".into()),
        };

        let mut valid_pool = Some(1);
        while let Some(pool_id) = valid_pool {
            if pool_id > last_pool_id {
                valid_pool = None;
            } else {
                // Load chain data
                let metadata_addr = node_runtime::storage()
                    .nomination_pools()
                    .metadata(&pool_id);
                if let Some(BoundedVec(metadata)) =
                    api.storage().at(block_hash).fetch(&metadata_addr).await?
                {
                    let metadata = str(metadata);
                    let mut pool = Pool::with_id_and_metadata(pool_id, metadata);

                    let bonded_pools_addr = node_runtime::storage()
                        .nomination_pools()
                        .bonded_pools(&pool_id);
                    if let Some(bonded) = api
                        .storage()
                        .at(block_hash)
                        .fetch(&bonded_pools_addr)
                        .await?
                    {
                        let state = match bonded.state {
                            PoolState::Blocked => pools::PoolState::Blocked,
                            PoolState::Destroying => pools::PoolState::Destroying,
                            _ => pools::PoolState::Open,
                        };
                        pool.state = state;

                        // assign roles
                        let mut depositor = Account::with_address(bonded.roles.depositor.clone());
                        depositor.identity =
                            get_identity(&onet, &bonded.roles.depositor, None).await?;
                        let root = if let Some(root) = bonded.roles.root {
                            let mut root_acc = Account::with_address(root.clone());
                            root_acc.identity = get_identity(&onet, &root, None).await?;
                            Some(root_acc)
                        } else {
                            None
                        };
                        let nominator = if let Some(acc) = bonded.roles.nominator {
                            let mut nominator = Account::with_address(acc.clone());
                            nominator.identity = get_identity(&onet, &acc, None).await?;
                            Some(nominator)
                        } else {
                            None
                        };
                        let state_toggler = if let Some(acc) = bonded.roles.bouncer {
                            let mut state_toggler = Account::with_address(acc.clone());
                            state_toggler.identity = get_identity(&onet, &acc, None).await?;
                            Some(state_toggler)
                        } else {
                            None
                        };

                        pool.roles = Some(Roles::with(depositor, root, nominator, state_toggler));
                        pool.block_number = block_number;

                        // serialize and cache pool
                        let serialized = serde_json::to_string(&pool)?;
                        redis::cmd("SET")
                            .arg(CacheKey::NominationPoolRecord(pool_id))
                            .arg(serialized)
                            .query_async(&mut cache as &mut Connection)
                            .await
                            .map_err(CacheError::RedisCMDError)?;
                    }
                }
                // cache pool_id into a sorted set by session
                redis::cmd("ZADD")
                    .arg(CacheKey::NominationPoolIdsBySession(epoch_index))
                    .arg(0)
                    .arg(pool_id)
                    .query_async(&mut cache as &mut Connection)
                    .await
                    .map_err(CacheError::RedisCMDError)?;

                valid_pool = Some(pool_id + 1);
            }
        }
        // Log cache processed duration time
        info!("Pools #{} cached ({:?})", epoch_index, start.elapsed());
    }
    Ok(())
}

async fn try_run_nomination(
    onet: &Onet,
    records: &Records,
    validators: Validators,
) -> Result<String, OnetError> {
    let config = CONFIG.clone();
    let api = onet.client().clone();

    // Load nominator seed account
    let seed = fs::read_to_string(config.pools_nominator_seed_path)
        .expect("Something went wrong reading the pool nominator seed file");
    let signer: Keypair = get_signer_from_seed(&seed, None);

    // create a batch call to nominate both pools
    let mut calls: Vec<Call> = vec![];

    // Define minimum para epochs to be considered in the nomination:
    // NOTE: this should be exactly the same as the minimum used in ranking
    // min_para_epochs = 1 if total_full_epochs < 12;
    // min_para_epochs = 2 if total_full_epochs < 24;
    // min_para_epochs = 3 if total_full_epochs < 36;
    // min_para_epochs = 4 if total_full_epochs < 48;
    // min_para_epochs = 5 if total_full_epochs = 48;
    let min_para_epochs = (records.total_full_epochs() / 12) + 1;

    let tvp_validators = validators
        .iter()
        .filter(|v| {
            v.subset == Subset::TVP && v.para_epochs >= min_para_epochs && v.missed_ratio.is_some()
        })
        .collect::<Vec<&Validator>>();

    // ** Define calls to be included in the batch **

    // Pool 1 should include top TVP validators in the last X sessions
    // Note: maximum validators are 24 in Kusama / 16 Polkadot
    let call = define_first_pool_call(&mut tvp_validators.clone(), None)?;
    calls.push(call);

    if config.pools_second_pool_enabled {
        // Pool 2 should include top TVP validators with the lowest commission in the last X sessions
        // Note: maximum validators are 12 in Kusama / 8 Polkadot
        let call = define_second_pool_call(
            &mut tvp_validators.clone(),
            Some(config.pools_maximum_nominations / 2),
        )?;
        calls.push(call);
    }

    if calls.len() > 0 {
        // Submit batch call with nominations
        let tx = node_runtime::tx().utility().batch(calls).unvalidated();

        let response = api
            .tx()
            .sign_and_submit_then_watch_default(&tx, &signer)
            .await?
            .wait_for_finalized()
            .await?;

        let tx_events = response.fetch_events().await?;

        // Get block number
        let block_number = if let Some(header) = onet
            .rpc()
            .chain_get_header(Some(tx_events.block_hash()))
            .await?
        {
            header.number
        } else {
            0
        };

        let failed_event = tx_events.find_first::<ExtrinsicFailed>()?;

        if let Some(ev) = failed_event {
            return Err(OnetError::PoolError(format!(
                "Nomination for <i>Pool Is {}</i> and <i>{}</i> failed at block #{} with event: {:?}",
                config.pool_id_1, config.pool_id_2, block_number, ev
            )));
        } else {
            let explorer_url = format!(
                "https://{}.subscan.io/extrinsic/{:?}",
                config.chain_name.to_lowercase(),
                tx_events.extrinsic_hash()
            );
            let mut message: String =
                format!("🗳️ Nomination for <i>Pool Id {}</i> ", config.pool_id_1,);
            if config.pools_second_pool_enabled {
                message.push_str(&format!("and <i>Pool Id {}</i> ", config.pool_id_2,));
            }
            message.push_str(&format!(
                "finalized at block #{} (<a href=\"{}\">{}</a>)",
                block_number,
                explorer_url,
                tx_events.extrinsic_hash().to_string()
            ));
            // // Cache pool nomination
            // let unix_now = SystemTime::now()
            //     .duration_since(SystemTime::UNIX_EPOCH)
            //     .unwrap();
            // let pool_nomination = PoolNomination {
            //     id: config.pool_id_1,
            //     sessions_counter: records.total_full_epochs(),
            //     block_number,
            //     extrinsic_hash: tx_events.extrinsic_hash(),
            //     ts: unix_now.as_secs(),
            // };
            // pool_nomination.cache()?;
            // let pool_nomination = PoolNomination {
            //     id: config.pool_id_2,
            //     sessions_counter: records.total_full_epochs(),
            //     block_number,
            //     extrinsic_hash: tx_events.extrinsic_hash(),
            //     ts: unix_now.as_secs(),
            // };
            // pool_nomination.cache()?;
            return Ok(message);
        }
    }
    Err(OnetError::PoolError(
        format!("Nomination for pools ({}, {}) failed since there are No calls for the batch call nomination.", config.pool_id_1,
        config.pool_id_2,),
    ))
}

async fn verify_oversubscribed(
    onet: &Onet,
    era_index: u32,
    stash: &AccountId32,
    block_hash: Option<H256>,
) -> Result<bool, OnetError> {
    let api = onet.client().clone();

    let max_addr = node_runtime::constants()
        .staking()
        .max_nominator_rewarded_per_validator();
    let max: u32 = api.constants().at(&max_addr)?;

    let block_hash = match block_hash {
        Some(bh) => bh,
        None => onet
            .rpc()
            .chain_get_block_hash(None)
            .await?
            .expect("didn't pass a block number; qed"),
    };

    let eras_stakers_addr = node_runtime::storage()
        .staking()
        .eras_stakers(&era_index, stash);
    if let Some(exposure) = api
        .storage()
        .at(block_hash)
        .fetch(&eras_stakers_addr)
        .await?
    {
        return Ok(exposure.others.len() as u32 > max);
    }
    return Ok(false);
}

async fn get_own_stake_via_controller(
    onet: &Onet,
    controller: &AccountId32,
    block_hash: H256,
) -> Result<u128, OnetError> {
    let api = onet.client().clone();

    let ledger_addr = node_runtime::storage().staking().ledger(controller);
    if let Some(ledger) = api.storage().at(block_hash).fetch(&ledger_addr).await? {
        return Ok(ledger.active);
    }
    return Ok(0);
}

async fn get_own_stake_via_stash(onet: &Onet, stash: &AccountId32) -> Result<u128, OnetError> {
    let api = onet.client().clone();

    let bonded_addr = node_runtime::storage().staking().bonded(stash);
    if let Some(controller) = api.storage().at_latest().await?.fetch(&bonded_addr).await? {
        let ledger_addr = node_runtime::storage().staking().ledger(controller);
        if let Some(ledger) = api.storage().at_latest().await?.fetch(&ledger_addr).await? {
            return Ok(ledger.active);
        }
    }
    return Ok(0);
}

async fn get_display_name(onet: &Onet, stash: &AccountId32) -> Result<String, OnetError> {
    if let Some(identity) = get_identity(&onet, &stash, None).await? {
        return Ok(identity.to_string());
    } else {
        let s = &stash.to_string();
        Ok(format!("{}...{}", &s[..6], &s[s.len() - 6..]))
    }
}

#[async_recursion]
async fn get_identity(
    onet: &Onet,
    stash: &AccountId32,
    sub_account_name: Option<String>,
) -> Result<Option<Identity>, OnetError> {
    let api = onet.client().clone();

    let identity_of_addr = node_runtime::storage().identity().identity_of(stash);
    match api
        .storage()
        .at_latest()
        .await?
        .fetch(&identity_of_addr)
        .await?
    {
        Some(identity) => {
            debug!("identity {:?}", identity);
            let parent = parse_identity_data(identity.info.display);
            let identity = match sub_account_name {
                Some(child) => Identity::with_name_and_sub(parent, child),
                None => Identity::with_name(parent),
            };
            Ok(Some(identity))
        }
        None => {
            let super_of_addr = node_runtime::storage().identity().super_of(stash);
            if let Some((parent_account, data)) = api
                .storage()
                .at_latest()
                .await?
                .fetch(&super_of_addr)
                .await?
            {
                let sub_account_name = parse_identity_data(data);
                return get_identity(&onet, &parent_account, Some(sub_account_name.to_string()))
                    .await;
            } else {
                Ok(None)
            }
        }
    }
}

//
fn parse_identity_data(data: Data) -> String {
    match data {
        Data::Raw0(bytes) => str(bytes.to_vec()),
        Data::Raw1(bytes) => str(bytes.to_vec()),
        Data::Raw2(bytes) => str(bytes.to_vec()),
        Data::Raw3(bytes) => str(bytes.to_vec()),
        Data::Raw4(bytes) => str(bytes.to_vec()),
        Data::Raw5(bytes) => str(bytes.to_vec()),
        Data::Raw6(bytes) => str(bytes.to_vec()),
        Data::Raw7(bytes) => str(bytes.to_vec()),
        Data::Raw8(bytes) => str(bytes.to_vec()),
        Data::Raw9(bytes) => str(bytes.to_vec()),
        Data::Raw10(bytes) => str(bytes.to_vec()),
        Data::Raw11(bytes) => str(bytes.to_vec()),
        Data::Raw12(bytes) => str(bytes.to_vec()),
        Data::Raw13(bytes) => str(bytes.to_vec()),
        Data::Raw14(bytes) => str(bytes.to_vec()),
        Data::Raw15(bytes) => str(bytes.to_vec()),
        Data::Raw16(bytes) => str(bytes.to_vec()),
        Data::Raw17(bytes) => str(bytes.to_vec()),
        Data::Raw18(bytes) => str(bytes.to_vec()),
        Data::Raw19(bytes) => str(bytes.to_vec()),
        Data::Raw20(bytes) => str(bytes.to_vec()),
        Data::Raw21(bytes) => str(bytes.to_vec()),
        Data::Raw22(bytes) => str(bytes.to_vec()),
        Data::Raw23(bytes) => str(bytes.to_vec()),
        Data::Raw24(bytes) => str(bytes.to_vec()),
        Data::Raw25(bytes) => str(bytes.to_vec()),
        Data::Raw26(bytes) => str(bytes.to_vec()),
        Data::Raw27(bytes) => str(bytes.to_vec()),
        Data::Raw28(bytes) => str(bytes.to_vec()),
        Data::Raw29(bytes) => str(bytes.to_vec()),
        Data::Raw30(bytes) => str(bytes.to_vec()),
        Data::Raw31(bytes) => str(bytes.to_vec()),
        Data::Raw32(bytes) => str(bytes.to_vec()),
        _ => format!("???"),
    }
}

fn str(bytes: Vec<u8>) -> String {
    format!("{}", String::from_utf8_lossy(&bytes))
}

async fn get_authority_index(
    onet: &Onet,
    block_hash: Option<H256>,
) -> Result<Option<AuthorityIndex>, OnetError> {
    if let Some(header) = onet.rpc().chain_get_header(block_hash).await? {
        match header.digest {
            Digest { logs } => {
                for digests in logs.iter() {
                    match digests {
                        DigestItem::PreRuntime(_, data) => {
                            if let Some(pre) = PreDigest::decode(&mut &data[..]).ok() {
                                match pre {
                                    PreDigest::Primary(e) => return Ok(Some(e.authority_index)),
                                    PreDigest::SecondaryPlain(e) => {
                                        return Ok(Some(e.authority_index))
                                    }
                                    PreDigest::SecondaryVRF(e) => {
                                        return Ok(Some(e.authority_index))
                                    }
                                }
                            }
                        }
                        _ => (),
                    }
                }
            }
        }
    }
    Ok(None)
}

pub async fn try_run_cache_session_stats_records(
    block_hash: H256,
    is_loading: bool,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.cache_writer_enabled {
        async_std::task::spawn(async move {
            if let Err(e) = cache_session_stats_records(block_hash, is_loading).await {
                error!("try_run_cache_session_stats_records error: {:?}", e);
            }
        });
    }

    Ok(())
}

/// ---
/// cache all validators profile and snapshot session stats at the last block of the session
pub async fn cache_session_stats_records(
    block_hash: H256,
    is_loading: bool,
) -> Result<(), OnetError> {
    let start = Instant::now();
    let config = CONFIG.clone();
    let onet: Onet = Onet::new().await;
    let api = onet.client().clone();
    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

    // Load network details
    let network = Network::load(onet.rpc()).await?;

    // ---
    // cache all validators profile every new session and snapshot session stats

    if let Some(block) = onet.rpc().chain_get_header(Some(block_hash)).await? {
        let active_era_addr = node_runtime::storage().staking().active_era();
        let era_index = match api
            .storage()
            .at(block.parent_hash)
            .fetch(&active_era_addr)
            .await?
        {
            Some(info) => info.index,
            None => return Err("Active era not defined".into()),
        };

        let current_index_addr = node_runtime::storage().session().current_index();
        let epoch_index = match api
            .storage()
            .at(block.parent_hash)
            .fetch(&current_index_addr)
            .await?
        {
            Some(index) => index,
            None => return Err("Current session index not defined".into()),
        };

        // initialize network stats (cached syncing status)
        let mut nss = NetworkSessionStats::new(epoch_index, (block.number - 1) as u64);

        // Initialize validators vec
        let mut validators: Vec<ValidatorProfileRecord> = Vec::new();

        // Collect Nominators data (** heavy duty task **)
        let nominators_map = collect_nominators_data(&onet, block.parent_hash).await?;

        // Load TVP stashes
        let tvp_stashes: Vec<AccountId32> = try_fetch_stashes_from_remote_url(is_loading).await?;

        // Fetch active validators
        let authorities_addr = node_runtime::storage().session().validators();
        if let Some(authorities) = api
            .storage()
            .at(block.parent_hash)
            .fetch(&authorities_addr)
            .await?
        {
            // Fetch all validators
            let validators_addr = node_runtime::storage().staking().validators_iter();
            let mut iter = api
                .storage()
                .at(block.parent_hash)
                .iter(validators_addr)
                .await?;
            while let Some(Ok((key, validator_prefs))) = iter.next().await {
                // validator stash address
                let stash = get_account_id_from_storage_key(key);
                // create a new validator instance
                let mut v = ValidatorProfileRecord::new(stash.clone());
                // validator controller address
                let bonded_addr = node_runtime::storage().staking().bonded(&stash);
                if let Some(controller) = api
                    .storage()
                    .at(block.parent_hash)
                    .fetch(&bonded_addr)
                    .await?
                {
                    v.controller = Some(controller.clone());
                    // get own stake
                    v.own_stake =
                        get_own_stake_via_controller(&onet, &controller, block.parent_hash).await?;

                    // deconstruct commisssion
                    let Perbill(commission) = validator_prefs.commission;
                    v.commission = commission;

                    // verify subset (1_000_000_000 = 100% commission)
                    v.subset = if commission != 1_000_000_000 {
                        if !tvp_stashes.contains(&stash) {
                            Subset::NONTVP
                        } else {
                            Subset::TVP
                        }
                    } else {
                        Subset::C100
                    };

                    // check if is oversubscribed
                    v.is_oversubscribed =
                        verify_oversubscribed(&onet, era_index, &stash, Some(block.parent_hash))
                            .await?;

                    // check if is in active set
                    v.is_active = authorities.contains(&stash);

                    // calculate session mvr and avg it with previous value
                    v.mvr = try_calculate_avg_mvr_by_session_and_stash(
                        &onet,
                        epoch_index,
                        stash.clone(),
                    )
                    .await?;
                    // keep track of when mvr was updated
                    if v.mvr.is_some() {
                        v.mvr_session = Some(epoch_index);
                    }

                    // check if block nominations
                    v.is_blocked = validator_prefs.blocked;

                    // get identity
                    v.identity = get_identity(&onet, &stash, None).await?;

                    // set nominators data
                    if let Some(nominators) = nominators_map.get(&stash) {
                        // TODO: Perhaps keep nominator stashes in a different struct
                        // let nominators_stashes = nominators
                        //     .iter()
                        //     .map(|(x, _, _)| x.to_string())
                        //     .collect::<Vec<String>>()
                        //     .join(",");

                        v.nominators_stake = nominators.iter().map(|(_, x, _)| x).sum();
                        v.nominators_raw_stake = nominators.iter().map(|(_, x, y)| x / y).sum();
                        v.nominators_counter = nominators.len().try_into().unwrap();
                    }

                    let serialized = serde_json::to_string(&v)?;
                    redis::pipe()
                        .atomic()
                        .cmd("SET")
                        .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
                        .arg(serialized)
                        .cmd("EXPIRE")
                        .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
                        .arg(config.cache_writer_prunning)
                        .cmd("SADD")
                        .arg(CacheKey::ValidatorAccountsBySession(epoch_index))
                        .arg(stash.to_string())
                        .cmd("EXPIRE")
                        .arg(CacheKey::ValidatorAccountsBySession(epoch_index))
                        .arg(config.cache_writer_prunning)
                        // cache own_stake rank
                        .cmd("ZADD")
                        .arg(CacheKey::NomiBoardBySessionAndTrait(
                            epoch_index,
                            Trait::OwnStake,
                        ))
                        .arg(
                            v.own_stake_trimmed(network.token_decimals as u32)
                                .to_string(),
                        ) // score
                        .arg(stash.to_string())
                        .cmd("EXPIRE")
                        .arg(CacheKey::NomiBoardBySessionAndTrait(
                            epoch_index,
                            Trait::OwnStake,
                        ))
                        .arg(config.cache_writer_prunning)
                        // cache nominators_stake rank
                        .cmd("ZADD")
                        .arg(CacheKey::NomiBoardBySessionAndTrait(
                            epoch_index,
                            Trait::NominatorsStake,
                        ))
                        .arg(
                            v.nominators_stake_trimmed(network.token_decimals as u32)
                                .to_string(),
                        ) // score
                        .arg(stash.to_string())
                        .cmd("EXPIRE")
                        .arg(CacheKey::NomiBoardBySessionAndTrait(
                            epoch_index,
                            Trait::NominatorsStake,
                        ))
                        .arg(config.cache_writer_prunning)
                        // cache nominators_counter rank
                        .cmd("ZADD")
                        .arg(CacheKey::NomiBoardBySessionAndTrait(
                            epoch_index,
                            Trait::NominatorsCounter,
                        ))
                        .arg(v.nominators_counter.to_string()) // score
                        .arg(stash.to_string())
                        .cmd("EXPIRE")
                        .arg(CacheKey::NomiBoardBySessionAndTrait(
                            epoch_index,
                            Trait::NominatorsCounter,
                        ))
                        .arg(config.cache_writer_prunning)
                        .query_async(&mut cache as &mut Connection)
                        .await
                        .map_err(CacheError::RedisCMDError)?;

                    validators.push(v);
                }
            }

            // track chilled nodes by checking if a session authority is no longer part of the validator list
            for stash in authorities.iter() {
                if validators
                    .iter()
                    .find(|&p| p.stash.as_ref().unwrap() == stash)
                    .is_none()
                {
                    // mark validator has chilled
                    let v: ValidatorProfileRecord = if let Ok(serialized_data) = redis::cmd("GET")
                        .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
                        .query_async::<Connection, String>(&mut cache as &mut Connection)
                        .await
                    {
                        let mut v: ValidatorProfileRecord =
                            serde_json::from_str(&serialized_data).unwrap_or_default();
                        v.is_chilled = true;
                        v
                    } else {
                        let mut v = ValidatorProfileRecord::new(stash.clone());
                        v.identity = get_identity(&onet, &stash, None).await?;
                        v.is_chilled = true;
                        v
                    };
                    let serialized = serde_json::to_string(&v)?;
                    redis::cmd("SET")
                        .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
                        .arg(serialized)
                        .query_async(&mut cache as &mut Connection)
                        .await
                        .map_err(CacheError::RedisCMDError)?;
                    //
                    validators.push(v);
                }
            }

            nss.total_vals_chilled = validators
                .iter_mut()
                .filter(|v| v.is_chilled)
                .count()
                .try_into()
                .unwrap();

            // Fetch Era reward points
            let era_reward_points_addr = node_runtime::storage()
                .staking()
                .eras_reward_points(&era_index);
            if let Some(era_reward_points) = api
                .storage()
                .at(block.parent_hash)
                .fetch(&era_reward_points_addr)
                .await?
            {
                nss.total_reward_points = era_reward_points.total;

                for (stash, points) in era_reward_points.individual.iter() {
                    validators
                        .iter_mut()
                        .filter(|v| v.stash.is_some())
                        .filter(|v| *(v.stash.as_ref().unwrap()) == *stash)
                        .for_each(|v| {
                            (*v).points = *points;
                        });
                }
            }

            // build stats
            //
            // general session stats
            // total issuance
            let total_issuance_addr = node_runtime::storage().balances().total_issuance();
            if let Some(total_issuance) = api
                .storage()
                .at(block.parent_hash)
                .fetch(&total_issuance_addr)
                .await?
            {
                nss.total_issuance = total_issuance;
            };

            // total staked
            let eras_total_stake_addr = node_runtime::storage()
                .staking()
                .eras_total_stake(&era_index);
            if let Some(total_staked) = api
                .storage()
                .at(block.parent_hash)
                .fetch(&eras_total_stake_addr)
                .await?
            {
                nss.total_staked = total_staked;
            };

            // total rewarded from previous era
            let eras_total_reward_addr = node_runtime::storage()
                .staking()
                .eras_validator_reward(&era_index - 1);
            if let Some(last_rewarded) = api
                .storage()
                .at(block.parent_hash)
                .fetch(&eras_total_reward_addr)
                .await?
            {
                nss.last_rewarded = last_rewarded;
            };

            let subsets = vec![Subset::C100, Subset::NONTVP, Subset::TVP];
            for subset in subsets {
                let mut ss = SubsetStats::new(subset.clone());

                // all validators
                ss.vals_total = validators
                    .iter()
                    .filter(|v| v.subset == subset)
                    .count()
                    .try_into()
                    .unwrap();

                // active validators
                ss.vals_active = validators
                    .iter()
                    .filter(|v| v.is_active && v.subset == subset)
                    .count()
                    .try_into()
                    .unwrap();

                // own stake
                let own_stakes: Vec<u128> = validators
                    .iter()
                    .filter(|v| v.subset == subset)
                    .map(|v| v.own_stake)
                    .collect();

                ss.vals_own_stake_total = own_stakes.iter().sum::<u128>();
                ss.vals_own_stake_avg = own_stakes.iter().sum::<u128>() / own_stakes.len() as u128;
                ss.vals_own_stake_min = *own_stakes.iter().min().unwrap_or_else(|| &0);
                ss.vals_own_stake_max = *own_stakes.iter().max().unwrap_or_else(|| &0);

                // oversubscribed
                ss.vals_oversubscribed = validators
                    .iter()
                    .filter(|v| v.is_oversubscribed && v.subset == subset)
                    .count()
                    .try_into()
                    .unwrap();

                // points
                let points: Vec<u32> = validators
                    .iter()
                    .filter(|v| v.subset == subset)
                    .map(|v| v.points)
                    .collect();

                ss.vals_points_total = points.iter().sum::<u32>();
                ss.vals_points_avg = points.iter().sum::<u32>() / points.len() as u32;
                ss.vals_points_min = *points.iter().min().unwrap_or_else(|| &0);
                ss.vals_points_max = *points.iter().max().unwrap_or_else(|| &0);

                // TODO: flagged (grade F) and exceptional A+ validators

                nss.subsets.push(ss);
            }

            // serialize and cache
            let serialized = serde_json::to_string(&nss)?;
            redis::pipe()
                .atomic()
                .cmd("SET")
                .arg(CacheKey::NetworkStatsBySession(Index::Num(
                    epoch_index.into(),
                )))
                .arg(serialized)
                .cmd("EXPIRE")
                .arg(CacheKey::NetworkStatsBySession(Index::Num(
                    epoch_index.into(),
                )))
                .arg(config.cache_writer_prunning)
                .query_async(&mut cache as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;

            // Log sesssion cache processed duration time
            info!(
                "Session #{} stats cached ({:?})",
                epoch_index,
                start.elapsed()
            );
        }

        // Set synced session associated with era (useful for nomi boards)
        let mut era_data: BTreeMap<String, String> = BTreeMap::new();
        era_data.insert(String::from("synced_session"), epoch_index.to_string());
        era_data.insert(
            String::from(format!("synced_at_block:{}", epoch_index)),
            (block.number - 1).to_string(),
        );

        // Build session limits
        let limits = build_limits_from_session(&onet.cache.clone(), epoch_index).await?;
        let limits_serialized = serde_json::to_string(&limits)?;

        // Set era and limits associated with session (useful for nomi boards)
        let mut session_data: BTreeMap<String, String> = BTreeMap::new();
        session_data.insert(String::from("era"), era_index.to_string());
        session_data.insert(String::from("limits"), limits_serialized.to_string());

        // by `epoch_index`
        redis::pipe()
            .atomic()
            .cmd("HSET")
            .arg(CacheKey::EraByIndex(Index::Num(era_index.into())))
            .arg(era_data)
            .cmd("EXPIRE")
            .arg(CacheKey::EraByIndex(Index::Num(era_index.into())))
            .arg(config.cache_writer_prunning)
            .cmd("HSET")
            .arg(CacheKey::NomiBoardEraBySession(epoch_index))
            .arg(session_data)
            .cmd("EXPIRE")
            .arg(CacheKey::NomiBoardEraBySession(epoch_index))
            .arg(config.cache_writer_prunning)
            .cmd("SET")
            .arg(CacheKey::EraByIndex(Index::Current))
            .arg(era_index.to_string())
            .query_async(&mut cache as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;
    }

    Ok(())
}

async fn collect_nominators_data(
    onet: &Onet,
    block_hash: H256,
) -> Result<BTreeMap<AccountId32, Vec<(AccountId32, u128, u128)>>, OnetError> {
    let start = Instant::now();
    let api = onet.client().clone();

    // BTreeMap<AccountId32, Vec<(AccountId32, u128, u32)>> = validator_stash : [(nominator_stash, nominator_total_stake, number_of_nominations)]
    let mut nominators_map: BTreeMap<AccountId32, Vec<(AccountId32, u128, u128)>> = BTreeMap::new();

    let mut counter = 0;
    let storage_addr = node_runtime::storage().staking().nominators_iter();
    let mut iter = api.storage().at(block_hash).iter(storage_addr).await?;
    while let Some(Ok((key, nominations))) = iter.next().await {
        let nominator_stash = get_account_id_from_storage_key(key);
        let bonded_addr = node_runtime::storage()
            .staking()
            .bonded(&nominator_stash.clone());
        if let Some(controller) = api.storage().at_latest().await?.fetch(&bonded_addr).await? {
            let ledger_addr = node_runtime::storage().staking().ledger(&controller);
            let nominator_stake =
                if let Some(ledger) = api.storage().at_latest().await?.fetch(&ledger_addr).await? {
                    ledger.total
                } else {
                    0
                };

            let BoundedVec(targets) = nominations.targets.clone();
            for target in targets.iter() {
                let n = nominators_map.entry(target.clone()).or_insert(vec![]);
                n.push((
                    nominator_stash.clone(),
                    nominator_stake,
                    targets.len().try_into().unwrap(),
                ));
            }
        }
        counter += 1;
    }
    info!(
        "Total Nominators {} collected ({:?})",
        counter,
        start.elapsed()
    );
    Ok(nominators_map)
}

pub async fn try_calculate_avg_mvr_by_session_and_stash(
    onet: &Onet,
    session_index: EpochIndex,
    stash: AccountId32,
) -> Result<Option<u64>, OnetError> {
    let mut conn = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

    if let Ok(value) = redis::cmd("GET")
        .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
        .query_async::<Connection, redis::Value>(&mut conn as &mut Connection)
        .await
    {
        match value {
            redis::Value::Data(data) => {
                let serialized_data = String::from_utf8(data).expect("Data should be valid utf8");
                let v: ValidatorProfileRecord = serde_json::from_str(&serialized_data)
                    .expect("Serialized data should be a valid profile record");
                match v.mvr {
                    Some(previous_mvr) => {
                        if let Some(latest_mvr) =
                            calculate_mvr_by_session_and_stash(&onet, session_index, stash.clone())
                                .await?
                        {
                            return Ok(Some((previous_mvr + latest_mvr) / 2));
                        }
                        return Ok(Some(previous_mvr));
                    }
                    None => {
                        return calculate_mvr_by_session_and_stash(
                            &onet,
                            session_index,
                            stash.clone(),
                        )
                        .await
                    }
                }
            }
            _ => return Ok(None),
        }
    };

    calculate_mvr_by_session_and_stash(&onet, session_index, stash.clone()).await
}

pub async fn calculate_mvr_by_session_and_stash(
    onet: &Onet,
    session_index: EpochIndex,
    stash: AccountId32,
) -> Result<Option<u64>, OnetError> {
    let mut conn = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

    use crate::api::responses::{AuthorityKey, AuthorityKeyCache};
    use crate::mcda::scores::base_decimals;

    if let Ok(authority_key_data) = redis::cmd("HGETALL")
        .arg(CacheKey::AuthorityKeyByAccountAndSession(
            stash.clone(),
            session_index,
        ))
        .query_async::<Connection, AuthorityKeyCache>(&mut conn as &mut Connection)
        .await
    {
        if !authority_key_data.is_empty() {
            let auth_key: AuthorityKey = authority_key_data.clone().into();
            if let Ok(serialized) = redis::cmd("HGET")
                .arg(CacheKey::AuthorityRecordVerbose(
                    auth_key.to_string(),
                    Verbosity::Summary,
                ))
                .arg("para_summary".to_string())
                .query_async::<Connection, String>(&mut conn as &mut Connection)
                .await
            {
                let para_summary: ParaStats = serde_json::from_str(&serialized).unwrap_or_default();

                let denominator = para_summary.explicit_votes
                    + para_summary.implicit_votes
                    + para_summary.missed_votes;

                if denominator > 0 {
                    return Ok(Some(
                        (base_decimals() * para_summary.missed_votes as u64) / denominator as u64,
                    ));
                };
            }
        }
    }

    Ok(None)
}
