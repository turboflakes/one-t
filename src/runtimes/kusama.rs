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
use crate::cache::{CacheKey, Index};
use crate::config::CONFIG;
use crate::errors::{CacheError, OnetError};
use crate::matrix::FileInfo;
use crate::onet::ReportType;
use crate::onet::{
    get_account_id_from_storage_key, get_from_seed, get_subscribers, get_subscribers_by_epoch,
    try_fetch_stashes_from_remote_url, Onet, EPOCH_FILENAME,
};
use crate::pools::{Nominee, Pool, PoolNomination, PoolNominees, PoolsEra};
use crate::records::{
    decode_authority_index, AuthorityIndex, AuthorityRecord, EpochIndex, EpochKey, EraIndex,
    ParaId, ParaRecord, ParaStats, Points, Records, Subscribers, Votes,
};
use crate::report::{
    Callout, Metadata, Network, RawData, RawDataGroup, RawDataPara, RawDataParachains,
    RawDataPools, RawDataRank, Report, Subset, Validator, Validators,
};
use redis::aio::Connection;

use async_recursion::async_recursion;
use futures::StreamExt;
use log::{debug, error, info, warn};
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    fs,
    iter::FromIterator,
    result::Result,
    thread, time,
    time::SystemTime,
};
use subxt::{
    sp_core::sr25519, sp_runtime::AccountId32, DefaultConfig, PairSigner, PolkadotExtrinsicParams,
};

#[subxt::subxt(
    runtime_metadata_path = "metadata/kusama_metadata.scale",
    derive_for_all_types = "PartialEq, Clone"
)]
mod node_runtime {}

use node_runtime::{
    runtime_types::{
        sp_runtime::bounded::bounded_vec::BoundedVec, pallet_identity::types::Data,
        polkadot_parachain::primitives::Id, polkadot_primitives::v2::CoreIndex,
        polkadot_primitives::v2::GroupIndex, polkadot_primitives::v2::ValidatorIndex,
        polkadot_primitives::v2::ValidityAttestation, sp_arithmetic::per_things::Perbill,
    },
    session::events::NewSession,
    system::events::ExtrinsicFailed,
};

type Api = node_runtime::RuntimeApi<DefaultConfig, PolkadotExtrinsicParams<DefaultConfig>>;
type Call = node_runtime::runtime_types::kusama_runtime::Call;
type NominationPoolsCall = node_runtime::runtime_types::pallet_nomination_pools::pallet::Call;

pub async fn init_and_subscribe_on_chain_events(onet: &Onet) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();

    let block_hash = api.client.rpc().block_hash(None).await?;

    let mut block_number =
        match api.client.rpc().block(block_hash).await? {
            Some(signed_block) => signed_block.block.header.number,
            None => return Err(
                "Block hash not available. Check current API -> api.client.rpc().block(block_hash)"
                    .into(),
            ),
        };

    // Fetch active era index
    let era_index = match api.storage().staking().active_era(None).await? {
        Some(active_era_info) => active_era_info.index,
        None => return Err("Active era not available. Check current API -> api.storage().staking().active_era(None)".into()),
    };

    // Cache Nomination pools
    try_run_cache_pools_era(era_index, false).await?;

    // Fetch current session index
    let session_index = api.storage().session().current_index(None).await?;
    // Cache current epoch
    let epoch_filename = format!("{}{}", config.data_path, EPOCH_FILENAME);
    fs::write(&epoch_filename, session_index.to_string())?;

    // Subscribers
    let mut subscribers = Subscribers::with_era_and_epoch(era_index, session_index);
    // Initialized subscribers
    if let Ok(subs) = get_subscribers() {
        for (account, user_id) in subs.iter() {
            subscribers.subscribe(account.clone(), user_id.to_string());
        }
    }

    // Records
    let mut records =
        Records::with_era_epoch_and_block(era_index, session_index, block_number.into());

    // Initialize subscribers records
    initialize_records(&onet, &mut records).await?;

    // Initialize cache
    cache_session_records(&onet, &records).await?;
    cache_track_records(&onet, &records).await?;

    // Subscribe to any events that occur:
    let mut sub = api.events().subscribe().await?;

    while let Some(events) = sub.next().await {
        let events = events?;
        let block_hash = events.block_hash();

        if let Some(signed_block) = api.client.rpc().block(Some(block_hash)).await? {
            if let Some(authority_index) = decode_authority_index(&signed_block) {
                // Note: just a safeguard so that records are not tracked again if block was already received
                if signed_block.block.header.number > block_number {
                    info!("Block #{} received", signed_block.block.header.number);
                    block_number = signed_block.block.header.number;

                    // Update records
                    track_records(&onet, authority_index, &mut records).await?;

                    if let Some(new_session_event) = events.find_first::<NewSession>()? {
                        info!("{:?}", new_session_event);

                        switch_new_session(
                            &onet,
                            block_number,
                            new_session_event.session_index,
                            &mut subscribers,
                            &mut records,
                        )
                        .await?;

                        // Network public report
                        try_run_network_report(new_session_event.session_index, &records).await?;

                        // Cache records every new session
                        cache_session_records(&onet, &records).await?;
                    }

                    // Update current block number
                    records.set_current_block_number(block_number.into());

                    // Cache pools every minute
                    try_run_cache_pools_data(&onet, block_number).await?;

                    // Cache records at every block
                    cache_track_records(&onet, &records).await?;
                } else {
                    warn!(
                        "Block #{} already received!",
                        signed_block.block.header.number
                    );
                }
            }
        }
    }
    // If subscription has closed for some reason await and subscribe again
    Err(OnetError::SubscriptionFinished)
}

pub async fn cache_track_records(onet: &Onet, records: &Records) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.api_enabled {
        let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

        // cache records every new block
        if let Some(block) = records.current_block() {
            redis::cmd("SET")
                .arg(CacheKey::BestBlock)
                .arg(*block)
                .query_async(&mut cache as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;

            let current_era = records.current_era();
            let current_epoch = records.current_epoch();
            if let Some(authorities) = records.get_authorities(None) {
                for authority_idx in authorities.iter() {
                    if let Some(authority_record) =
                        records.get_authority_record(*authority_idx, None)
                    {
                        let mut data: BTreeMap<String, String> = BTreeMap::new();
                        if let Some(para_record) = records.get_para_record(*authority_idx, None) {
                            let serialized = serde_json::to_string(&para_record)?;
                            data.insert(String::from("para"), serialized);
                        }
                        let serialized = serde_json::to_string(&authority_record)?;
                        data.insert(String::from("auth"), serialized);
                        redis::cmd("HSET")
                            .arg(CacheKey::AuthorityRecord(
                                current_era,
                                current_epoch,
                                *authority_idx,
                            ))
                            .arg(data)
                            .query_async(&mut cache as &mut Connection)
                            .await
                            .map_err(CacheError::RedisCMDError)?;
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn cache_session_records(onet: &Onet, records: &Records) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.api_enabled {
        let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

        // cache records every new session
        let current_era = records.current_era();
        let current_epoch = records.current_epoch();
        // --- Cache SessionByIndex -> `current` or `epoch_index` (to be able to search history)
        if let Some(block) = records.start_block(None) {
            let mut data: BTreeMap<String, String> = BTreeMap::new();
            data.insert(String::from("era"), records.current_era().to_string());
            data.insert(String::from("session"), records.current_epoch().to_string());
            data.insert(String::from("start_block"), (*block).to_string());

            // by `current`
            redis::cmd("HSET")
                .arg(CacheKey::SessionByIndex(Index::Str(String::from(
                    "current",
                ))))
                .arg(data.clone())
                .query_async(&mut cache as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;

            // by `epoch_index`
            redis::cmd("HSET")
                .arg(CacheKey::SessionByIndex(Index::Num(
                    records.current_epoch(),
                )))
                .arg(data)
                .query_async(&mut cache as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;
        }
        // ---
        // cache authorities every new session
        if let Some(authorities) = records.get_authorities(None) {
            for authority_idx in authorities.iter() {
                if let Some(authority_record) = records.get_authority_record(*authority_idx, None) {
                    let identity =
                        get_display_name(&onet, &authority_record.address(), None).await?;
                    // cache authority key for the current era and session
                    // along with data_type and identity
                    let mut data: BTreeMap<String, String> = BTreeMap::new();
                    data.insert(String::from("identity"), identity);
                    data.insert(
                        String::from("address"),
                        (&authority_record.address()).to_string(),
                    );
                    data.insert(String::from("session"), records.current_epoch().to_string());
                    redis::cmd("HSET")
                        .arg(CacheKey::AuthorityRecord(
                            current_era,
                            current_epoch,
                            *authority_idx,
                        ))
                        .arg(data)
                        .query_async(&mut cache as &mut Connection)
                        .await
                        .map_err(CacheError::RedisCMDError)?;
                    // cache authority key by stash account
                    let mut data: BTreeMap<String, String> = BTreeMap::new();
                    data.insert(String::from("era"), current_era.to_string());
                    data.insert(String::from("session"), current_epoch.to_string());
                    data.insert(String::from("authority"), (*authority_idx).to_string());
                    redis::cmd("HSET")
                        .arg(CacheKey::AuthorityKeyByAccountAndSession(
                            authority_record.address().clone(),
                            current_epoch,
                        ))
                        .arg(data)
                        .query_async(&mut cache as &mut Connection)
                        .await
                        .map_err(CacheError::RedisCMDError)?;
                    // cache authority key into authorities by session to be easily filtered
                    let _: () = redis::cmd("SADD")
                        .arg(CacheKey::AuthorityKeysBySession(current_epoch))
                        .arg(
                            CacheKey::AuthorityRecord(current_era, current_epoch, *authority_idx)
                                .to_string(),
                        )
                        .query_async(&mut cache as &mut Connection)
                        .await
                        .map_err(CacheError::RedisCMDError)?;
                    if records.get_para_record(*authority_idx, None).is_some() {
                        // cache authority key into authorities by session (only para_validators) to be easily filtered
                        let _: () = redis::cmd("SADD")
                            .arg(CacheKey::AuthorityKeysBySessionParaOnly(current_epoch))
                            .arg(
                                CacheKey::AuthorityRecord(
                                    current_era,
                                    current_epoch,
                                    *authority_idx,
                                )
                                .to_string(),
                            )
                            .query_async(&mut cache as &mut Connection)
                            .await
                            .map_err(CacheError::RedisCMDError)?;
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn initialize_records(onet: &Onet, records: &mut Records) -> Result<(), OnetError> {
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();

    // Fetch Era reward points
    let era_reward_points = api
        .storage()
        .staking()
        .eras_reward_points(&records.current_era(), None)
        .await?;

    // Fetch active validators
    let authorities = api.storage().session().validators(None).await?;

    // Fetch para validator groups
    let validator_groups = api
        .storage()
        .para_scheduler()
        .validator_groups(None)
        .await?;

    // Fetch para validator indices
    let active_validator_indices = api
        .storage()
        .paras_shared()
        .active_validator_indices(None)
        .await?;

    // Update records groups with respective authorities
    for (group_idx, group) in validator_groups.iter().enumerate() {
        let auths: Vec<AuthorityIndex> = group
            .into_iter()
            .map(|ValidatorIndex(i)| {
                let ValidatorIndex(auth_idx) = active_validator_indices.get(*i as usize).unwrap();
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
                                let points = if let Some((_s, points)) = era_reward_points
                                    .individual
                                    .iter()
                                    .find(|(s, _p)| s == address)
                                {
                                    *points
                                } else {
                                    0
                                };

                                // Get the number of authored_blocks already authored for the current session
                                let authored_blocks = api
                                    .storage()
                                    .im_online()
                                    .authored_blocks(&records.current_epoch(), &address, None)
                                    .await?;

                                // Define AuthorityRecord
                                let authority_record =
                                    AuthorityRecord::with_index_address_points_and_blocks(
                                        *auth_idx,
                                        address.clone(),
                                        points,
                                        authored_blocks,
                                    );

                                // Find authority indexes for peers
                                let peers: Vec<AuthorityIndex> = group
                                    .into_iter()
                                    .filter(|ValidatorIndex(i)| i != para_idx)
                                    .map(|ValidatorIndex(i)| {
                                        let ValidatorIndex(peer_auth_idx) =
                                            active_validator_indices.get(*i as usize).unwrap();
                                        *peer_auth_idx
                                    })
                                    .collect();

                                // Define ParaRecord
                                let para_record = ParaRecord::with_index_group_and_peers(
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
            let points = if let Some((_s, points)) = era_reward_points
                .individual
                .iter()
                .find(|(s, _p)| s == stash)
            {
                *points
            } else {
                0
            };

            // Get the number of authored_blocks already authored for the current session
            let authored_blocks = api
                .storage()
                .im_online()
                .authored_blocks(&records.current_epoch(), &stash, None)
                .await?;

            let authority_record = AuthorityRecord::with_index_address_points_and_blocks(
                auth_idx,
                stash.clone(),
                points,
                authored_blocks,
            );

            records.insert(stash, auth_idx, authority_record, None);
        }
    }

    // debug!("records {:?}", records);
    Ok(())
}

pub async fn switch_new_session(
    onet: &Onet,
    block_number: u32,
    new_session_index: EpochIndex,
    subscribers: &mut Subscribers,
    records: &mut Records,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();

    // keep previous era in context
    let previous_era_index = records.current_era().clone();

    // Fetch active era index
    let current_era_index = match api.storage().staking().active_era(None).await? {
        Some(active_era_info) => active_era_info.index,
        None => return Err("Active era not available".into()),
    };

    // Update records current Era and Epoch
    records.start_new_epoch(current_era_index, new_session_index);
    // Update records current block number
    records.set_current_block_number(block_number.into());

    // Update subscribers current Era and Epoch
    subscribers.start_new_epoch(current_era_index, new_session_index);

    if let Ok(subs) = get_subscribers() {
        for (account, user_id) in subs.iter() {
            subscribers.subscribe(account.clone(), user_id.to_string());
        }
    }

    // Initialize records for new epoch
    initialize_records(&onet, records).await?;

    // Remove older keys, default is maximum_history_eras + 1
    records.remove(EpochKey(
        records.current_era() - config.maximum_history_eras + 1,
        records.current_epoch() - ((config.maximum_history_eras + 1) * 6),
    ));
    subscribers.remove(EpochKey(
        records.current_era() - config.maximum_history_eras + 1,
        records.current_epoch() - ((config.maximum_history_eras + 1) * 6),
    ));

    // Send reports from previous session
    let era_index: u32 = if current_era_index != previous_era_index {
        previous_era_index
    } else {
        current_era_index
    };

    // try to run matrix reports
    if !config.matrix_disabled {
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
    authority_index: AuthorityIndex,
    records: &mut Records,
) -> Result<(), OnetError> {
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();

    // Fetch on chain votes
    let on_chain_votes = api.storage().para_inherent().on_chain_votes(None).await?;

    // Fetch currently scheduled cores
    let scheduled_cores = api.storage().para_scheduler().scheduled(None).await?;

    // Update records para_group
    for core_assignment in scheduled_cores.iter() {
        debug!("core_assignment: {:?}", core_assignment);
        // CoreAssignment { core: CoreIndex(16), para_id: Id(2087), kind: Parachain, group_idx: GroupIndex(31) }

        // Destructure GroupIndex
        let GroupIndex(group_idx) = core_assignment.group_idx;
        // Destructure CoreIndex
        let CoreIndex(core) = core_assignment.core;
        // Destructure Id
        let Id(para_id) = core_assignment.para_id;

        records.update_para_group(para_id, core, group_idx);
    }

    // Fetch Era reward points
    let era_reward_points = api
        .storage()
        .staking()
        .eras_reward_points(&records.current_era(), None)
        .await?;

    let current_session = records.current_epoch();

    if let Some(authorities) = records.get_authorities(None) {
        // Find groupIdx and peers for each authority
        for authority_idx in authorities.iter() {
            if let Some(authority_record) = records.get_mut_authority_record(*authority_idx) {
                // Increment authored blocks if it is the current block author
                if authority_index == *authority_idx {
                    authority_record.inc_authored_blocks();
                }

                // Collect current points
                let current_points = if let Some((_s, points)) = era_reward_points
                    .individual
                    .iter()
                    .find(|(s, _p)| s == authority_record.address())
                {
                    *points
                } else {
                    0
                };
                // Update authority current points and get the difference
                let diff_points = authority_record.update_current_points(current_points);

                if let Some(para_record) = records.get_mut_para_record(*authority_idx) {
                    // 1st. Increment current para_id diff_points and authored blocks if the author of the finalized block
                    para_record.update_points(diff_points, authority_index == *authority_idx);

                    // 2nd. Check if the para_id assigned to this authority got any on chain votes
                    if let Some(ref backing_votes) = on_chain_votes {
                        // Verify that records are in the same session as on chain votes
                        if current_session == backing_votes.session {
                            for (candidate_receipt, group_authorities) in
                                backing_votes.backing_validators_per_candidate.iter()
                            {
                                debug!(
                                    "para_id: {:?} group_authorities {:?}",
                                    candidate_receipt.descriptor.para_id, group_authorities
                                );
                                // Destructure ParaId
                                let Id(para_id) = candidate_receipt.descriptor.para_id;
                                // If para id exists increment vote or missed vote
                                if para_record.is_para_id_assigned(para_id) {
                                    if let Some((_, vote)) = group_authorities.iter().find(
                                        |(ValidatorIndex(para_idx), _)| {
                                            para_idx == para_record.para_index()
                                        },
                                    ) {
                                        match vote {
                                            ValidityAttestation::Explicit(_) => {
                                                para_record.inc_explicit_votes(para_id);
                                            }
                                            ValidityAttestation::Implicit(_) => {
                                                para_record.inc_implicit_votes(para_id);
                                            }
                                        }
                                    } else {
                                        // Try to guarantee that one of the peers is in the same group
                                        if group_authorities.len() > 0 {
                                            let (ValidatorIndex(para_idx), _) =
                                                group_authorities[0];
                                            if let Some(group_idx) = para_record.group() {
                                                if para_idx / 5 == group_idx {
                                                    para_record.inc_missed_votes(para_id);
                                                }
                                            }
                                        } else {
                                            para_record.inc_missed_votes(para_id);
                                        }
                                    }

                                    break;
                                } else {
                                    debug!("On chain votes para_id: {:?} is different from the para_id: {:?} current assigned to the validator index: {}.", para_id, para_record.para_id(), para_record.para_index());
                                }
                            }
                        } else {
                            warn!(
                                "Backing votes session: {} is different from records.current_session: {}",
                                backing_votes.session, current_session
                            );
                        }
                    }

                    // debug!("------");
                    // debug!("------");
                    // debug!("authored_blocks: {} points: {}", authored_blocks, points);
                    // debug!(
                    //     "validator_index: {:?} group: {:?} para_id: {:?} peers: {:?}",
                    //     para_record.para_index(),
                    //     para_record.group(),
                    //     para_record.para_id(),
                    //     para_record.peers()
                    // );
                    // for (k, s) in para_record.para_stats().iter() {
                    //     debug!("para_id: {}", k);
                    //     debug!("stats: {:?}", s);
                    // }
                    // debug!("------");
                    // debug!("------");
                }
            }
        }
    }

    // debug!("records {:?}", records);

    Ok(())
}

pub async fn run_val_perf_report(
    era_index: EraIndex,
    epoch_index: EpochIndex,
    records: &Records,
    subscribers: &Subscribers,
) -> Result<(), OnetError> {
    let onet: Onet = Onet::new().await;
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();

    let network = Network::load(client).await?;
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
    for Id(para_id) in api.storage().paras().parachains(None).await? {
        parachains.push(para_id);
    }

    // Populate some maps to get ranks
    let mut group_authorities_map: BTreeMap<u32, Vec<(AuthorityRecord, ParaRecord)>> =
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
                        let auths = group_authorities_map.entry(group_idx).or_insert(Vec::new());
                        auths.push((authority_record.clone(), para_record.clone()));
                        auths.sort_by(|(_, a), (_, b)| b.total_votes().cmp(&a.total_votes()));
                    }
                }
            }
        }
    }

    // Convert map to vec and sort group by points
    let mut group_authorities_sorted = Vec::from_iter(group_authorities_map);
    group_authorities_sorted.sort_by(|(_, a), (_, b)| {
        b.iter()
            .map(|x| x.1.total_votes())
            .sum::<Votes>()
            .cmp(&a.iter().map(|x| x.1.total_votes()).sum::<Votes>())
    });

    // Prepare data for each validator subscriber
    if let Some(subs) = subscribers.get(Some(EpochKey(era_index, epoch_index))) {
        for (stash, user_id) in subs.iter() {
            let mut validator = Validator::new(stash.clone());
            validator.name = get_display_name(&onet, &stash, None).await?;
            let mut data = RawDataPara {
                network: network.clone(),
                meta: metadata.clone(),
                report_type: ReportType::Validator,
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

                    // Get group rank
                    if let Some(group_idx) = para_record.group() {
                        if let Some(group_rank) = group_authorities_sorted
                            .iter()
                            .position(|&(g, _)| g == group_idx)
                        {
                            data.group_rank = Some(group_rank.clone());
                            // Get para validator rank
                            let (_, authorities) = &group_authorities_sorted[group_rank];
                            if let Some(validator_rank) = authorities.iter().position(|(a, _)| {
                                a.authority_index() == authority_record.authority_index()
                            }) {
                                data.para_validator_rank = Some((group_rank * 5) + validator_rank);
                            }
                        }
                    }

                    // Collect peers information
                    for peer_authority_index in para_record.peers().iter() {
                        if let Some(peer_authority_record) = records.get_authority_record(
                            *peer_authority_index,
                            Some(EpochKey(era_index, epoch_index)),
                        ) {
                            let peer_name =
                                get_display_name(&onet, peer_authority_record.address(), None)
                                    .await?;

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
    let client = onet.client();

    let network = Network::load(client).await?;

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
                        // get validator name
                        let name =
                            get_display_name(&onet, &authority_record.address(), None).await?;

                        //
                        let auths = group_authorities_map.entry(group_idx).or_insert(Vec::new());
                        auths.push((authority_record.clone(), para_record.clone(), name));
                        auths.sort_by(|(a, _, _), (b, _, _)| b.para_points().cmp(&a.para_points()));
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
    let client = onet.client();

    let network = Network::load(client).await?;

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
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if !config.matrix_disabled {
        if (epoch_index as f64 % config.matrix_network_report_epoch_rate as f64) == 0.0_f64 {
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
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();

    let network = Network::load(client).await?;

    // Fetch active era
    let active_era_index = match api.storage().staking().active_era(None).await? {
        Some(active_era_info) => active_era_info.index,
        None => return Err("Active era not available".into()),
    };

    // Fetch current epoch
    let current_session_index = api.storage().session().current_index(None).await?;

    // Fetch active era total stake

    let active_era_total_stake = api
        .storage()
        .staking()
        .eras_total_stake(&active_era_index, None)
        .await?;

    // Set era/session details
    let metadata = Metadata {
        active_era_index,
        current_session_index,
        active_era_total_stake,
        ..Default::default()
    };

    let mut validators: Validators = Vec::new();

    // Load TVP stashes
    let tvp_stashes: Vec<AccountId32> = try_fetch_stashes_from_remote_url().await?;

    // Fetch all validators
    let mut all_validators = api.storage().staking().validators_iter(None).await?;
    // Fetch active validators
    let active_validators = api.storage().session().validators(None).await?;

    while let Some((key, validator_prefs)) = all_validators.next().await? {
        let stash = get_account_id_from_storage_key(key);
        let mut v = Validator::new(stash.clone());
        if validator_prefs.commission != Perbill(1000000000) {
            if !tvp_stashes.contains(&stash) {
                v.subset = Subset::NONTVP;
            } else {
                v.subset = Subset::TVP;
            }
            v.is_oversubscribed = verify_oversubscribed(&onet, active_era_index, &stash).await?;
        } else {
            v.subset = Subset::C100;
        }
        // Commisssion
        let Perbill(commission) = validator_prefs.commission;
        v.commission = commission as f64 / 1_000_000_000.0_f64;
        // Check if validator is in active set
        v.is_active = active_validators.contains(&stash);

        // Fetch own stake
        v.own_stake = get_own_stake(&onet, &stash).await?;

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
                v.name = get_display_name(&onet, &stash, None).await?;
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

    // Collect era points for maximum_history_eras
    let start_era_index = active_era_index - config.maximum_history_eras;
    for era_index in start_era_index..active_era_index {
        let era_reward_points = api
            .storage()
            .staking()
            .eras_reward_points(&era_index, None)
            .await?;
        debug!("era_reward_points: {:?}", era_reward_points);

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
            let r = current_session_index as f64 % config.pools_nominate_rate as f64;
            if r == 0.0_f64 {
                if records.total_full_epochs() >= config.pools_minimum_sessions {
                    match try_run_nomination_pools(&onet, &records, validators).await {
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
                // Cache pools APR and send message
                try_run_cache_pools_era(active_era_index, true).await?;
            } else {
                // Only cache pools APR. No need to send message if no new nomination was performed
                try_run_cache_pools_era(active_era_index, false).await?;
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

pub async fn fetch_pool_data(onet: &Onet, pool_id: u32) -> Result<Option<Pool>, OnetError> {
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();
    let network = Network::load(client).await?;

    // Load chain data
    let BoundedVec(metadata) = api
        .storage()
        .nomination_pools()
        .metadata(&pool_id, None)
        .await?;

    if let Some(bounded) = api
        .storage()
        .nomination_pools()
        .bonded_pools(&pool_id, None)
        .await?
    {
        let unix_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();

        // NOTE: Remove ONE-T metadata url
        let metadata = str(metadata);

        let pool = Pool {
            id: pool_id,
            metadata: metadata
                .replace("• https://one-t.turboflakes.io", "")
                .trim()
                .to_string(),
            member_counter: bounded.member_counter,
            bonded: format!(
                "{} {}",
                bounded.points / 10u128.pow(network.token_decimals as u32),
                network.token_symbol
            ),
            state: format!("{:?}", bounded.state),
            nominees: None,
            ts: unix_now.as_secs(),
        };
        return Ok(Some(pool));
    }

    Ok(None)
}

pub async fn try_run_cache_pools_data(onet: &Onet, block_number: u32) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.pools_enabled {
        if (block_number as f64 % 10.0_f64) == 0.0_f64 {
            cache_pool_data(&onet, config.pool_id_1).await?;
            cache_pool_data(&onet, config.pool_id_2).await?;
        }
    }
    Ok(())
}

pub async fn cache_pool_data(onet: &Onet, pool_id: u32) -> Result<(), OnetError> {
    if let Some(pool) = fetch_pool_data(&onet, pool_id).await? {
        pool.cache()?;
    }
    Ok(())
}

// * APR is the annualized average of all targets from the last X eras.
pub async fn calculate_apr(onet: &Onet, targets: Vec<AccountId32>) -> Result<f64, OnetError> {
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();
    let config = CONFIG.clone();

    // Fetch active era index
    let current_era_index = match api.storage().staking().active_era(None).await? {
        Some(active_era_info) => active_era_info.index,
        None => return Err("Active era not available. Check current API -> api.storage().staking().active_era(None)".into()),
    };

    let mut total_eras: u128 = 0;
    let mut total_points: u128 = 0;
    let mut total_reward: u128 = 0;
    let mut nominees_total_eras: u128 = 0;
    let mut nominees_total_points: u128 = 0;
    let mut nominees_total_stake: u128 = 0;
    let mut nominees_total_commission: u128 = 0;

    // Collect nominees commission
    for nominee in targets.iter() {
        let validator = api.storage().staking().validators(&nominee, None).await?;
        let Perbill(commission) = validator.commission;
        nominees_total_commission += commission as u128;
    }

    // Collect chain data for maximum_history_eras
    // let start_era_index = current_era_index - config.maximum_history_eras;
    let start_era_index = current_era_index - 84;
    for era_index in start_era_index..current_era_index {
        let era_reward_points = api
            .storage()
            .staking()
            .eras_reward_points(&era_index, None)
            .await?;
        for (stash, points) in era_reward_points.individual.iter() {
            if targets.contains(stash) {
                nominees_total_eras += 1;
                nominees_total_points += *points as u128;
                let eras_stakers = api
                    .storage()
                    .staking()
                    .eras_stakers(&era_index, &stash, None)
                    .await?;
                nominees_total_stake += eras_stakers.total;
            }
        }
        total_points += era_reward_points.total as u128;
        total_eras += 1;

        if let Some(eras_validator_reward) = api
            .storage()
            .staking()
            .eras_validator_reward(&era_index, None)
            .await?
        {
            total_reward += eras_validator_reward;
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
        info!(
            "avg_points_per_nominee_per_era: {}",
            avg_points_per_nominee_per_era
        );
        let avg_stake_per_nominee_per_era = nominees_total_stake / nominees_total_eras;
        info!(
            "avg_stake_per_nominee_per_era: {}",
            avg_stake_per_nominee_per_era
        );
        let avg_reward_per_era = total_reward / total_eras;
        info!("avg_reward_per_era: {}", avg_reward_per_era);
        let avg_points_per_era = total_points / total_eras;
        info!("avg_points_per_era: {}", avg_points_per_era);

        let avg_reward_per_nominee_per_era =
            (avg_points_per_nominee_per_era * avg_reward_per_era) / avg_points_per_era;
        info!(
            "avg_reward_per_nominee_per_era: {}",
            avg_reward_per_nominee_per_era
        );

        let avg_commission_per_nominee = nominees_total_commission / targets.len() as u128;
        info!("avg_commission_per_nominee: {}", avg_commission_per_nominee);

        let commission = avg_commission_per_nominee as f64 / 1_000_000_000.0_f64;
        let apr: f64 = (avg_reward_per_nominee_per_era as f64 * (1.0 - commission))
            * (1.0 / avg_stake_per_nominee_per_era as f64)
            * config.eras_per_day as f64
            * 365.0;
        info!("apr: {}", apr);
        Ok(apr)
    } else {
        Ok(0.0_f64)
    }
}

pub async fn try_run_cache_pools_era(
    era_index: EraIndex,
    send_report: bool,
) -> Result<(), OnetError> {
    async_std::task::spawn(async move {
        if let Err(e) = run_cache_pools_era(era_index, send_report).await {
            error!("run_cache_pools_era error: {:?}", e);
        }
    });

    Ok(())
}

pub async fn run_cache_pools_era(era_index: EraIndex, send_report: bool) -> Result<(), OnetError> {
    let onet: Onet = Onet::new().await;
    let client = onet.client();
    let config = CONFIG.clone();

    if config.pools_enabled {
        match cache_pools_era(&onet, era_index).await {
            Ok((onet_pools, pools_avg_apr)) => {
                if send_report {
                    let network = Network::load(client).await?;

                    let metadata = Metadata {
                        active_era_index: era_index,
                        ..Default::default()
                    };

                    let data = RawDataPools {
                        network,
                        meta: metadata,
                        report_type: ReportType::NominationPools,
                        onet_pools,
                        pools_avg_apr,
                    };

                    // Send report only if para records available
                    let report = Report::from(data);

                    onet.matrix()
                        .send_public_message(&report.message(), Some(&report.formatted_message()))
                        .await?;
                }
            }
            Err(e) => error!("{}", e),
        }
    }

    Ok(())
}

pub async fn cache_pools_era(
    onet: &Onet,
    era_index: EraIndex,
) -> Result<(Vec<(u32, String, f64)>, f64), OnetError> {
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();
    let config = CONFIG.clone();

    let mut onet_pools: Vec<(u32, String, f64)> = Vec::new();

    // Pools Eras
    let mut pools_era = PoolsEra::with_era(era_index);

    // Load pools stash accounts
    let mut pools = api
        .storage()
        .nomination_pools()
        .reverse_pool_id_lookup_iter(None)
        .await?;

    while let Some((key, pool_id)) = pools.next().await? {
        let pool_stash = get_account_id_from_storage_key(key);

        // Load chain data
        // if let Some(nominations) = api.storage().staking().nominators(&acc, None).await? {
        if let Some(nominations) = api
            .storage()
            .staking()
            .nominators(&pool_stash, None)
            .await?
        {
            // Fetch pool data
            if let Some(pool) = fetch_pool_data(&onet, pool_id).await? {
                let mut pool = pool;
                let mut nominees: Vec<Nominee> = Vec::new();
                let BoundedVec(targets) = nominations.targets;
                info!("Calculate APR for pool id: {}", pool_id);
                let apr = calculate_apr(&onet, targets.clone()).await?;

                for nominee in targets.iter() {
                    // get nominee identity
                    let nominee = Nominee {
                        stash: nominee.to_string(),
                        identity: get_display_name(&onet, &nominee, None).await?,
                    };
                    nominees.push(nominee);
                }
                let unix_now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap();
                let pool_nominees = PoolNominees {
                    id: pool_id,
                    nominees,
                    apr,
                    ts: unix_now.as_secs(),
                };

                // Cache if one of the config pools
                if pool_id == config.pool_id_1 || pool_id == config.pool_id_2 {
                    onet_pools.push((pool_id, pool.metadata.clone(), apr));
                    pool_nominees.cache()?;
                }
                pool.nominees = Some(pool_nominees);
                pools_era.pools.push(pool);
            }
        }
    }
    // Calculate all pools average APR
    let total_pools = pools_era
        .pools
        .iter()
        .filter(|p| p.nominees.is_some())
        .count();
    let aprs: Vec<f64> = pools_era
        .pools
        .iter()
        .filter(|p| p.nominees.is_some())
        .map(|p| p.nominees.as_ref().unwrap().apr)
        .collect();
    let pools_avg_apr = aprs.iter().sum::<f64>() / total_pools as f64;

    // Serialize and cache
    pools_era.cache()?;

    Ok((onet_pools, pools_avg_apr))
}

async fn try_run_nomination_pools(
    onet: &Onet,
    records: &Records,
    validators: Validators,
) -> Result<String, OnetError> {
    let config = CONFIG.clone();
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();

    // Load nominator seed account
    let seed = fs::read_to_string(config.pools_nominator_seed_path)
        .expect("Something went wrong reading the pool nominator seed file");
    let seed_account: sr25519::Pair = get_from_seed(&seed, None);
    let signer = PairSigner::<DefaultConfig, sr25519::Pair>::new(seed_account);

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

    // Pool 2 should include top TVP validators with the lowest commission in the last X sessions
    // Note: maximum validators are 12 in Kusama / 8 Polkadot
    let call = define_second_pool_call(
        &mut tvp_validators.clone(),
        Some(config.pools_maximum_nominations / 2),
    )?;
    calls.push(call);

    if calls.len() > 0 {
        // Submit batch call with nominations
        let response = api
            .tx()
            .utility()
            .batch(calls)?
            .sign_and_submit_then_watch_default(&signer)
            .await?
            .wait_for_finalized()
            .await?;

        let tx_events = response.fetch_events().await?;

        // Get block number
        let block_number =
            if let Some(header) = client.rpc().header(Some(tx_events.block_hash())).await? {
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
            let message = format!(
                "🗳️ Nomination for <i>Pool Id {}</i> and <i>Pool Id {}</i> finalized at block #{} (<a href=\"{}\">{}</a>)",
                config.pool_id_1,
                config.pool_id_2,
                block_number,
                explorer_url,
                tx_events.extrinsic_hash().to_string()
            );
            // Cache pool nomination
            let unix_now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap();
            let pool_nomination = PoolNomination {
                id: config.pool_id_1,
                sessions_counter: records.total_full_epochs(),
                block_number,
                extrinsic_hash: tx_events.extrinsic_hash(),
                ts: unix_now.as_secs(),
            };
            pool_nomination.cache()?;
            let pool_nomination = PoolNomination {
                id: config.pool_id_2,
                sessions_counter: records.total_full_epochs(),
                block_number,
                extrinsic_hash: tx_events.extrinsic_hash(),
                ts: unix_now.as_secs(),
            };
            pool_nomination.cache()?;
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
) -> Result<bool, OnetError> {
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();

    let exposure = api
        .storage()
        .staking()
        .eras_stakers(&era_index, stash, None)
        .await?;
    Ok(exposure.others.len() > 256)
}

async fn get_own_stake(onet: &Onet, stash: &AccountId32) -> Result<u128, OnetError> {
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();

    if let Some(controller) = api.storage().staking().bonded(stash, None).await? {
        if let Some(ledger) = api.storage().staking().ledger(&controller, None).await? {
            return Ok(ledger.active);
        }
    }
    return Ok(0);
}

#[async_recursion]
async fn get_display_name(
    onet: &Onet,
    stash: &AccountId32,
    sub_account_name: Option<String>,
) -> Result<String, OnetError> {
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();

    match api.storage().identity().identity_of(stash, None).await? {
        Some(identity) => {
            debug!("identity {:?}", identity);
            let parent = parse_identity_data(identity.info.display);
            let name = match sub_account_name {
                Some(child) => format!("{}/{}", parent, child),
                None => parent,
            };
            Ok(name)
        }
        None => {
            if let Some((parent_account, data)) =
                api.storage().identity().super_of(stash, None).await?
            {
                let sub_account_name = parse_identity_data(data);
                return get_display_name(
                    &onet,
                    &parent_account,
                    Some(sub_account_name.to_string()),
                )
                .await;
            } else {
                let s = &stash.to_string();
                Ok(format!("{}...{}", &s[..6], &s[s.len() - 6..]))
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
