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
use async_recursion::async_recursion;
use log::{debug, error, info, warn};
use onet_api::responses::{AuthorityKey, AuthorityKeyCache};
use onet_asset_hub_paseo::{
    asset_hub_runtime,
    asset_hub_runtime::{
        runtime_types::{
            bounded_collections::bounded_vec::BoundedVec, pallet_nomination_pools::PoolState,
            pallet_staking_async::pallet::pallet::BoundedExposurePage,
            sp_arithmetic::per_things::Perbill,
        },
        staking::events::PagedElectionProceeded,
        staking::events::SessionRotated,
        staking_rc_client::events::OffenceReceived,
        staking_rc_client::events::SessionReportReceived,
    },
};

use onet_asset_hub_paseo::{
    fetch_account_info, fetch_active_era_info, fetch_bonded_controller_account, fetch_bonded_pools,
    fetch_era_reward_points, fetch_eras_total_stake, fetch_eras_validator_reward,
    fetch_first_session_from_active_era, fetch_last_pool_id, fetch_ledger_from_controller,
    fetch_nominators, fetch_own_stake_via_stash, fetch_pool_metadata,
    fetch_relay_parent_block_number, fetch_total_issuance, AssetHubCall, NominationPoolsCall,
};
use onet_cache::{
    cache_best_block, cache_board_limits_at_session, cache_finalized_block,
    cache_network_stats_at_session, cache_nomination_pool, cache_nomination_pool_nominees,
    cache_nomination_pool_stats, cache_records, cache_records_at_new_session,
    cache_validator_profile, cache_validator_profile_only,
};
use onet_cache::{
    error::CacheError,
    types::{CacheKey, ChainKey, Verbosity},
};
use onet_config::{CONFIG, EPOCH_FILENAME};
use onet_core::{
    core::{
        get_account_id_from_storage_key, get_latest_block_number_processed, get_signer_from_seed,
        get_subscribers, get_subscribers_by_epoch, write_latest_block_number_processed,
    },
    error::OnetError,
    Onet,
};
use onet_discovery::try_fetch_discovery_data;
use onet_dn::try_fetch_stashes_from_remote_url;
use onet_matrix::FileInfo;
use onet_mcda::scores::base_decimals;
use onet_people_paseo::{bytes_to_str, get_display_name, get_identity};
use onet_pools::{
    nomination_pool_account, Account, AccountType, ActiveNominee, Pool, PoolNominees, PoolStats,
    Roles,
};

use onet_records::{
    AuthorityIndex, AuthorityRecord, BlockNumber, DiscoveryRecord, EpochIndex, EpochKey, EraIndex,
    NetworkSessionStats, ParaId, ParaRecord, ParaStats, Points, Records, Subscribers, Subset,
    SubsetStats, ValidatorProfileRecord,
};
use onet_report::{
    group_by_points, position, Callout, Metadata as ReportMetadata, Network, RawData, RawDataGroup,
    RawDataPara, RawDataParachains, RawDataRank, Report, ReportType, Validator, Validators,
};
use redis::aio::Connection;

use codec::Decode;
use std::{
    collections::BTreeMap,
    convert::{TryFrom, TryInto},
    fs,
    iter::FromIterator,
    result::Result,
    str::FromStr,
    thread, time,
    time::Instant,
};

use frame_metadata::RuntimeMetadataPrefixed;
use subxt::{
    backend::legacy::LegacyRpcMethods,
    config::substrate::{Digest, DigestItem},
    ext::{frame_metadata, subxt_core::Metadata},
    tx::TxStatus,
    utils::{AccountId32, H256},
    OnlineClient, PolkadotConfig,
};
use subxt_signer::sr25519::Keypair;

#[subxt::subxt(
    runtime_metadata_path = "artifacts/metadata/paseo_metadata.scale",
    derive_for_all_types = "PartialEq, Clone, codec::Decode, codec::Encode"
)]
pub mod relay_runtime {}

use crate::custom_types::PreDigest;

use relay_runtime::{
    grandpa::events::NewAuthorities,
    historical::events::RootStored,
    // historical::events::RootsPruned,
    para_inclusion::events::CandidateIncluded,
    // para_inclusion::storage::types::v1::V1 as CoreInfo,
    para_inherent::calls::types::Enter,
    para_inherent::storage::types::on_chain_votes::OnChainVotes,
    para_scheduler::storage::types::session_start_block::SessionStartBlock,
    para_scheduler::storage::types::validator_groups::ValidatorGroups,
    paras_shared::storage::types::active_validator_indices::ActiveValidatorIndices,
    runtime_types::{
        // frame_system::AccountInfo,
        // frame_system::LastRuntimeUpgradeInfo,
        // pallet_balances::types::AccountData,
        polkadot_parachain_primitives::primitives::Id,
        polkadot_primitives::v8::AvailabilityBitfield,
        polkadot_primitives::v8::CoreIndex,
        polkadot_primitives::v8::DisputeStatement,
        polkadot_primitives::v8::ValidatorIndex,
        polkadot_primitives::v8::ValidityAttestation,
        // polkadot_runtime_parachains::scheduler::common::Assignment,
        // polkadot_runtime_parachains::scheduler::pallet::CoreOccupied,
        sp_authority_discovery::app::Public,
        // sp_consensus_babe::digests::PreDigest,
    },
    session::events::new_session::SessionIndex,
    session::events::NewSession,
    // session::storage::types::queued_keys::QueuedKeys,
    // session::storage::types::validators::Validators as ValidatorSet,
    // staking_ah_client::events::CouldNotMergeAndDropped,
    // staking_ah_client::events::SetTooSmallAndDropped,
    staking_ah_client::events::ValidatorSetReceived,
    system::events::ExtrinsicFailed,
};

pub type RcCall = relay_runtime::runtime_types::paseo_runtime::RuntimeCall;
pub type RcNominationPoolsCall =
    relay_runtime::runtime_types::pallet_nomination_pools::pallet::Call;

pub async fn init_start_block_number(onet: &Onet) -> Result<BlockNumber, OnetError> {
    let config = CONFIG.clone();
    let rc_rpc = onet.relay_rpc().clone();

    // Initialize from the last block processed
    let latest_block_number = get_latest_block_number_processed()?;

    if config.start_from_cached_block_enabled {
        return Ok(latest_block_number);
    }

    // Initialize from the first block of the session of last block processed
    let rc_api = onet.relay_client().clone();
    let latest_block_hash = try_fetch_relay_chain_block_hash(&rc_rpc, latest_block_number).await?;
    // Fetch ParaSession start block for the latest block processed
    let mut start_block_number = fetch_session_start_block(&rc_api, latest_block_hash).await?;
    // Note: We want to start sync in the first block of a session.
    // For that we get the first block of a ParaSession and remove 1 block,
    // since ParaSession starts always at the the second block of a new session
    start_block_number -= 1;
    // Load into memory the minimum initial eras defined (default=0)
    start_block_number -= config.minimum_initial_eras * 6 * config.blocks_per_session;

    Ok(start_block_number.into())
}

pub async fn init_and_subscribe_on_chain_events(onet: &Onet) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let rc_api = onet.relay_client().clone();
    let rc_rpc = onet.relay_rpc().clone();
    let ah_api = onet
        .asset_hub_client()
        .as_ref()
        .expect("AH API to be available");

    let stashes: Vec<String> = config.pools_featured_nominees;
    info!(
        "{} featured nominees loaded from 'config.pools_featured_nominees'",
        stashes.len()
    );

    let start_block_number = init_start_block_number(&onet).await?;

    // get block hash from the start block
    let rc_block_hash =
        try_fetch_relay_chain_block_hash(&rc_rpc, start_block_number.into()).await?;

    let ah_block_hash =
        fetch_asset_hub_block_hash_from_relay_chain(onet, start_block_number.into(), rc_block_hash)
            .await?;

    info!(
        "Start from RC Block #{} {:?}",
        start_block_number, rc_block_hash
    );
    info!("Start from AH Block Hash {:?}", ah_block_hash);

    // Fetch active era index
    let active_era_info = fetch_active_era_info(&ah_api, ah_block_hash).await?;
    let era_index = active_era_info.index;

    // Cache Nomination pools
    // try_run_cache_pools_era(era_index, false).await?;

    // Fetch session index
    let session_index = super::storage::fetch_session_index(&rc_api, rc_block_hash).await?;

    // Cache current epoch
    let epoch_filename = format!("{}{}", config.data_path, EPOCH_FILENAME);
    fs::write(&epoch_filename, session_index.to_string())?;

    // Matrix users subscribers
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
    info!("Start records: {:?}", records);

    // Initialize subscribers records
    initialize_records(
        &rc_api,
        &ah_api,
        &mut records,
        start_block_number,
        rc_block_hash,
        ah_block_hash,
    )
    .await?;

    // Initialize cache
    if config.cache_writer_enabled {
        let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

        let first_session_index =
            fetch_first_session_from_active_era(&ah_api, ah_block_hash).await?;
        cache_records_at_new_session(&mut cache, &records, first_session_index).await?;
        cache_records(&mut cache, &records).await?;
    }

    // Initialize p2p discovery
    try_run_cache_discovery_records(&records, rc_block_hash).await?;

    // Start indexing from the start_block_number
    let mut latest_block_number_processed: Option<u64> = Some(start_block_number.into());
    let mut is_loading = true;

    // AH Subscribe head
    try_run_subscribe_best_asset_hub().await?;

    // RC Subscribe head
    // NOTE: the reason why we subscribe head and not finalized_head,
    // is just because head is in sync more frequently.
    // finalized_head can always be queried so as soon as it changes we process th repective block_hash
    let mut blocks_sub = rc_api.blocks().subscribe_best().await?;
    while let Some(Ok(best_block)) = blocks_sub.next().await {
        info!("RC Block #{:?} best received", best_block.number());
        // update records best_block number
        process_best_block(
            &onet,
            &mut records,
            ChainKey::RC,
            best_block.number().into(),
        )
        .await?;

        // fetch latest finalized block
        let finalized_block_hash = onet.rpc().chain_get_finalized_head().await?;
        if let Some(block) = onet
            .rpc()
            .chain_get_header(Some(finalized_block_hash))
            .await?
        {
            info!("RC Block #{:?} finalized fetched", block.number);
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
                            finalized_block_hash,
                            is_loading,
                        )
                        .await?;
                    } else {
                        // fetch block_hash if not the finalized head
                        let block_hash =
                            try_fetch_relay_chain_block_hash(&rc_rpc, block_number).await?;

                        process_finalized_block(
                            &onet,
                            &mut subscribers,
                            &mut records,
                            block_number,
                            block_hash,
                            is_loading,
                        )
                        .await?;
                    };

                    //
                    latest_block_number_processed = Some(block_number);
                }
            }
            // Cache latest block_number processed
            write_latest_block_number_processed(block.number.into())?;
        }
        latest_block_number_processed = Some(get_latest_block_number_processed()?);
    }

    Err(OnetError::SubscriptionFinished)
}

pub async fn process_best_block(
    onet: &Onet,
    records: &mut Records,
    chain_key: ChainKey,
    block_number: BlockNumber,
) -> Result<(), OnetError> {
    // update best block number
    match chain_key {
        ChainKey::RC => records.set_relay_chain_best_block_number(block_number.into()),
        ChainKey::AH => records.set_asset_hub_best_block_number(block_number.into()),
    };

    // if api enabled cache best block
    let config = CONFIG.clone();
    if !config.cache_writer_enabled {
        return Ok(());
    }
    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;
    cache_best_block(&mut cache, chain_key, block_number).await?;

    Ok(())
}

pub async fn process_finalized_block(
    onet: &Onet,
    subscribers: &mut Subscribers,
    records: &mut Records,
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
    is_loading: bool,
) -> Result<(), OnetError> {
    let start = Instant::now();
    debug!("RC Block #{} to be processed now", rc_block_number);

    let BlockProcessingContext {
        rc_api,
        rc_rpc,
        ah_api,
        ah_rpc,
        current_metadata,
    } = setup_processing_context(onet, rc_block_number).await?;

    // Process RC events with the parent_metadata
    process_relay_chain_events(
        &onet,
        &rc_api,
        &rc_rpc,
        &ah_api,
        &ah_rpc,
        records,
        subscribers,
        rc_block_number,
        rc_block_hash,
        is_loading,
    )
    .await?;

    // NOTE_1: It might require further testing, but since v1003000 the aproach will be to
    // restore the original `current_metadata` to process the next records!

    // NOTE_2: Lookup for exceptions where both metadatas (parent_metadata or current_metadata)
    // need to be passed down and apply them where required!

    // Restore assignement of static_metadata to the api
    rc_api.set_metadata(current_metadata);

    // Update records
    // Note: these records should be updated after the switch of session
    track_records(&rc_api, &rc_rpc, records, rc_block_number, rc_block_hash).await?;

    let config = CONFIG.clone();
    if config.cache_writer_enabled {
        let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;
        // Cache records at every block
        cache_records(&mut cache, &records).await?;
    }

    // Log block processed duration time
    info!(
        "RC Block #{} processed ({:?})",
        rc_block_number,
        start.elapsed()
    );

    Ok(())
}

pub async fn try_run_subscribe_best_asset_hub() -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if !config.cache_writer_enabled {
        return Ok(());
    }

    async_std::task::spawn(async move {
        if let Err(e) = subscribe_best_asset_hub().await {
            error!("subscribe_best_asset_hub error: {:?}", e);
        }
    });

    Ok(())
}

pub async fn subscribe_best_asset_hub() -> Result<(), OnetError> {
    let onet: Onet = Onet::new().await;
    let ah_api = onet
        .asset_hub_client()
        .as_ref()
        .expect("AH API to be available");
    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;
    let mut blocks_sub = ah_api.blocks().subscribe_best().await?;
    while let Some(Ok(best_block)) = blocks_sub.next().await {
        info!("AH Block #{:?} best received", best_block.number());
        let block_number = best_block.number();
        let chain_key = ChainKey::AH;
        cache_best_block(&mut cache, chain_key, block_number.into()).await?;
    }
    Err(OnetError::SubscriptionFinished)
}

struct BlockProcessingContext {
    rc_api: OnlineClient<PolkadotConfig>,
    rc_rpc: LegacyRpcMethods<PolkadotConfig>,
    ah_api: OnlineClient<PolkadotConfig>,
    ah_rpc: LegacyRpcMethods<PolkadotConfig>,
    current_metadata: Metadata,
}

async fn setup_processing_context(
    onet: &Onet,
    block_number: BlockNumber,
) -> Result<BlockProcessingContext, OnetError> {
    let rc_api = onet.relay_client().clone();
    let rc_rpc = onet.relay_rpc().clone();
    let ah_api = onet
        .asset_hub_client()
        .as_ref()
        .expect("AH API to be available")
        .clone();
    let ah_rpc = onet
        .asset_hub_rpc()
        .as_ref()
        .expect("AH RPC to be available")
        .clone();
    let current_metadata = rc_api.metadata().clone();

    // Get parent block metadata for better handling of runtime upgrades
    let parent_block_hash = try_fetch_relay_chain_block_hash(&rc_rpc, block_number - 1).await?;

    // let parent_metadata = rc_api::fetch_latest_stable_metadata(parent_block_hash).await?;
    let parent_metadata_bytes = rc_rpc
        .state_get_metadata(Some(parent_block_hash))
        .await?
        .into_raw();
    let parent_metadata: Metadata =
        RuntimeMetadataPrefixed::decode(&mut &parent_metadata_bytes[..])?.try_into()?;

    rc_api.set_metadata(parent_metadata.clone());

    Ok(BlockProcessingContext {
        rc_api,
        rc_rpc,
        ah_api,
        ah_rpc,
        current_metadata,
    })
}

async fn process_relay_chain_events(
    onet: &Onet,
    rc_api: &OnlineClient<PolkadotConfig>,
    rc_rpc: &LegacyRpcMethods<PolkadotConfig>,
    ah_api: &OnlineClient<PolkadotConfig>,
    ah_rpc: &LegacyRpcMethods<PolkadotConfig>,
    records: &mut Records,
    subscribers: &mut Subscribers,
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
    is_loading: bool,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let events = rc_api.events().at(rc_block_hash).await?;

    for event in events.iter() {
        let event = event?;
        if let Some(ev) = event.as_event::<CandidateIncluded>()? {
            if ev.0.descriptor.para_id == Id(config.asset_hub_para_id) {
                let ah_block_hash = ev.0.descriptor.para_head;
                process_asset_hub_events(
                    &onet,
                    rc_api,
                    rc_rpc,
                    ah_api,
                    ah_rpc,
                    rc_block_number,
                    rc_block_hash,
                    ah_block_hash,
                    subscribers,
                    records,
                    is_loading,
                )
                .await?;
            }
        } else if let Some(ev) = event.as_event::<NewSession>()? {
            info!("RC Event {:?}", ev);

            if !is_loading {
                // Cache p2p discovery
                try_run_cache_discovery_records(&records, rc_block_hash).await?;
            }
        } else if let Some(ev) = event.as_event::<relay_runtime::staking::events::EraPaid>()? {
            info!("RC Event {:?}", ev);
        } else if let Some(ev) = event.as_event::<RootStored>()? {
            info!("RC Event {:?}", ev);
        } else if let Some(ev) = event.as_event::<ValidatorSetReceived>()? {
            info!("RC Event {:?}", ev);
        } else if let Some(ev) = event.as_event::<NewAuthorities>()? {
            info!("RC Event NewAuthorities: {:?}", ev.authority_set.len());
        }
    }

    Ok(())
}

async fn process_asset_hub_events(
    onet: &Onet,
    rc_api: &OnlineClient<PolkadotConfig>,
    rc_rpc: &LegacyRpcMethods<PolkadotConfig>,
    ah_api: &OnlineClient<PolkadotConfig>,
    ah_rpc: &LegacyRpcMethods<PolkadotConfig>,
    _rc_block_number: BlockNumber,
    _rc_block_hash: H256,
    ah_block_hash: H256,
    subscribers: &mut Subscribers,
    records: &mut Records,
    is_loading: bool,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let (ah_block_number, ah_parent_block_hash) =
        fetch_asset_hub_block_info(ah_rpc, ah_block_hash).await?;

    // Fetch the RC Parent block
    let rc_parent_number = fetch_relay_parent_block_number(ah_api, ah_block_hash).await?;

    let events = ah_api.events().at(ah_block_hash).await?;

    for event in events.iter() {
        let event = event?;
        if let Some(ev) = event.as_event::<SessionRotated>()? {
            info!("AH event {:?}", ev);
            let rc_parent_block_hash =
                fetch_relay_chain_block_hash(rc_rpc, rc_parent_number).await?;
            let previous_epoch_era_index = process_session_rotated(
                rc_api,
                ah_api,
                ev.starting_session,
                ev.active_era,
                subscribers,
                records,
                rc_parent_number,
                rc_parent_block_hash,
                ah_block_number,
                ah_block_hash,
            )
            .await?;

            // Init cache session records every new session
            try_run_init_cache_records_at_new_session(&onet, records, ah_block_hash).await?;

            // Cache session stats records every new session with data collected
            // at last block of the session (Grandparent RC block number)
            let rc_grandparent_block_hash =
                fetch_relay_chain_block_hash(rc_rpc, rc_parent_number - 1).await?;

            let rc_parent_block_hash =
                try_fetch_relay_chain_block_hash(&rc_rpc, rc_parent_number).await?;

            try_run_cache_session_stats_records(
                ev.starting_session - 1,
                rc_parent_number,
                rc_parent_block_hash,
                rc_grandparent_block_hash,
                ah_block_hash,
                ah_parent_block_hash,
                is_loading,
            )
            .await?;

            // Cache nomination pools every new session
            try_run_cache_nomination_pools(ev.starting_session, ah_block_number, ah_block_hash)
                .await?;

            // Run matrix reports every new session
            try_run_matrix_reports(records, subscribers, previous_epoch_era_index, is_loading)
                .await?;
        } else if let Some(ev) = event.as_event::<PagedElectionProceeded>()? {
            info!("AH Event {:?}", ev);
        } else if let Some(ev) = event.as_event::<asset_hub_runtime::staking::events::EraPaid>()? {
            info!("AH Event {:?}", ev);
            // Note: Network public report is based on the previous era index and parent hash
            try_run_network_report(ev.era_index, &records, is_loading).await?;
        } else if let Some(ev) = event.as_event::<SessionReportReceived>()? {
            info!("AH Event {:?}", ev);
        } else if let Some(ev) = event.as_event::<OffenceReceived>()? {
            info!("AH Event {:?}", ev);
        } else if let Some(ev) = event.as_event::<OffenceReceived>()? {
            info!("AH Event {:?}", ev);
        }
        // TODO: Handle multi_block events
        //  if pallet == "MultiBlock"
        // || pallet == "MultiBlockVerifier"
        // || pallet == "MultiBlockSigned"
        // || pallet == "MultiBlockUnsigned"
    }

    records.set_asset_hub_block_number(ah_block_number, rc_parent_number);

    // Cache pool stats every 10 minutes
    try_run_cache_nomination_pools_stats(records.current_epoch(), ah_block_number, ah_block_hash)
        .await?;

    // Cache finalized block
    if config.cache_writer_enabled {
        let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;
        cache_finalized_block(&mut cache, ChainKey::AH, ah_block_number.into()).await?;
    }

    Ok(())
}

/// Process session rotated at AH SessionRotated event
pub async fn process_session_rotated(
    rc_api: &OnlineClient<PolkadotConfig>,
    ah_api: &OnlineClient<PolkadotConfig>,
    starting_session: EpochIndex,
    active_era: EraIndex,
    subscribers: &mut Subscribers,
    records: &mut Records,
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
    ah_block_number: BlockNumber,
    ah_block_hash: H256,
) -> Result<EraIndex, OnetError> {
    let config = CONFIG.clone();

    // keep previous era in context
    let previous_era_index = records.current_era().clone();

    // Update records current Era and Epoch
    records.start_new_epoch(active_era, starting_session);

    // Update records current block number
    records.set_relay_chain_block_number(rc_block_number.into());
    records.set_asset_hub_block_number(ah_block_number.into(), rc_block_number.into());

    // Initialize records for new epoch
    initialize_records(
        rc_api,
        ah_api,
        records,
        rc_block_number,
        rc_block_hash,
        ah_block_hash,
    )
    .await?;

    // Update subscribers current Era and Epoch
    subscribers.start_new_epoch(active_era, starting_session);

    if let Ok(subs) = get_subscribers() {
        for (account, user_id, param) in subs.iter() {
            subscribers.subscribe(account.clone(), user_id.to_string(), param.clone());
        }
    }

    // Remove older keys, default is maximum_history_eras + 1
    records.remove(EpochKey(
        records.current_epoch() - ((config.maximum_history_eras + 1) * 6),
    ));
    subscribers.remove(EpochKey(
        records.current_epoch() - ((config.maximum_history_eras + 1) * 6),
    ));

    // Cache current epoch
    let epoch_filename = format!("{}{}", config.data_path, EPOCH_FILENAME);
    fs::write(&epoch_filename, starting_session.to_string())?;

    Ok(previous_era_index)
}

/// Run process_matrix_reports after rotate_session
pub async fn try_run_matrix_reports(
    records: &mut Records,
    subscribers: &mut Subscribers,
    previous_epoch_era_index: EraIndex,
    is_loading: bool,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();

    // Try to run matrix reports
    if config.matrix_disabled || is_loading {
        return Ok(());
    }
    let current_era_index = records.current_era();
    // Send reports from previous session (verify if era_index is the same or previous)
    let era_index: u32 = if current_era_index != previous_epoch_era_index {
        previous_epoch_era_index
    } else {
        current_era_index
    };

    let records_cloned = records.clone();
    let subscribers_cloned = subscribers.clone();
    async_std::task::spawn(async move {
        let epoch_index = records_cloned.current_epoch() - 1;
        if let Err(e) =
            run_val_perf_report(era_index, epoch_index, &records_cloned, &subscribers_cloned).await
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

    Ok(())
}

pub async fn try_run_cache_discovery_records(
    records: &Records,
    block_hash: H256,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if !config.discovery_enabled {
        return Ok(());
    }

    let records_cloned = records.clone();
    async_std::task::spawn(async move {
        if let Err(e) = try_fetch_discovery_data(&records_cloned, block_hash).await {
            error!("try_fetch_discovery_data error: {:?}", e);
        }
    });

    Ok(())
}

pub async fn initialize_records(
    rc_api: &OnlineClient<PolkadotConfig>,
    ah_api: &OnlineClient<PolkadotConfig>,
    records: &mut Records,
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
    ah_block_hash: H256,
) -> Result<(), OnetError> {
    let start = Instant::now();
    // Fetch active validators
    let authorities = super::storage::fetch_authorities(&rc_api, rc_block_hash).await?;

    // Fetch queued keys
    let queued_keys = super::storage::fetch_queued_keys(&rc_api, rc_block_hash).await?;

    // Fetch para validator groups
    let validator_groups = super::storage::fetch_validator_groups(&rc_api, rc_block_hash).await?;

    // Fetch para validator indices
    let active_validator_indices =
        super::storage::fetch_validator_indices(&rc_api, rc_block_hash).await?;

    // Fetch era reward points
    let era_reward_points =
        fetch_era_reward_points(&ah_api, ah_block_hash, records.current_era()).await?;

    // Update records groups with respective authorities
    for (group_idx, group) in validator_groups.iter().enumerate() {
        let auths: Vec<AuthorityIndex> = group
            .iter()
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

        // Verify if is a para_validator
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
                                // Fetch peer points

                                let points = era_reward_points
                                    .as_ref()
                                    .and_then(|erp| {
                                        erp.individual
                                            .0
                                            .iter()
                                            .find(|(s, _)| s == address)
                                            .map(|(_, points)| *points)
                                    })
                                    .unwrap_or(0);

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

                                // Find authority discovery key
                                if let Some((_, keys)) =
                                    queued_keys.iter().find(|(addr, _)| addr == address)
                                {
                                    let Public(authority_discovery_key) = keys.authority_discovery;
                                    let discovery_record =
                                        DiscoveryRecord::with_authority_discovery_key(
                                            authority_discovery_key.clone(),
                                        );

                                    records.set_discovery_record(*auth_idx, discovery_record);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            // Fetch stash points
            let points = era_reward_points
                .as_ref()
                .and_then(|erp| {
                    erp.individual
                        .0
                        .iter()
                        .find(|(s, _)| s == stash)
                        .map(|(_, points)| *points)
                })
                .unwrap_or(0);

            let authority_record =
                AuthorityRecord::with_index_address_and_points(auth_idx, stash.clone(), points);

            records.insert(stash, auth_idx, authority_record, None);

            // Find authority discovery key
            if let Some((_, keys)) = queued_keys.iter().find(|(addr, _)| addr == stash) {
                let Public(authority_discovery_key) = keys.authority_discovery;
                let discovery_record =
                    DiscoveryRecord::with_authority_discovery_key(authority_discovery_key.clone());

                records.set_discovery_record(auth_idx, discovery_record);
            }
        }
    }
    // debug!("records {:?}", records);

    // Log records initialization duration time
    info!(
        "RC records initialized at #{} ({:?})",
        rc_block_number,
        start.elapsed()
    );

    Ok(())
}

/// Fetch validator points and track points collected per authority
async fn fetch_and_track_authority_points(
    api: &OnlineClient<PolkadotConfig>,
    records: &mut Records,
    block_authority_index: AuthorityIndex,
    session_index: SessionIndex,
    block_hash: H256,
) -> Result<(), OnetError> {
    let validator_points_addr = relay_runtime::storage()
        .staking_ah_client()
        .validator_points_iter();
    let mut iter = api
        .storage()
        .at(block_hash)
        .iter(validator_points_addr)
        .await?;
    while let Some(Ok(storage_resp)) = iter.next().await {
        let stash = get_account_id_from_storage_key(storage_resp.key_bytes);
        let mut latest_points_collected: u32 = 0;
        if let Some(authority_record) =
            records.get_mut_authority_record_with_address(&stash, Some(EpochKey(session_index)))
        {
            if authority_record.address().is_some() {
                // Update authority current points and get the difference
                latest_points_collected =
                    authority_record.update_current_points(storage_resp.value);
            }

            if let Some(authority_idx) = authority_record.authority_index() {
                // Get para_record for the same session
                if let Some(para_record) =
                    records.get_mut_para_record(authority_idx, Some(session_index))
                {
                    para_record.update_points(
                        latest_points_collected,
                        block_authority_index == authority_idx,
                    );
                }
            }
        }
    }

    Ok(())
}

/// Track authority votes per authority
fn track_authority_votes(
    records: &mut Records,
    backing_votes: &OnChainVotes,
    validator_groups: &ValidatorGroups,
    active_validator_indices: &ActiveValidatorIndices,
) -> Result<(), OnetError> {
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

                if let Some((_, vote)) = group_authorities
                    .iter()
                    .find(|(ValidatorIndex(para_idx), _)| *para_idx == *group_para_val_idx)
                {
                    // get authority index from active_validator_indices
                    if let Some(ValidatorIndex(auth_idx)) =
                        active_validator_indices.get(*group_para_val_idx as usize)
                    {
                        // NOTE: in case there are less backing authorities than the original group len it means that someone is missing.
                        // keep track of the ones present so that the ones missing could be identified later
                        if group_authorities.len() < group.len() {
                            authorities_present.push(*auth_idx);
                            para_id_flagged = Some(para_id);
                        }

                        // get para_record for the same on chain votes session
                        if let Some(para_record) =
                            records.get_mut_para_record(*auth_idx, Some(backing_votes.session))
                        {
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
    Ok(())
}

/// Track initiated disputes per authority
fn track_disputes(
    records: &mut Records,
    backing_votes: &OnChainVotes,
    active_validator_indices: &ActiveValidatorIndices,
    block_number: BlockNumber,
) -> Result<(), OnetError> {
    for dispute_statement_set in backing_votes.disputes.iter() {
        for (statement, ValidatorIndex(para_idx), _) in dispute_statement_set.statements.iter() {
            match statement {
                DisputeStatement::Invalid(_) => {
                    if let Some(ValidatorIndex(auth_idx)) =
                        active_validator_indices.get(*para_idx as usize)
                    {
                        // Log stash address for the initiated dispute
                        if let Some(authority_record) =
                            records.get_mut_authority_record(*auth_idx, Some(backing_votes.session))
                        {
                            if let Some(stash) = authority_record.address() {
                                warn!(
                                    "Dispute initiated for stash: {} ({}) {:?}",
                                    stash, auth_idx, statement
                                );
                            }
                        }
                        // Get para_record for the same on chain votes session
                        if let Some(para_record) =
                            records.get_mut_para_record(*auth_idx, Some(backing_votes.session))
                        {
                            para_record.push_dispute(block_number, format!("{:?}", statement));
                        }
                    } else {
                        warn!("Dispute initiated at block {block_number} but authority record for para_idx: {para_idx} not found!");
                    }
                }
                _ => continue,
            }
        }
    }

    Ok(())
}

/// Fetch and track the core assigned to a para_id from para_inclusion.v1 storage
async fn fetch_and_track_core_assignments(
    api: &OnlineClient<PolkadotConfig>,
    records: &mut Records,
    backing_votes: &OnChainVotes,
    block_hash: H256,
) -> Result<(), OnetError> {
    let paras_inclusion_addr = relay_runtime::storage().para_inclusion().v1_iter();
    let mut iter = api
        .storage()
        .at(block_hash)
        .iter(paras_inclusion_addr)
        .await?;
    while let Some(Ok(storage_resp)) = iter.next().await {
        for candidate_pending_availability in storage_resp.value {
            let CoreIndex(core_index) = candidate_pending_availability.core;
            let Id(para_id) = candidate_pending_availability.descriptor.para_id;

            records.update_core_by_para_id(para_id, core_index, Some(backing_votes.session));
        }
    }
    Ok(())
}

/// Fetch block extrinsics and track data availability per authority
async fn fetch_and_track_availability(
    api: &OnlineClient<PolkadotConfig>,
    records: &mut Records,
    backing_votes: &OnChainVotes,
    active_validator_indices: &ActiveValidatorIndices,
    block_number: BlockNumber,
    block_hash: H256,
) -> Result<(), OnetError> {
    // NOTE: authorities_present vec will contain the authorities present in para_inherent.data.bitfields and it's useful
    // to increase unavailability to the authorities not present
    let mut authorities_present = Vec::new();
    let extrinsics = api.blocks().at(block_hash).await?.extrinsics().await?;
    for res in extrinsics.find::<Enter>() {
        let extrinsic = res?;
        for availability_bitfield in extrinsic.value.data.bitfields.iter() {
            // Note: availability_bitfield.validator_index is the index of the validator in the paras_shared.active_validator_indices
            let ValidatorIndex(para_idx) = &availability_bitfield.validator_index;

            if let Some(ValidatorIndex(auth_idx)) = active_validator_indices.get(*para_idx as usize)
            {
                // Get para_record for the same on chain votes session
                if let Some(para_record) =
                    records.get_mut_para_record(*auth_idx, Some(backing_votes.session))
                {
                    let AvailabilityBitfield(decoded_bits) = &availability_bitfield.payload;
                    if decoded_bits.as_bits().iter().any(|x| x) {
                        para_record.inc_availability();
                    } else {
                        para_record.push_unavailable_at(block_number);
                    }
                }
                // Keep track of the authorities that show up in para_inherent.data.bitfields
                authorities_present.push(*auth_idx);
            }
        }
    }
    // Also increase unavailability to the authorities that do not show up in para_inherent.data.bitfields
    if active_validator_indices.len() != authorities_present.len() {
        for ValidatorIndex(auth_idx) in active_validator_indices.iter() {
            if !authorities_present.contains(auth_idx) {
                if let Some(para_record) =
                    records.get_mut_para_record(*auth_idx, Some(backing_votes.session))
                {
                    para_record.push_unavailable_at(block_number);
                }
            }
        }
    }
    Ok(())
}

pub async fn track_records(
    rc_api: &OnlineClient<PolkadotConfig>,
    rc_rpc: &LegacyRpcMethods<PolkadotConfig>,
    records: &mut Records,
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
) -> Result<(), OnetError> {
    // Update records current block number
    records.set_relay_chain_block_number(rc_block_number.into());

    // Extract authority from the block header
    let block_authority_index = get_authority_index(&rc_rpc, Some(rc_block_hash))
        .await?
        .ok_or_else(|| OnetError::from("Authority index not found"))?;

    // Fetch session index
    let session_index = super::storage::fetch_session_index(&rc_api, rc_block_hash).await?;

    // Track block authored
    if let Some(authority_record) =
        records.get_mut_authority_record(block_authority_index, Some(session_index))
    {
        authority_record.push_authored_block(rc_block_number);
    }

    // Fetch para validator groups
    let validator_groups = super::storage::fetch_validator_groups(&rc_api, rc_block_hash).await?;

    // Fetch para validator indices
    let active_validator_indices =
        super::storage::fetch_validator_indices(&rc_api, rc_block_hash).await?;

    // Fetch on chain votes
    let backing_votes = super::storage::fetch_on_chain_votes(&rc_api, rc_block_hash).await?;

    // Fetch and Track authority points
    fetch_and_track_authority_points(
        &rc_api,
        records,
        block_authority_index,
        session_index,
        rc_block_hash,
    )
    .await?;

    // Track authority votes
    track_authority_votes(
        records,
        &backing_votes,
        &validator_groups,
        &active_validator_indices,
    )?;

    // Track disputes
    track_disputes(
        records,
        &backing_votes,
        &active_validator_indices,
        rc_block_number,
    )?;

    // Fetch and Track core assignments
    fetch_and_track_core_assignments(&rc_api, records, &backing_votes, rc_block_hash).await?;

    // Fetch and Track availability
    fetch_and_track_availability(
        &rc_api,
        records,
        &backing_votes,
        &active_validator_indices,
        rc_block_number,
        rc_block_hash,
    )
    .await?;

    debug!("records {:?}", records);

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
        .start_block(Some(EpochKey(epoch_index)))
        .unwrap_or(&0);
    let end_block = records.end_block(Some(EpochKey(epoch_index))).unwrap_or(&0);
    let metadata = ReportMetadata {
        active_era_index: era_index,
        current_session_index: epoch_index,
        blocks_interval: Some((*start_block, *end_block)),
        ..Default::default()
    };

    // Fetch parachains list
    // TODO: get parachains names
    let mut parachains: Vec<ParaId> = Vec::new();
    let parachains_addr = relay_runtime::storage().paras().parachains();
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

    if let Some(authorities) = records.get_authorities(Some(EpochKey(epoch_index))) {
        for authority_idx in authorities.iter() {
            if let Some(para_record) =
                records.get_para_record(*authority_idx, Some(EpochKey(epoch_index)))
            {
                if let Some(group_idx) = para_record.group() {
                    if let Some(authority_record) =
                        records.get_authority_record(*authority_idx, Some(EpochKey(epoch_index)))
                    {
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
    if let Some(subs) = subscribers.get(Some(EpochKey(epoch_index))) {
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

            if let Some(authority_record) =
                records.get_authority_record_with_address(&stash, Some(EpochKey(epoch_index)))
            {
                data.authority_record = Some(authority_record.clone());

                if let Some(para_record) =
                    records.get_para_record_with_address(&stash, Some(EpochKey(epoch_index)))
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
                            Some(EpochKey(epoch_index)),
                        ) {
                            if let Some(peer_stash) = peer_authority_record.address() {
                                let peer_name = get_display_name(&onet, &peer_stash).await?;

                                if let Some(peer_para_record) = records.get_para_record(
                                    *peer_authority_index,
                                    Some(EpochKey(epoch_index)),
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
        .start_block(Some(EpochKey(epoch_index)))
        .unwrap_or(&0);
    let end_block = records.end_block(Some(EpochKey(epoch_index))).unwrap_or(&0);
    let metadata = ReportMetadata {
        active_era_index: era_index,
        current_session_index: epoch_index,
        blocks_interval: Some((*start_block, *end_block)),
        ..Default::default()
    };

    // Populate some maps to get ranks
    let mut group_authorities_map: BTreeMap<u32, Vec<(AuthorityRecord, ParaRecord, String)>> =
        BTreeMap::new();

    if let Some(authorities) = records.get_authorities(Some(EpochKey(epoch_index))) {
        for authority_idx in authorities.iter() {
            if let Some(para_record) =
                records.get_para_record(*authority_idx, Some(EpochKey(epoch_index)))
            {
                if let Some(group_idx) = para_record.group() {
                    if let Some(authority_record) =
                        records.get_authority_record(*authority_idx, Some(EpochKey(epoch_index)))
                    {
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
        .start_block(Some(EpochKey(epoch_index)))
        .unwrap_or(&0);
    let end_block = records.end_block(Some(EpochKey(epoch_index))).unwrap_or(&0);
    let metadata = ReportMetadata {
        active_era_index: era_index,
        current_session_index: epoch_index,
        blocks_interval: Some((*start_block, *end_block)),
        ..Default::default()
    };

    // Populate some maps to get ranks
    let mut parachains_map: BTreeMap<ParaId, ParaStats> = BTreeMap::new();

    if let Some(authorities) = records.get_authorities(Some(EpochKey(epoch_index))) {
        for authority_idx in authorities.iter() {
            if let Some(para_record) =
                records.get_para_record(*authority_idx, Some(EpochKey(epoch_index)))
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
    era_index: EraIndex,
    records: &Records,
    is_loading: bool,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.matrix_disabled || config.matrix_network_report_disabled || is_loading {
        return Ok(());
    }
    if records.total_full_epochs() == 0 {
        warn!("No full sessions yet to run the network report.");
        return Ok(());
    }
    let records_cloned = records.clone();
    async_std::task::spawn(async move {
        if let Err(e) = run_network_report(era_index, &records_cloned).await {
            error!("try_run_network_report error: {:?}", e);
        }
    });

    Ok(())
}

pub async fn run_network_report(
    active_era_index: EraIndex,
    records: &Records,
) -> Result<(), OnetError> {
    let onet: Onet = Onet::new().await;
    let config = CONFIG.clone();
    let rc_api = onet.relay_client().clone();
    let rc_rpc = onet.relay_rpc().clone();
    let ah_api = onet
        .asset_hub_client()
        .as_ref()
        .expect("AH API to be available");

    let network = Network::load(onet.rpc()).await?;

    // Note: the network report is triggered when a session is rotated, or previous era paid;
    // At this points records must have been already actualized with the new session authorities,
    // and we want the report to be based on the previous eras, so we get the previous session index
    // stored in the records and the last block hash of the previous session
    let current_session_index = records.current_epoch() - 1;

    // Get the last block number of the previous session from records
    let Some(rc_block_number) = records.end_block(Some(EpochKey(current_session_index))) else {
        return Err(OnetError::from(format!(
            "Last block number not available for session {current_session_index}"
        )));
    };

    let rc_block_hash = try_fetch_relay_chain_block_hash(&rc_rpc, *rc_block_number).await?;

    let ah_block_hash =
        fetch_asset_hub_block_hash_from_relay_chain(&onet, *rc_block_number, rc_block_hash).await?;

    // Fetch active era total stake
    let active_era_total_stake =
        fetch_eras_total_stake(&ah_api, ah_block_hash, active_era_index).await?;

    // Set era/session details
    let metadata = ReportMetadata {
        active_era_index,
        current_session_index,
        active_era_total_stake,
        ..Default::default()
    };

    let mut validators: Validators = Vec::new();

    // Load TVP stashes
    let tvp_stashes: Vec<AccountId32> = if onet.runtime().is_dn_supported() {
        try_fetch_stashes_from_remote_url(false, None).await?
    } else {
        Vec::new()
    };

    // Fetch authorities
    let authorities = super::storage::fetch_authorities(&rc_api, rc_block_hash).await?;

    // Fetch all validators
    let validators_addr = asset_hub_runtime::storage().staking().validators_iter();
    let mut iter = ah_api
        .storage()
        .at(ah_block_hash)
        .iter(validators_addr)
        .await?;
    while let Some(Ok(storage_resp)) = iter.next().await {
        let stash = get_account_id_from_storage_key(storage_resp.key_bytes);
        let mut v = Validator::new(stash.clone());
        if storage_resp.value.commission != Perbill(1000000000) {
            if !tvp_stashes.contains(&stash) {
                v.subset = Subset::NONTVP;
            } else {
                v.subset = Subset::TVP;
            }
        } else {
            v.subset = Subset::C100;
        }
        // Commisssion
        let Perbill(commission) = storage_resp.value.commission;
        v.commission = commission as f64 / 1_000_000_000.0_f64;
        // Check if validator is in active set
        v.is_active = authorities.contains(&stash);

        // Fetch own stake
        v.own_stake = fetch_own_stake_via_stash(&ah_api, ah_block_hash, &stash).await?;

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
                bitfields_availability,
                bitfields_unavailability,
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
                if bitfields_availability + bitfields_unavailability > 0 {
                    let bar = bitfields_availability as f64
                        / (bitfields_availability + bitfields_unavailability) as f64;
                    v.bitfields_availability_ratio = Some(bar);
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
        // Fetch Era reward points
        let era_reward_points = fetch_era_reward_points(&ah_api, ah_block_hash, era_index).await?;
        if let Some(erp) = era_reward_points {
            for (stash, points) in erp.individual.0.iter() {
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
    // SCORE_1 = (1-MVR)*0.50 + BAR*0.25 + ((AVG_PV_POINTS - MIN_AVG_POINTS)/(MAX_AVG_PV_POINTS-MIN_AVG_PV_POINTS))*0.18 + (PV_SESSIONS/TOTAL_SESSIONS)*0.07
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
                (1.0_f64 - v.missed_ratio.unwrap_or_default()) * 0.50_f64
                    + v.bitfields_availability_ratio.unwrap_or_default() * 0.25_f64
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
                .start_block(Some(EpochKey(start_epoch)))
                .unwrap_or(&0);

            let end_epoch = current_session_index - 1;
            if let Some(end_era) = records.get_era_index(Some(end_epoch)) {
                let end_block = records
                    .end_block(Some(EpochKey(current_session_index - 1)))
                    .unwrap_or(&0);
                let metadata = ReportMetadata {
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
) -> Result<AssetHubCall, OnetError> {
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

        let nominees = validators
            .iter()
            .map(|v| v.stash.clone())
            .collect::<Vec<AccountId32>>();

        // Load featured stashes
        let stashes: Vec<String> = config.pools_featured_nominees;
        info!(
            "{} featured nominees loaded from 'config.pools_featured_nominees'",
            stashes.len()
        );

        let mut accounts: Vec<AccountId32> = stashes
            .iter()
            .map(|s| AccountId32::from_str(&s).unwrap())
            .collect();

        accounts.extend(nominees);
        accounts.truncate(max);

        // Define call
        let call = AssetHubCall::NominationPools(NominationPoolsCall::nominate {
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
) -> Result<AssetHubCall, OnetError> {
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
        let call = AssetHubCall::NominationPools(NominationPoolsCall::nominate {
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

// DEPRECATED: Being left here for now as comments for future reference/use

// * APR is the annualized average of all stashes from the last X eras.
// pub async fn _calculate_apr_from_stashes(
//     onet: &Onet,
//     stashes: Vec<AccountId32>,
//     block_hash: H256,
// ) -> Result<f64, OnetError> {
//     let start = Instant::now();
//     let api = onet.client().clone();
//     let config = CONFIG.clone();

//     // Fetch active era index
//     let active_era_addr = relay_runtime::storage().staking().active_era();
//     let active_era_index = match api.storage().at(block_hash).fetch(&active_era_addr).await? {
//         Some(info) => info.index,
//         None => return Err("Active era not defined".into()),
//     };

//     let mut total_eras: u128 = 0;
//     let mut total_points: u128 = 0;
//     let mut total_reward: u128 = 0;
//     let mut nominees_total_eras: u128 = 0;
//     let mut nominees_total_points: u128 = 0;
//     let mut nominees_total_stake: u128 = 0;
//     let mut nominees_total_commission: u128 = 0;

//     // Collect stash commission
//     for stash in stashes.iter() {
//         let validator_addr = relay_runtime::storage().staking().validators(stash);
//         if let Some(validator) = api.storage().at(block_hash).fetch(&validator_addr).await? {
//             let Perbill(commission) = validator.commission;
//             nominees_total_commission += commission as u128;
//         }
//     }

//     // Collect chain data for maximum_history_eras
//     // let start_era_index = active_era_index - config.maximum_history_eras;
//     let start_era_index = active_era_index - 84;
//     for era_index in start_era_index..active_era_index {
//         // Fetch Era reward points
//         let era_reward_points_addr = relay_runtime::storage()
//             .staking()
//             .eras_reward_points(&era_index);
//         if let Some(era_reward_points) = api
//             .storage()
//             .at(block_hash)
//             .fetch(&era_reward_points_addr)
//             .await?
//         {
//             for (stash, points) in era_reward_points.individual.iter() {
//                 if stashes.contains(stash) {
//                     nominees_total_eras += 1;
//                     nominees_total_points += *points as u128;

//                     // Fetch Era stakers
//                     let eras_stakers_addr = relay_runtime::storage()
//                         .staking()
//                         .eras_stakers(&era_index, stash);
//                     if let Some(eras_stakers) = api
//                         .storage()
//                         .at(block_hash)
//                         .fetch(&eras_stakers_addr)
//                         .await?
//                     {
//                         nominees_total_stake += eras_stakers.total;
//                     }
//                 }
//             }
//             total_points += era_reward_points.total as u128;
//             total_eras += 1;

//             // Fetch Era validator reward
//             let eras_validator_reward_addr = relay_runtime::storage()
//                 .staking()
//                 .eras_validator_reward(&era_index);
//             if let Some(eras_validator_reward) = api
//                 .storage()
//                 .at(block_hash)
//                 .fetch(&eras_validator_reward_addr)
//                 .await?
//             {
//                 total_reward += eras_validator_reward;
//             }
//         }
//     }

//     debug!(
//         "nominees_total_eras: {} nominees_total_points: {} nominees_total_stake: {}",
//         nominees_total_eras, nominees_total_points, nominees_total_stake
//     );
//     debug!(
//         "total_eras: {} total_points: {} total_reward: {}",
//         total_eras, total_points, total_reward
//     );

//     if nominees_total_eras > 0 {
//         let avg_points_per_nominee_per_era = nominees_total_points / nominees_total_eras;
//         debug!(
//             "avg_points_per_nominee_per_era: {}",
//             avg_points_per_nominee_per_era
//         );
//         let avg_stake_per_nominee_per_era = nominees_total_stake / nominees_total_eras;
//         debug!(
//             "avg_stake_per_nominee_per_era: {}",
//             avg_stake_per_nominee_per_era
//         );
//         let avg_reward_per_era = total_reward / total_eras;
//         debug!("avg_reward_per_era: {}", avg_reward_per_era);
//         let avg_points_per_era = total_points / total_eras;
//         debug!("avg_points_per_era: {}", avg_points_per_era);

//         let avg_reward_per_nominee_per_era =
//             (avg_points_per_nominee_per_era * avg_reward_per_era) / avg_points_per_era;
//         debug!(
//             "avg_reward_per_nominee_per_era: {}",
//             avg_reward_per_nominee_per_era
//         );

//         let avg_commission_per_nominee = nominees_total_commission / stashes.len() as u128;
//         debug!("avg_commission_per_nominee: {}", avg_commission_per_nominee);

//         let commission = avg_commission_per_nominee as f64 / 1_000_000_000.0_f64;
//         let apr: f64 = (avg_reward_per_nominee_per_era as f64 * (1.0 - commission))
//             * (1.0 / avg_stake_per_nominee_per_era as f64)
//             * config.eras_per_day as f64
//             * 365.0;
//         debug!("APR: {} calculated ({:?})", apr, start.elapsed());
//         Ok(apr)
//     } else {
//         Ok(0.0_f64)
//     }
// }

// ***************************************
// NOMINATION POOLS ON ASSET HUB
//  ***************************************
pub async fn try_run_cache_nomination_pools(
    epoch_index: EpochIndex,
    ah_block_number: BlockNumber,
    ah_block_hash: H256,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.cache_writer_enabled && config.pools_enabled {
        async_std::task::spawn(async move {
            if let Err(e) =
                cache_nomination_pools(epoch_index, ah_block_number, ah_block_hash).await
            {
                error!("cache_nomination_pools error: {:?}", e);
            }
        });

        async_std::task::spawn(async move {
            if let Err(e) =
                cache_nomination_pools_stats(epoch_index, ah_block_number, ah_block_hash).await
            {
                error!("cache_nomination_pools_stats error: {:?}", e);
            }
        });

        // NOTE: network_report is issued every era we could use the same config to cache nomination pools APR
        // but since the APR is based on the current nominees and these can be changed within the session
        // we calculate the APR every new session for now
        async_std::task::spawn(async move {
            if let Err(e) =
                cache_nomination_pools_nominees(epoch_index, ah_block_number, ah_block_hash).await
            {
                error!("cache_nomination_pools_nominees error: {:?}", e);
            }
        });
    }
    Ok(())
}

pub async fn try_run_cache_nomination_pools_stats(
    epoch_index: EpochIndex,
    ah_block_number: BlockNumber,
    ah_block_hash: H256,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if !config.cache_writer_enabled || !config.pools_enabled {
        return Ok(());
    }

    // collect nomination stats every minute
    if (ah_block_number as f64 % 10.0_f64) == 0.0_f64 {
        async_std::task::spawn(async move {
            if let Err(e) =
                cache_nomination_pools_stats(epoch_index, ah_block_number, ah_block_hash).await
            {
                error!("cache_nomination_pools_stats error: {:?}", e);
            }
        });
    }
    Ok(())
}

pub async fn cache_nomination_pools(
    epoch_index: EpochIndex,
    ah_block_number: BlockNumber,
    ah_block_hash: H256,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let start = Instant::now();
    let onet: Onet = Onet::new().await;
    let ah_api = onet
        .asset_hub_client()
        .as_ref()
        .expect("AH API to be available");
    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

    let last_pool_id = fetch_last_pool_id(&ah_api, ah_block_hash).await?;

    let mut some_pool = Some(1);
    while let Some(pool_id) = some_pool {
        if pool_id > last_pool_id {
            some_pool = None;
        } else {
            // Verify if pool is valid
            match fetch_bonded_pools(&ah_api, ah_block_hash, pool_id).await {
                Ok(bonded) => {
                    let metadata = fetch_pool_metadata(&ah_api, ah_block_hash, pool_id).await?;
                    let BoundedVec(metadata) = metadata;
                    let metadata = bytes_to_str(metadata);
                    let mut pool = Pool::with_id_and_metadata(pool_id, metadata.clone());

                    let state = match bonded.state {
                        PoolState::Blocked => onet_pools::PoolState::Blocked,
                        PoolState::Destroying => onet_pools::PoolState::Destroying,
                        _ => onet_pools::PoolState::Open,
                    };
                    pool.state = state;

                    // assign roles
                    let mut depositor = Account::with_address(bonded.roles.depositor.clone());
                    depositor.identity = get_identity(&onet, &bonded.roles.depositor, None).await?;
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
                    pool.block_number = ah_block_number;

                    cache_nomination_pool(&mut cache, &config, &pool, pool_id, epoch_index).await?;
                }
                Err(e) => debug!("{:?} {}", {}, e),
            }

            some_pool = Some(pool_id + 1);
        }
    }

    // Log cache processed duration time
    info!(
        "AH Pools status cached #{} ({:?})",
        ah_block_number,
        start.elapsed()
    );

    Ok(())
}

pub async fn cache_nomination_pools_stats(
    epoch_index: EpochIndex,
    ah_block_number: BlockNumber,
    ah_block_hash: H256,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let start = Instant::now();
    let onet: Onet = Onet::new().await;
    let ah_api = onet
        .asset_hub_client()
        .as_ref()
        .expect("AH API to be available");
    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

    let last_pool_id = fetch_last_pool_id(&ah_api, ah_block_hash).await?;

    let mut some_pool = Some(1);
    while let Some(pool_id) = some_pool {
        if pool_id > last_pool_id {
            some_pool = None;
        } else {
            // Verify if pool is valid
            match fetch_bonded_pools(&ah_api, ah_block_hash, pool_id).await {
                Ok(bonded) => {
                    let mut pool_stats = PoolStats::new();
                    pool_stats.block_number = ah_block_number;

                    pool_stats.points = bonded.points;
                    pool_stats.member_counter = bonded.member_counter;

                    // fetch pool stash account staked amount from staking pallet
                    let stash_account = nomination_pool_account(AccountType::Bonded, pool_id);

                    let staking_ledger =
                        fetch_ledger_from_controller(&ah_api, ah_block_hash, &stash_account)
                            .await?;
                    pool_stats.staked = staking_ledger.active;
                    pool_stats.unbonding = staking_ledger.total - staking_ledger.active;

                    // fetch pool reward account free amount
                    let stash_account = nomination_pool_account(AccountType::Reward, pool_id);
                    let account_info =
                        fetch_account_info(&ah_api, ah_block_hash, stash_account).await?;
                    pool_stats.reward = account_info.data.free;

                    cache_nomination_pool_stats(
                        &mut cache,
                        &config,
                        &pool_stats,
                        pool_id,
                        epoch_index,
                    )
                    .await?;
                }
                Err(e) => debug!("{:?} {}", {}, e),
            }

            some_pool = Some(pool_id + 1);
        }
    }
    // Log cache processed duration time
    info!(
        "AH Pools stats cached #{} ({:?})",
        ah_block_number,
        start.elapsed()
    );

    Ok(())
}

pub async fn cache_nomination_pools_nominees(
    epoch_index: EpochIndex,
    ah_block_number: BlockNumber,
    ah_block_hash: H256,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let start = Instant::now();
    let onet: Onet = Onet::new().await;
    let ah_api = onet
        .asset_hub_client()
        .as_ref()
        .expect("AH API to be available");
    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

    // fetch last pool id
    let last_pool_id = fetch_last_pool_id(&ah_api, ah_block_hash).await?;

    let active_era_info = fetch_active_era_info(&ah_api, ah_block_hash).await?;
    let era_index = active_era_info.index;

    let mut some_pool = Some(1);
    while let Some(pool_id) = some_pool {
        if pool_id > last_pool_id {
            some_pool = None;
        } else {
            // Verify if pool is valid
            match fetch_bonded_pools(&ah_api, ah_block_hash, pool_id).await {
                Ok(_) => {
                    let mut pool_nominees = PoolNominees::new();
                    pool_nominees.block_number = ah_block_number;
                    let pool_stash_account = nomination_pool_account(AccountType::Bonded, pool_id);

                    // fetch pool nominees
                    let Ok(nominations) =
                        fetch_nominators(&ah_api, ah_block_hash, pool_stash_account.clone()).await
                    else {
                        debug!(
                            "Failed to fetch pool nominees for pool ID: {} with stash account: {}",
                            pool_id, pool_stash_account
                        );
                        cache_nomination_pool_nominees(
                            &mut cache,
                            &config,
                            &pool_nominees,
                            pool_id,
                            epoch_index,
                        )
                        .await?;

                        some_pool = Some(pool_id + 1);
                        continue;
                    };

                    // deconstruct targets
                    let BoundedVec(stashes) = nominations.targets;

                    // DEPRECATE calculate APR
                    // pool_nominees.apr =
                    //     calculate_apr_from_stashes(&onet, stashes.clone(), block_hash).await?;

                    pool_nominees.nominees = stashes.clone();

                    let mut active = Vec::<ActiveNominee>::new();
                    // check active nominees
                    for stash in stashes {
                        // Identify which active validators have pool stake assigned
                        let eras_stakers_paged_addr = asset_hub_runtime::storage()
                            .staking()
                            .eras_stakers_paged_iter2(era_index, stash.clone());
                        let mut iter = ah_api
                            .storage()
                            .at(ah_block_hash)
                            .iter(eras_stakers_paged_addr)
                            .await?;

                        while let Some(Ok(storage_kv)) = iter.next().await {
                            let BoundedExposurePage(exposure) = storage_kv.value;
                            if let Some(individual) = exposure
                                .others
                                .iter()
                                .find(|x| x.who == pool_stash_account.clone())
                            {
                                active.push(ActiveNominee::with(stash.clone(), individual.value));
                            }
                        }
                    }
                    pool_nominees.active = active;

                    cache_nomination_pool_nominees(
                        &mut cache,
                        &config,
                        &pool_nominees,
                        pool_id,
                        epoch_index,
                    )
                    .await?;
                }
                Err(e) => debug!("{:?} {}", {}, e),
            }
            some_pool = Some(pool_id + 1);
        }
    }
    // Log cache processed duration time
    info!(
        "AH Pools nominees cached #{} ({:?})",
        ah_block_number,
        start.elapsed()
    );

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
    let mut calls: Vec<AssetHubCall> = vec![];

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
        let tx = asset_hub_runtime::tx().utility().batch(calls).unvalidated();

        let mut tx_progress = api
            .tx()
            .sign_and_submit_then_watch_default(&tx, &signer)
            .await?;

        while let Some(status) = tx_progress.next().await {
            match status? {
                TxStatus::InFinalizedBlock(in_block) => {
                    // Get block number
                    let block_number = if let Some(header) = onet
                        .rpc()
                        .chain_get_header(Some(in_block.block_hash()))
                        .await?
                    {
                        header.number
                    } else {
                        0
                    };

                    // Fetch events from block
                    let tx_events = in_block.fetch_events().await?;

                    //
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
                        return Ok(message);
                    }
                }
                other => {
                    warn!("TxStatus: {other:?}");
                }
            }
        }
    }
    Err(OnetError::PoolError(
        format!("Nomination for pools ({}, {}) failed since there are No calls for the batch call nomination.", config.pool_id_1,
        config.pool_id_2,),
    ))
}

async fn get_authority_index(
    rpc: &LegacyRpcMethods<PolkadotConfig>,
    block_hash: Option<H256>,
) -> Result<Option<AuthorityIndex>, OnetError> {
    if let Some(header) = rpc.chain_get_header(block_hash).await? {
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

/// Cache records at the start of each session
pub async fn try_run_init_cache_records_at_new_session(
    onet: &Onet,
    records: &mut Records,
    ah_block_hash: H256,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if !config.cache_writer_enabled {
        return Ok(());
    }

    let ah_api = onet
        .asset_hub_client()
        .as_ref()
        .expect("AH API to be available");

    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;
    let first_session_index = fetch_first_session_from_active_era(&ah_api, ah_block_hash).await?;

    cache_records_at_new_session(&mut cache, records, first_session_index).await?;

    Ok(())
}

/// Cache session stats records every new session
/// The block hash given should be from the parent block where the
/// `NewSession` event is present.
pub async fn try_run_cache_session_stats_records(
    session_index: EpochIndex,
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
    rc_parent_block_hash: H256,
    ah_block_hash: H256,
    ah_parent_block_hash: H256,
    is_loading: bool,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if !config.cache_writer_enabled {
        return Ok(());
    }

    async_std::task::spawn(async move {
        if let Err(e) = cache_session_stats_records(
            session_index,
            rc_block_number,
            rc_block_hash,
            rc_parent_block_hash,
            ah_block_hash,
            ah_parent_block_hash,
            is_loading,
        )
        .await
        {
            error!("try_run_cache_session_stats_records error: {:?}", e);
        }
    });

    Ok(())
}

/// ---
/// cache all validators profile and snapshot session stats at the last block of the session
pub async fn cache_session_stats_records(
    epoch_index: EpochIndex,
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
    rc_parent_block_hash: H256,
    ah_block_hash: H256,
    ah_parent_block_hash: H256,
    is_loading: bool,
) -> Result<(), OnetError> {
    let start = Instant::now();
    let config = CONFIG.clone();
    let onet: Onet = Onet::new().await;
    let rc_api = onet.client().clone();
    let ah_api = onet
        .asset_hub_client()
        .as_ref()
        .expect("AH API to be available");
    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

    // Load network details
    let network = Network::load(onet.rpc()).await?;

    // initialize network stats (cached syncing status)
    let mut nss = NetworkSessionStats::new(epoch_index, rc_block_number);

    // Initialize validators vec
    let mut validators: Vec<ValidatorProfileRecord> = Vec::new();

    // Collect Nominators data (** heavy duty task **)
    let nominators_map = collect_nominators_data(&ah_api, ah_block_hash).await?;

    // Load TVP stashes
    let tvp_stashes: Vec<AccountId32> = if onet.runtime().is_dn_supported() {
        try_fetch_stashes_from_remote_url(is_loading, None).await?
    } else {
        Vec::new()
    };

    // Fetch active validators
    let authorities = super::storage::fetch_authorities(&rc_api, rc_block_hash).await?;

    // Fetch all validators
    let validators_addr = asset_hub_runtime::storage().staking().validators_iter();
    let mut iter = ah_api
        .storage()
        .at(ah_block_hash)
        .iter(validators_addr)
        .await?;
    while let Some(Ok(storage_resp)) = iter.next().await {
        // validator stash address
        let stash = get_account_id_from_storage_key(storage_resp.key_bytes);
        // create a new validator instance
        let mut profile = ValidatorProfileRecord::new(stash.clone());
        // validator controller address
        let Ok(controller) = fetch_bonded_controller_account(ah_api, ah_block_hash, &stash).await
        else {
            warn!("Failed to fetch bonded_controller for stash {:?}", stash);
            continue;
        };
        profile.controller = Some(controller.clone());
        // get own stake
        profile.own_stake = fetch_own_stake_via_stash(&ah_api, ah_block_hash, &controller).await?;

        // deconstruct commisssion
        let Perbill(commission) = storage_resp.value.commission;
        profile.commission = commission;

        // verify subset (1_000_000_000 = 100% commission)
        profile.subset = if commission != 1_000_000_000 {
            if !tvp_stashes.contains(&stash) {
                Subset::NONTVP
            } else {
                Subset::TVP
            }
        } else {
            Subset::C100
        };

        // check if is in active set
        profile.is_active = authorities.contains(&stash);

        // calculate session mvr and avg it with previous value
        profile.mvr = try_calculate_avg_mvr_by_session_and_stash_from_cache(
            &onet,
            epoch_index,
            stash.clone(),
        )
        .await?;
        // keep track of when mvr was updated
        if profile.mvr.is_some() {
            profile.mvr_session = Some(epoch_index);
        }

        // check if block nominations
        profile.is_blocked = storage_resp.value.blocked;

        // get identity
        profile.identity = get_identity(&onet, &stash, None).await?;

        // set nominators data
        if let Some(nominators) = nominators_map.get(&stash) {
            // TODO: Perhaps keep nominator stashes in a different struct
            // let nominators_stashes = nominators
            //     .iter()
            //     .map(|(x, _, _)| x.to_string())
            //     .collect::<Vec<String>>()
            //     .join(",");

            profile.nominators_stake = nominators.iter().map(|(_, x, _)| x).sum();
            profile.nominators_raw_stake = nominators.iter().map(|(_, x, y)| x / y).sum();
            profile.nominators_counter = nominators.len().try_into().unwrap();
        }

        cache_validator_profile(&mut cache, &config, &profile, &network, &stash, epoch_index)
            .await?;

        validators.push(profile);
    }

    // track chilled nodes by checking if a session authority is no longer part of the validator list
    for stash in authorities.iter() {
        if validators
            .iter()
            .find(|&p| p.stash.as_ref().unwrap() == stash)
            .is_none()
        {
            // mark validator has chilled
            let profile: ValidatorProfileRecord = if let Ok(serialized_data) = redis::cmd("GET")
                .arg(CacheKey::ValidatorProfileByAccount(stash.clone()))
                .query_async::<Connection, String>(&mut cache as &mut Connection)
                .await
            {
                let mut profile: ValidatorProfileRecord =
                    serde_json::from_str(&serialized_data).unwrap_or_default();
                profile.is_chilled = true;
                profile
            } else {
                let mut profile = ValidatorProfileRecord::new(stash.clone());
                profile.identity = get_identity(&onet, &stash, None).await?;
                profile.is_chilled = true;
                profile
            };
            cache_validator_profile_only(&mut cache, &config, &profile, &stash).await?;
            //
            validators.push(profile);
        }
    }

    nss.total_vals_chilled = validators
        .iter_mut()
        .filter(|v| v.is_chilled)
        .count()
        .try_into()
        .unwrap();

    // Fetch Era reward points
    // Note: era_reward_points are asynchronously sent RC->AH at the beginning of each session
    // We want to know which points were collected up to the last block of the session, so we need to gather the active era
    // from the parent AH block
    let active_era_info = fetch_active_era_info(&ah_api, ah_parent_block_hash).await?;
    let era_index = active_era_info.index;

    let storage_addr = relay_runtime::storage()
        .staking_ah_client()
        .validator_points_iter();
    let mut iter = rc_api
        .storage()
        .at(rc_parent_block_hash)
        .iter(storage_addr)
        .await?;
    while let Some(Ok(storage_resp)) = iter.next().await {
        let stash = get_account_id_from_storage_key(storage_resp.clone().key_bytes);
        validators
            .iter_mut()
            .filter(|v| v.stash.is_some())
            .filter(|v| *(v.stash.as_ref().unwrap()) == stash)
            .for_each(|v| {
                (*v).points = storage_resp.value;
            });
    }

    // Sum all validator points aggregated during the session
    nss.total_reward_points = validators.iter().map(|v| v.points).sum();

    // NOTE: DEPRECATED era_reward_points in favor of validator points retrieved
    // from asset_hub_staking_client.validator_points
    //
    // let era_reward_points = fetch_era_reward_points(&ah_api, ah_block_hash, era_index).await?;
    // nss.total_reward_points = era_reward_points.total;
    // for (stash, points) in era_reward_points.individual {
    //     validators
    //         .iter_mut()
    //         .filter(|v| v.stash.is_some())
    //         .filter(|v| *(v.stash.as_ref().unwrap()) == *stash)
    //         .for_each(|v| {
    //             (*v).points = *points;
    //         });
    // }
    //

    // build stats
    //
    // general session stats
    //
    // total issuance
    let total_issuance = fetch_total_issuance(&ah_api, ah_block_hash).await?;
    nss.total_issuance = total_issuance;

    // total staked
    let total_staked = fetch_eras_total_stake(&ah_api, ah_block_hash, era_index).await?;
    nss.total_staked = total_staked;

    // total rewarded from previous era
    let last_rewarded = fetch_eras_validator_reward(&ah_api, ah_block_hash, era_index - 1).await?;
    nss.last_rewarded = last_rewarded;

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

        // check to skip subset stats if no validators
        if ss.vals_total == 0 {
            continue;
        }

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

    cache_network_stats_at_session(&mut cache, &config, &nss, epoch_index).await?;

    cache_board_limits_at_session(&mut cache, &config, rc_block_number, era_index, epoch_index)
        .await?;

    // Log sesssion cache processed duration time
    info!(
        "AH Session #{} stats cached ({:?})",
        epoch_index,
        start.elapsed()
    );

    Ok(())
}

async fn collect_nominators_data(
    api: &OnlineClient<PolkadotConfig>,
    ah_block_hash: H256,
) -> Result<BTreeMap<AccountId32, Vec<(AccountId32, u128, u128)>>, OnetError> {
    let start = Instant::now();

    // BTreeMap<AccountId32, Vec<(AccountId32, u128, u32)>> = validator_stash : [(nominator_stash, nominator_total_stake, number_of_nominations)]
    let mut nominators_map: BTreeMap<AccountId32, Vec<(AccountId32, u128, u128)>> = BTreeMap::new();

    let mut counter = 0;
    let storage_addr = asset_hub_runtime::storage().staking().nominators_iter();
    let mut iter = api.storage().at(ah_block_hash).iter(storage_addr).await?;
    while let Some(Ok(storage_resp)) = iter.next().await {
        let nominator_stash = get_account_id_from_storage_key(storage_resp.key_bytes);
        let controller =
            fetch_bonded_controller_account(&api, ah_block_hash, &nominator_stash).await?;

        let staking_ledger = fetch_ledger_from_controller(&api, ah_block_hash, &controller).await?;
        let nominator_stake = staking_ledger.total;

        let BoundedVec(targets) = storage_resp.value.targets.clone();
        for target in targets.iter() {
            let n = nominators_map.entry(target.clone()).or_insert(vec![]);
            n.push((
                nominator_stash.clone(),
                nominator_stake,
                targets.len().try_into().unwrap(),
            ));
        }

        counter += 1;
    }
    info!(
        "AH Total Nominators {} collected ({:?})",
        counter,
        start.elapsed()
    );
    Ok(nominators_map)
}

pub async fn try_calculate_avg_mvr_by_session_and_stash_from_cache(
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

/// Helper fetch functions
///

/// Fetch session start block at the specified block hash
async fn fetch_session_start_block(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
) -> Result<SessionStartBlock, OnetError> {
    let addr = relay_runtime::storage()
        .para_scheduler()
        .session_start_block();

    api.storage().at(hash).fetch(&addr).await?.ok_or_else(|| {
        OnetError::from(format!(
            "Session start block not defined at block hash {hash}"
        ))
    })
}

/// Fetch asset hub included block_hash at the specified relay chain block hash
async fn fetch_asset_hub_included_block_hash(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
) -> Result<Option<H256>, OnetError> {
    let config = CONFIG.clone();

    // Fetch events
    let events = api.events().at(hash).await?;
    for event in events.iter() {
        let event = event?;
        if let Some(ev) = event.as_event::<CandidateIncluded>()? {
            if ev.0.descriptor.para_id == Id(config.asset_hub_para_id) {
                return Ok(Some(ev.0.descriptor.para_head));
            }
        }
    }
    Ok(None)
}

/// Fetch AH block hash from a specified block number
async fn fetch_asset_hub_block_hash(
    rpc: &LegacyRpcMethods<PolkadotConfig>,
    block_number: BlockNumber,
) -> Result<H256, OnetError> {
    rpc.chain_get_block_hash(Some(block_number.into()))
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "AH block hash not available at block number {block_number}"
            ))
        })
}

/// Fetch asset hub block header info at the specified block hash
async fn fetch_asset_hub_block_info(
    rpc: &LegacyRpcMethods<PolkadotConfig>,
    hash: H256,
) -> Result<(BlockNumber, H256), OnetError> {
    rpc.chain_get_header(Some(hash))
        .await?
        .map(|header| (header.number.into(), header.parent_hash))
        .ok_or_else(|| {
            OnetError::from(format!(
                "AH Block number not available at block hash {hash:?}"
            ))
        })
}

/// Try to fetch asset hub block info from a specified block hash, wait if not available
/// Note: Cap retries up to 100 times ~= 10minutes
async fn try_fetch_asset_hub_block_info(
    rpc: &LegacyRpcMethods<PolkadotConfig>,
    hash: H256,
) -> Result<(BlockNumber, H256), OnetError> {
    let mut retries = 100;
    while retries > 0 {
        match fetch_asset_hub_block_info(rpc, hash).await {
            Ok(info) => {
                return Ok(info);
            }
            Err(err) => {
                if retries == 1 {
                    // Last retry, return the error
                    return Err(OnetError::from(format!("{err} after 100 retries")));
                }
                warn!(
                    "{err} -> Waiting 6 seconds and retrying ({} retries left)",
                    retries - 1
                );
                async_std::task::sleep(std::time::Duration::from_secs(6)).await;
                retries -= 1;
            }
        };
    }
    Err(OnetError::from(format!(
        "AH block info not available at block hash {hash} after 100 retries"
    )))
}

/// Fetch relay chain block hash from a specified block number
async fn fetch_relay_chain_block_hash(
    rpc: &LegacyRpcMethods<PolkadotConfig>,
    block_number: BlockNumber,
) -> Result<H256, OnetError> {
    rpc.chain_get_block_hash(Some(block_number.into()))
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "RC block hash not available at block number {block_number}"
            ))
        })
}

/// Try to fetch relay chain block hash from a specified block number, wait if not available
/// Note: Cap retries up to 100 times ~= 10minutes
async fn try_fetch_relay_chain_block_hash(
    rpc: &LegacyRpcMethods<PolkadotConfig>,
    block_number: BlockNumber,
) -> Result<H256, OnetError> {
    let mut retries = 100;
    while retries > 0 {
        match fetch_relay_chain_block_hash(rpc, block_number).await {
            Ok(hash) => {
                return Ok(hash);
            }
            Err(err) => {
                if retries == 1 {
                    // Last retry, return the error
                    return Err(OnetError::from(format!("{err} after 100 retries")));
                }
                warn!(
                    "{err} -> Waiting 6 seconds and retrying ({} retries left)",
                    retries - 1
                );
                async_std::task::sleep(std::time::Duration::from_secs(6)).await;
                retries -= 1;
            }
        };
    }
    Err(OnetError::from(format!(
        "Relay block hash not available at block number {block_number} after 100 retries"
    )))
}

/// Fetch the included asset hub block hash from a specified relay chain block number
#[async_recursion]
async fn fetch_asset_hub_block_hash_from_relay_chain(
    onet: &Onet,
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
) -> Result<H256, OnetError> {
    let rc_api = onet.relay_client().clone();

    // 1. Fetch the included asset hub block hash from the specified relay chain block number
    if let Some(hash) = fetch_asset_hub_included_block_hash(&rc_api, rc_block_hash).await? {
        let ah_api = onet
            .asset_hub_client()
            .as_ref()
            .expect("AH API to be available");
        let ah_rpc = onet
            .asset_hub_rpc()
            .as_ref()
            .expect("AH RPC to be available")
            .clone();
        // 2. Verify if the RC parent_block_number included in AH block is equal to the rc_block_number being queried
        // If not fetch the next AH block and try again
        let mut ah_next_block_hash = hash;
        let mut ah_block_number_opt: Option<u64> = None;
        loop {
            let parent_block_number =
                fetch_relay_parent_block_number(&ah_api, ah_next_block_hash).await?;
            if parent_block_number == rc_block_number {
                return Ok(ah_next_block_hash);
            }
            // Fetch AH block_number from current hash, add 1 and fetch to get the next AH hash
            ah_block_number_opt = if let Some(n) = ah_block_number_opt {
                Some(n + 1)
            } else {
                let (n, _) = try_fetch_asset_hub_block_info(&ah_rpc, ah_next_block_hash).await?;
                Some(n + 1)
            };
            let ah_block_number = ah_block_number_opt.unwrap();
            ah_next_block_hash = fetch_asset_hub_block_hash(&ah_rpc, ah_block_number).await?;
        }
    }
    let rc_rpc = onet.relay_rpc().clone();
    let rc_next_block_number = rc_block_number + 1;
    let rc_next_block_hash =
        try_fetch_relay_chain_block_hash(&rc_rpc, rc_next_block_number).await?;

    fetch_asset_hub_block_hash_from_relay_chain(onet, rc_next_block_number, rc_next_block_hash)
        .await
}

// /// Fetch the included asset hub block hash from a specified relay chain block number
// #[async_recursion]
// async fn fetch_asset_hub_block_hash_from_relay_chain(
//     onet: &Onet,
//     rc_block_number: BlockNumber,
//     rc_block_hash: H256,
// ) -> Result<H256, OnetError> {
//     let rc_api = onet.relay_client().clone();
//     let rc_rpc = onet.relay_rpc().clone();
//     if let Some(hash) = fetch_asset_hub_block_hash(&rc_api, rc_block_hash).await? {
//         return Ok(hash);
//     }

//     let rc_next_block_number = rc_block_number + 1;
//     let rc_next_block_hash =
//         try_fetch_relay_chain_block_hash(&rc_rpc, rc_next_block_number).await?;

//     fetch_asset_hub_block_hash_from_relay_chain(onet, rc_next_block_number, rc_next_block_hash)
//         .await
// }
