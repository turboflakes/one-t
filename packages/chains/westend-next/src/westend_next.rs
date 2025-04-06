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
use super::people::{bytes_to_str, get_display_name, get_identity};

use async_recursion::async_recursion;
use log::{debug, error, info, warn};
use onet_api::responses::{AuthorityKey, AuthorityKeyCache};
use onet_cache::{CacheKey, Index, Trait, Verbosity};
use onet_config::{CONFIG, EPOCH_FILENAME};
use onet_core::{
    get_account_id_from_storage_key, get_latest_block_number_processed, get_signer_from_seed,
    get_subscribers, get_subscribers_by_epoch, write_latest_block_number_processed, Onet,
};
use onet_discovery::try_fetch_discovery_data;
use onet_dn::try_fetch_stashes_from_remote_url;
use onet_errors::{CacheError, OnetError};
use onet_matrix::FileInfo;
use onet_mcda::{criterias::build_limits_from_session, scores::base_decimals};
use onet_pools::{
    nomination_pool_account, Account, AccountType, ActiveNominee, Pool, PoolNominees, PoolStats,
    Roles,
};
use onet_records::{
    AuthorityIndex, AuthorityRecord, BlockNumber, DiscoveryRecord, EpochIndex, EpochKey, EraIndex,
    NetworkSessionStats, ParaId, ParaRecord, ParaStats, ParachainRecord, Points, Records,
    SessionStats, Subscribers, Subset, SubsetStats, ValidatorProfileRecord,
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

use subxt::{
    config::{
        substrate::{Digest, DigestItem},
        Header,
    },
    ext::subxt_core::Metadata,
    tx::TxStatus,
    utils::{AccountId32, H256},
    OnlineClient, PolkadotConfig,
};
use subxt_signer::sr25519::Keypair;

#[subxt::subxt(
    runtime_metadata_path = "artifacts/metadata/westend_next_metadata.scale",
    derive_for_all_types = "PartialEq, Clone"
)]
mod relay_runtime {}

use relay_runtime::{
    grandpa::events::NewAuthorities,
    historical::events::RootStored,
    historical::events::RootsPruned,
    para_inclusion::events::CandidateIncluded,
    para_inherent::calls::types::Enter,
    para_inherent::storage::types::on_chain_votes::OnChainVotes,
    para_scheduler::storage::types::session_start_block::SessionStartBlock,
    para_scheduler::storage::types::validator_groups::ValidatorGroups,
    paras_shared::storage::types::active_validator_indices::ActiveValidatorIndices,
    runtime_types::{
        frame_system::AccountInfo,
        frame_system::LastRuntimeUpgradeInfo,
        pallet_balances::types::AccountData,
        polkadot_parachain_primitives::primitives::Id,
        polkadot_primitives::v8::AvailabilityBitfield,
        polkadot_primitives::v8::DisputeStatement,
        polkadot_primitives::v8::ValidatorIndex,
        polkadot_primitives::v8::ValidityAttestation,
        polkadot_runtime_parachains::scheduler::common::Assignment,
        // polkadot_runtime_parachains::scheduler::pallet::CoreOccupied,
        sp_authority_discovery::app::Public,
        sp_consensus_babe::digests::PreDigest,
    },
    session::events::new_session::SessionIndex,
    session::events::NewSession,
    session::storage::types::queued_keys::QueuedKeys,
    session::storage::types::validators::Validators as ValidatorSet,
    staking_next_ah_client::events::CouldNotMergeAndDropped,
    staking_next_ah_client::events::SetTooSmallAndDropped,
    staking_next_ah_client::events::ValidatorSetReceived,
    system::events::ExtrinsicFailed,
};

#[subxt::subxt(
    runtime_metadata_path = "artifacts/metadata/asset_hub_westend_next_metadata.scale",
    derive_for_all_types = "PartialEq, Clone"
)]
mod asset_hub_runtime {}

use asset_hub_runtime::{
    balances::storage::types::total_issuance::TotalIssuance,
    multi_block::events::PhaseTransitioned,
    // multi_block_signed::events::Signed,
    // multi_block_unsigned::events::Unsigned,
    multi_block_verifier::events::Queued,
    multi_block_verifier::events::VerificationDataUnavailable,
    multi_block_verifier::events::VerificationFailed,
    // multi_block_verifier::events::VerificationSucceeded,
    multi_block_verifier::events::Verified,
    nomination_pools::storage::types::bonded_pools::BondedPools,
    nomination_pools::storage::types::metadata::Metadata as PoolMetadata,
    runtime_types::{
        bounded_collections::bounded_vec::BoundedVec,
        pallet_nomination_pools::PoolState,
        pallet_staking_async::{ActiveEraInfo, EraRewardPoints, StakingLedger},
        // polkadot_runtime_parachains::scheduler::pallet::CoreOccupied,
        sp_arithmetic::per_things::Perbill,
    },
    staking::events::EraPaid,
    staking::events::PagedElectionProceeded,
    staking::events::SessionRotated,
    staking::storage::types::eras_start_session_index::ErasStartSessionIndex,
    staking::storage::types::eras_total_stake::ErasTotalStake,
    staking::storage::types::nominators::Nominators,
    staking_next_rc_client::events::OffenceReceived,
    staking_next_rc_client::events::SessionReportReceived,
};

type AssetHubCall =
    asset_hub_runtime::runtime_types::pallet_staking_async_parachain_runtime::RuntimeCall;
type NominationPoolsCall = asset_hub_runtime::runtime_types::pallet_nomination_pools::pallet::Call;

pub async fn init_and_subscribe_on_chain_events(onet: &Onet) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let rc_api = onet.client().clone();
    let ah_api = onet.asset_hub_client().clone();

    let stashes: Vec<String> = config.pools_featured_nominees;
    info!(
        "{} featured nominees loaded from 'config.pools_featured_nominees'",
        stashes.len()
    );

    // Initialize from the first block of the session of last block processed
    let latest_block_number = get_latest_block_number_processed()?;
    let latest_block_hash = fetch_relay_chain_block_hash(onet, latest_block_number).await?;

    // Fetch ParaSession start block for the latest block processed
    let mut start_block_number = fetch_session_start_block(&rc_api, latest_block_hash).await?;
    info!("Start block number_: {}", start_block_number);
    // Note: We want to start sync in the first block of a session.
    // For that we get the first block of a ParaSession and remove 1 block,
    // since ParaSession starts always at the the second block of a new session
    start_block_number -= 1;
    // Load into memory the minimum initial eras defined (default=0)

    start_block_number -= config.minimum_initial_eras * 6 * config.blocks_per_session;
    info!("Start block number__: {}", start_block_number);

    // get block hash from the start block
    let rc_block_hash = fetch_relay_chain_block_hash(onet, start_block_number.into()).await?;

    let ah_block_hash =
        fetch_asset_hub_block_hash_from_relay_chain(onet, start_block_number.into(), rc_block_hash)
            .await?;

    // Fetch active era index
    let active_era_info = fetch_active_era_info(&ah_api, ah_block_hash).await?;
    let era_index = active_era_info.index;

    // Cache Nomination pools
    // try_run_cache_pools_era(era_index, false).await?;

    // Fetch session index
    let session_index = fetch_session_index(&rc_api, rc_block_hash).await?;

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
    initialize_records(&rc_api, &mut records, rc_block_hash).await?;

    // Initialize cache
    cache_session_records(&records, rc_block_hash, ah_block_hash).await?;

    cache_track_records(&onet, &records).await?;

    // Initialize p2p discovery
    try_run_cache_discovery_records(&records, rc_block_hash).await?;

    // Start indexing from the start_block_number
    let mut latest_block_number_processed: Option<u64> = Some(start_block_number.into());
    let mut is_loading = true;

    // Subscribe head
    // NOTE: the reason why we subscribe head and not finalized_head,
    // is just because head is in sync more frequently.
    // finalized_head can always be queried so as soon as it changes we process th repective block_hash
    let mut blocks_sub = rc_api.blocks().subscribe_best().await?;
    while let Some(Ok(best_block)) = blocks_sub.next().await {
        info!("Block #{:?} received", best_block.number());
        // update records best_block number
        process_best_block(&onet, &mut records, best_block.number().into()).await?;

        // fetch latest finalized block
        let finalized_block_hash = onet.rpc().chain_get_finalized_head().await?;
        if let Some(block) = onet
            .rpc()
            .chain_get_header(Some(finalized_block_hash))
            .await?
        {
            info!("Block #{:?} finalized in storage", block.number);
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
            .query_async::<_, ()>(&mut cache as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;
    }

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
    debug!("Block #{} to be processed now", rc_block_number);

    let BlockProcessingContext {
        rc_api,
        ah_api,
        parent_metadata,
        current_metadata,
    } = setup_processing_context(onet, rc_block_number).await?;

    // Process RC events with the parent_metadata
    let mut ah_block_hash = None;
    process_relay_chain_events(
        &rc_api,
        &ah_api,
        records,
        subscribers,
        rc_block_number,
        rc_block_hash,
        &mut ah_block_hash,
        is_loading,
    )
    .await?;

    // NOTE_1: It might require further testing, but since v1003000 the aproach will be to
    // restore the original `current_metadata` to process the next records!

    // NOTE_2: Lookup for exceptions where both metadatas (parent_metadata or current_metadata)
    // need to be passed down and apply them where required!

    // Restore assignement of static_metadata to the api
    rc_api.set_metadata(current_metadata);

    // // Update records
    // // Note: these records should be updated after the switch of session
    // track_records(&onet, records, rc_block_number, rc_block_hash).await?;

    // // Cache pool stats every 10 minutes
    // try_run_cache_nomination_pools_stats(rc_block_number, rc_block_hash, ah_block_hash).await?;

    // // Cache records at every block
    // cache_track_records(&onet, &records).await?;

    // Log block processed duration time
    info!(
        "Block #{} processed ({:?})",
        rc_block_number,
        start.elapsed()
    );

    Ok(())
}

struct BlockProcessingContext {
    rc_api: OnlineClient<PolkadotConfig>,
    ah_api: OnlineClient<PolkadotConfig>,
    parent_metadata: Metadata,
    current_metadata: Metadata,
}

async fn setup_processing_context(
    onet: &Onet,
    block_number: BlockNumber,
) -> Result<BlockProcessingContext, OnetError> {
    let config = CONFIG.clone();
    let rc_api = onet.client().clone();
    let ah_api = onet.asset_hub_client().clone();
    let current_metadata = rc_api.metadata().clone();

    // Get parent block metadata for better handling of runtime upgrades
    let parent_block_hash = onet
        .rpc()
        .chain_get_block_hash(Some((block_number - 1).into()))
        .await?;
    let parent_metadata = onet.rpc().state_get_metadata(parent_block_hash).await?;
    rc_api.set_metadata(parent_metadata.clone());

    Ok(BlockProcessingContext {
        rc_api,
        ah_api,
        parent_metadata,
        current_metadata,
    })
}

async fn process_relay_chain_events(
    rc_api: &OnlineClient<PolkadotConfig>,
    ah_api: &OnlineClient<PolkadotConfig>,
    records: &mut Records,
    subscribers: &mut Subscribers,
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
    ah_block_hash: &mut Option<H256>,
    is_loading: bool,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let events = rc_api.events().at(rc_block_hash).await?;

    for event in events.iter() {
        let event = event?;
        if let Some(ev) = event.as_event::<CandidateIncluded>()? {
            if ev.0.descriptor.para_id == Id(config.asset_hub_para_id) {
                *ah_block_hash = Some(ev.0.descriptor.para_head);
                process_asset_hub_events(
                    ah_api,
                    ev.0.descriptor.para_head,
                    subscribers,
                    records,
                    is_loading,
                )
                .await?;
            }
        } else if let Some(ev) = event.as_event::<NewSession>()? {
            info!("RC event {:?}", ev);
            process_new_session_event(&rc_api, records, ev, rc_block_number, rc_block_hash).await?;
        } else if let Some(ev) = event.as_event::<RootStored>()? {
            info!("RC event {:?}", ev);
        } else if let Some(ev) = event.as_event::<ValidatorSetReceived>()? {
            info!("RC event {:?}", ev);
        } else if let Some(ev) = event.as_event::<NewAuthorities>()? {
            info!("RC event {:?}", ev);
        }
    }

    Ok(())
}

async fn process_new_session_event(
    rc_api: &OnlineClient<PolkadotConfig>,
    records: &mut Records,
    event: NewSession,
    rc_block_number: u64,
    rc_block_hash: H256,
) -> Result<(), OnetError> {
    process_new_session(
        &rc_api,
        records,
        event.session_index,
        rc_block_number,
        rc_block_hash,
    )
    .await?;
    // switch_new_session(
    //     &onet,
    //     rc_block_number,
    //     ev.session_index,
    //     subscribers,
    //     records,
    //     rc_block_hash,
    //     ah_block_hash,
    //     is_loading,
    // )
    // .await?;

    // // Network public report
    // try_run_network_report(ev.session_index, &records, is_loading).await?;

    // // Cache session records every new session
    // try_run_cache_session_records(&records, rc_block_hash, ah_block_hash).await?;

    // // Cache session stats records every new session
    // try_run_cache_session_stats_records(rc_block_hash, is_loading).await?;

    // // Cache nomination pools every new session
    // try_run_cache_nomination_pools(rc_block_number, rc_block_hash).await?;

    // if !is_loading {
    //     // Cache p2p discovery
    //     try_run_cache_discovery_records(&records, rc_block_hash).await?;
    // }
    Ok(())
}

async fn process_asset_hub_events(
    ah_api: &OnlineClient<PolkadotConfig>,
    ah_hash: H256,
    subscribers: &mut Subscribers,
    records: &mut Records,
    is_loading: bool,
) -> Result<(), OnetError> {
    // TODO: Get asset hub ah_block_number from the API
    let ah_block_number = 0;
    let events = ah_api.events().at(ah_hash).await?;

    for event in events.iter() {
        let event = event?;
        if let Some(ev) = event.as_event::<SessionRotated>()? {
            info!("AH event {:?}", ev);
            let previous_era_index = rotate_session(
                ev.starting_session,
                ev.active_era,
                subscribers,
                records,
                ah_block_number,
            )?;
            process_matrix_reports(previous_era_index, subscribers, records, is_loading).await?;
        } else if let Some(ev) = event.as_event::<PagedElectionProceeded>()? {
            info!("AH event {:?}", ev);
        } else if let Some(ev) = event.as_event::<EraPaid>()? {
            info!("AH event {:?}", ev);
        } else if let Some(ev) = event.as_event::<SessionReportReceived>()? {
            info!("AH event {:?}", ev);
        } else if let Some(ev) = event.as_event::<OffenceReceived>()? {
            info!("AH event {:?}", ev);
        } else if let Some(ev) = event.as_event::<OffenceReceived>()? {
            info!("AH event {:?}", ev);
        }
        // TODO: Handle multi_block events
        //  if pallet == "MultiBlock"
        // || pallet == "MultiBlockVerifier"
        // || pallet == "MultiBlockSigned"
        // || pallet == "MultiBlockUnsigned"
    }

    Ok(())
}

/// Run rotate_session at RC NewSession event
pub async fn process_new_session(
    rc_api: &OnlineClient<PolkadotConfig>,
    records: &mut Records,
    new_session_index: EpochIndex,
    rc_block_number: u64,
    rc_block_hash: H256,
) -> Result<(), OnetError> {
    // Update records current Epoch
    records.set_new_epoch(new_session_index);
    // Update records current block number
    records.set_current_block_number(rc_block_number.into());
    // Initialize records for new epoch
    initialize_records(&rc_api, records, rc_block_hash).await?;

    Ok(())
}

/// Run rotate_session at AHSessionRotated event
pub fn rotate_session(
    starting_session: EpochIndex,
    active_era: EraIndex,
    subscribers: &mut Subscribers,
    records: &mut Records,
    ah_block_number: u64,
) -> Result<EraIndex, OnetError> {
    let config = CONFIG.clone();

    // keep previous era in context
    let previous_era_index = records.current_era().clone();

    // Update records current Era and Epoch
    records.rotate_session(active_era, starting_session);

    // Update records current block number
    records.set_current_ah_block_number(ah_block_number.into());

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
pub async fn process_matrix_reports(
    previous_era_index: EraIndex,
    subscribers: &mut Subscribers,
    records: &mut Records,
    is_loading: bool,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();

    // Try to run matrix reports
    if !config.matrix_disabled && !is_loading {
        let current_era_index = records.current_era();
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
                            // bitfields availability
                            session_stats.bitfields_availability +=
                                para_record.total_availability();
                            session_stats.bitfields_unavailability +=
                                para_record.total_unavailability();

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
                                .query_async::<_, ()>(&mut cache as &mut Connection)
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
                                .query_async::<_, ()>(&mut cache as &mut Connection)
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
                            .query_async::<_, ()>(&mut cache as &mut Connection)
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
                .query_async::<_, ()>(&mut cache as &mut Connection)
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
                    .query_async::<_, ()>(&mut cache as &mut Connection)
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
                        .query_async::<_, ()>(&mut cache as &mut Connection)
                        .await
                        .map_err(CacheError::RedisCMDError)?;
                }
            }
        }
    }

    Ok(())
}

pub async fn try_run_cache_discovery_records(
    records: &Records,
    block_hash: H256,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.discovery_enabled {
        let records_cloned = records.clone();
        async_std::task::spawn(async move {
            if let Err(e) = try_fetch_discovery_data(&records_cloned, block_hash).await {
                error!("try_fetch_discovery_data error: {:?}", e);
            }
        });
    }

    Ok(())
}

pub async fn try_run_cache_session_records(
    records: &Records,
    rc_block_hash: H256,
    ah_block_hash: H256,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.cache_writer_enabled {
        let records_cloned = records.clone();
        async_std::task::spawn(async move {
            if let Err(e) =
                cache_session_records(&records_cloned, rc_block_hash, ah_block_hash).await
            {
                error!("try_run_cache_session_records error: {:?}", e);
            }
        });
    }

    Ok(())
}

// cache_session_records is called once at every new session
pub async fn cache_session_records(
    records: &Records,
    rc_block_hash: H256,
    ah_block_hash: H256,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.cache_writer_enabled {
        let start = Instant::now();
        let onet: Onet = Onet::new().await;
        let rc_api = onet.client().clone();
        let ah_api = onet.asset_hub_client().clone();
        let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

        // cache records every new session
        let current_era = records.current_era();
        let current_epoch = records.current_epoch();

        // --- Cache SessionByIndex -> `current` or `epoch_index` (to be able to search history)
        if let Some(start_block) = records.start_block(None) {
            if let Some(current_block) = records.current_block() {
                // fetch start session index
                let start_session_index =
                    fetch_eras_start_session_index(&ah_api, ah_block_hash, &current_era).await?;

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
                    .query_async::<_, ()>(&mut cache as &mut Connection)
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
                            .query_async::<_, ()>(&mut cache as &mut Connection)
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
                            .query_async::<_, ()>(&mut cache as &mut Connection)
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
                            .query_async::<_, ()>(&mut cache as &mut Connection)
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
                                .query_async::<_, ()>(&mut cache as &mut Connection)
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
    rc_api: &OnlineClient<PolkadotConfig>,
    records: &mut Records,
    rc_block_hash: H256,
) -> Result<(), OnetError> {
    // Fetch active validators
    let authorities = fetch_authorities(&rc_api, rc_block_hash).await?;

    // Fetch queued keys
    let queued_keys = fetch_queued_keys(&rc_api, rc_block_hash).await?;

    // Fetch para validator groups
    let validator_groups = fetch_validator_groups(&rc_api, rc_block_hash).await?;

    // Fetch para validator indices
    let active_validator_indices = fetch_validator_indices(&rc_api, rc_block_hash).await?;

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
                                let points =
                                    fetch_validator_points(&rc_api, rc_block_hash, address).await?;

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
            let points = fetch_validator_points(&rc_api, rc_block_hash, stash).await?;

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
        .staking_next_ah_client()
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

/// TODO: Track authority core assignments per authority
// fn track_core_assignments(
//     records: &mut Records,
//     backing_votes: &OnChainVotes,
//     availability_cores: Vec<CoreOccupied<u32>>,
// ) -> Result<(), OnetError> {
//     for (i, core_occupied) in availability_cores.iter().enumerate() {
//         let core_idx = u32::try_from(i).unwrap();
//         match &core_occupied {
//             CoreOccupied::Free => records.update_core_free(core_idx, Some(backing_votes.session)),
//             CoreOccupied::Paras(paras_entry) => {
//                 match &paras_entry.assignment {
//                     //     ParasEntry::<u32>
//                     Assignment::Pool {
//                         para_id: Id(para_id),
//                         core_index: _,
//                     } => {
//                         records.update_core_by_para_id(
//                             para_id.clone(),
//                             core_idx,
//                             Some(backing_votes.session),
//                         );
//                     }
//                     Assignment::Bulk(Id(para_id)) => {
//                         records.update_core_by_para_id(
//                             para_id.clone(),
//                             core_idx,
//                             Some(backing_votes.session),
//                         );
//                     }
//                 }
//             }
//         }
//     }
//     Ok(())
// }

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
    onet: &Onet,
    records: &mut Records,
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
) -> Result<(), OnetError> {
    let rc_api = onet.client().clone();

    // Update records current block number
    records.set_current_block_number(rc_block_number.into());

    // Extract authority from the block header
    let block_authority_index = get_authority_index(&onet, Some(rc_block_hash))
        .await?
        .ok_or_else(|| OnetError::from("Authority index not found"))?;

    // Fetch session index
    let session_index = fetch_session_index(&rc_api, rc_block_hash).await?;

    // Track block authored
    if let Some(authority_record) =
        records.get_mut_authority_record(block_authority_index, Some(session_index))
    {
        authority_record.push_authored_block(rc_block_number);
    }

    // Fetch para validator groups
    let validator_groups = fetch_validator_groups(&rc_api, rc_block_hash).await?;

    // Fetch para validator indices
    let active_validator_indices = fetch_validator_indices(&rc_api, rc_block_hash).await?;

    // Fetch on chain votes
    let backing_votes = fetch_on_chain_votes(&rc_api, rc_block_hash).await?;

    // Fetch availability cores
    // let availability_cores = fetch_availability_cores(&rc_api, rc_block_hash).await?;
    //
    //

    // Fetcht and Track authority points
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

    // TODO: Track core assignments
    // track_core_assignments(records, &backing_votes, availability_cores)?;

    // Track disputes
    track_disputes(
        records,
        &backing_votes,
        &active_validator_indices,
        rc_block_number,
    )?;

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
    epoch_index: EpochIndex,
    records: &Records,
    rc_block_hash: H256,
    ah_block_hash: H256,
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
                    if let Err(e) =
                        run_network_report(&records_cloned, rc_block_hash, ah_block_hash).await
                    {
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

pub async fn run_network_report(
    records: &Records,
    rc_block_hash: H256,
    ah_block_hash: H256,
) -> Result<(), OnetError> {
    let onet: Onet = Onet::new().await;
    let config = CONFIG.clone();
    let rc_api = onet.client().clone();
    let ah_api = onet.asset_hub_client().clone();

    let network = Network::load(onet.rpc()).await?;

    // Fetch active era index
    let active_era = fetch_active_era_info(&rc_api, rc_block_hash).await?;
    let active_era_index = active_era.index;

    // Fetch current epoch
    let current_session_index = fetch_session_index(&rc_api, rc_block_hash).await?;

    // Fetch active era total stake
    let active_era_total_stake =
        fetch_eras_total_stake(&rc_api, rc_block_hash, &active_era_index).await?;

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
    let authorities = fetch_authorities(&rc_api, rc_block_hash).await?;

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
        let staking_ledger = fetch_ledger_from_controller(&ah_api, ah_block_hash, &stash).await?;
        v.own_stake = staking_ledger.active;

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

pub async fn try_run_cache_nomination_pools(
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
    ah_block_hash: H256,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.cache_writer_enabled && config.pools_enabled {
        async_std::task::spawn(async move {
            if let Err(e) =
                cache_nomination_pools(rc_block_number, rc_block_hash, ah_block_hash).await
            {
                error!("cache_nomination_pools error: {:?}", e);
            }
        });

        async_std::task::spawn(async move {
            if let Err(e) =
                cache_nomination_pools_stats(rc_block_number, rc_block_hash, ah_block_hash).await
            {
                error!("cache_nomination_pools_stats error: {:?}", e);
            }
        });

        // NOTE: network_report is issued every era we could use the same config to cache nomination pools APR
        // but since the APR is based on the current nominees and these can be changed within the session
        // we calculate the APR every new session for now
        async_std::task::spawn(async move {
            if let Err(e) =
                cache_nomination_pools_nominees(rc_block_number, rc_block_hash, ah_block_hash).await
            {
                error!("cache_nomination_pools_stats error: {:?}", e);
            }
        });
    }
    Ok(())
}

pub async fn try_run_cache_nomination_pools_stats(
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
    ah_block_hash: Option<H256>,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.cache_writer_enabled && config.pools_enabled && ah_block_hash.is_some() {
        // collect nomination stats every minute
        if (rc_block_number as f64 % 10.0_f64) == 0.0_f64 {
            async_std::task::spawn(async move {
                let ah_block_hash = ah_block_hash.unwrap();
                if let Err(e) =
                    cache_nomination_pools_stats(rc_block_number, rc_block_hash, ah_block_hash)
                        .await
                {
                    error!("cache_nomination_pools_stats error: {:?}", e);
                }
            });
        }
    }
    Ok(())
}

pub async fn cache_nomination_pools_nominees(
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
    ah_block_hash: H256,
) -> Result<(), OnetError> {
    let start = Instant::now();
    let onet: Onet = Onet::new().await;
    let api = onet.client().clone();
    let ah_api = onet.asset_hub_client().clone();
    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

    // fetch last pool id
    let last_pool_id = fetch_last_pool_id(&ah_api, ah_block_hash).await?;

    let active_era_info = fetch_active_era_info(&ah_api, ah_block_hash).await?;
    let era_index = active_era_info.index;

    let epoch_index = fetch_session_index(&ah_api, ah_block_hash).await?;

    let mut valid_pool = Some(1);
    while let Some(pool_id) = valid_pool {
        if pool_id > last_pool_id {
            valid_pool = None;
        } else {
            let mut pool_nominees = PoolNominees::new();
            pool_nominees.block_number = rc_block_number;
            let pool_stash_account = nomination_pool_account(AccountType::Bonded, pool_id);

            // fetch pool nominees
            let nominations = fetch_nominators(&api, ah_block_hash, &pool_stash_account).await?;

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
                    .eras_stakers_paged_iter2(&era_index, &stash);
                let mut iter = api
                    .storage()
                    .at(ah_block_hash)
                    .iter(eras_stakers_paged_addr)
                    .await?;

                while let Some(Ok(storage_kv)) = iter.next().await {
                    if let Some(individual) = storage_kv
                        .value
                        .others
                        .iter()
                        .find(|x| x.who == pool_stash_account)
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
                .query_async::<_, ()>(&mut cache as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;

            valid_pool = Some(pool_id + 1);
        }
    }
    // Log cache processed duration time
    info!(
        "Pools nominees #{} cached ({:?})",
        epoch_index,
        start.elapsed()
    );

    Ok(())
}

pub async fn cache_nomination_pools_stats(
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
    ah_block_hash: H256,
) -> Result<(), OnetError> {
    let start = Instant::now();
    let onet: Onet = Onet::new().await;
    let rc_api = onet.client().clone();
    let ah_api = onet.asset_hub_client().clone();
    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

    let last_pool_id = fetch_last_pool_id(&ah_api, ah_block_hash).await?;
    let epoch_index = fetch_session_index(&rc_api, rc_block_hash).await?;

    let mut valid_pool = Some(1);
    while let Some(pool_id) = valid_pool {
        if pool_id > last_pool_id {
            valid_pool = None;
        } else {
            let mut pool_stats = PoolStats::new();
            pool_stats.block_number = rc_block_number;

            let bonded = fetch_bonded_pools(&ah_api, ah_block_hash, pool_id).await?;

            pool_stats.points = bonded.points;
            pool_stats.member_counter = bonded.member_counter;

            // fetch pool stash account staked amount from staking pallet
            let stash_account = nomination_pool_account(AccountType::Bonded, pool_id);

            let staking_ledger =
                fetch_ledger_from_controller(&ah_api, ah_block_hash, &stash_account).await?;
            pool_stats.staked = staking_ledger.active;
            pool_stats.unbonding = staking_ledger.total - staking_ledger.active;

            // fetch pool reward account free amount
            let stash_account = nomination_pool_account(AccountType::Reward, pool_id);
            let account_info = fetch_account_info(&rc_api, rc_block_hash, &stash_account).await?;
            pool_stats.reward = account_info.data.free;

            // serialize and cache pool
            let serialized = serde_json::to_string(&pool_stats)?;
            redis::cmd("SET")
                .arg(CacheKey::NominationPoolStatsByPoolAndSession(
                    pool_id,
                    epoch_index,
                ))
                .arg(serialized)
                .query_async::<_, ()>(&mut cache as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;

            valid_pool = Some(pool_id + 1);
        }
    }
    // Log cache processed duration time
    info!(
        "Pools stats #{} cached ({:?})",
        epoch_index,
        start.elapsed()
    );

    Ok(())
}

pub async fn cache_nomination_pools(
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
    ah_block_hash: H256,
) -> Result<(), OnetError> {
    let start = Instant::now();
    let onet: Onet = Onet::new().await;
    let rc_api = onet.client().clone();
    let ah_api = onet.asset_hub_client().clone();
    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

    let last_pool_id = fetch_last_pool_id(&ah_api, ah_block_hash).await?;
    let epoch_index = fetch_session_index(&rc_api, rc_block_hash).await?;

    let mut valid_pool = Some(1);
    while let Some(pool_id) = valid_pool {
        if pool_id > last_pool_id {
            valid_pool = None;
        } else {
            let metadata = fetch_pool_metadata(&ah_api, ah_block_hash, pool_id).await?;
            let BoundedVec(metadata) = metadata;
            let metadata = bytes_to_str(metadata);
            let mut pool = Pool::with_id_and_metadata(pool_id, metadata.clone());

            let bonded = fetch_bonded_pools(&ah_api, ah_block_hash, pool_id).await?;

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
            pool.block_number = rc_block_number;

            // serialize and cache pool
            let serialized = serde_json::to_string(&pool)?;
            redis::cmd("SET")
                .arg(CacheKey::NominationPoolRecord(pool_id))
                .arg(serialized)
                .query_async::<_, ()>(&mut cache as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;
        }
        // cache pool_id into a sorted set by session
        redis::cmd("ZADD")
            .arg(CacheKey::NominationPoolIdsBySession(epoch_index))
            .arg(0)
            .arg(pool_id)
            .query_async::<_, ()>(&mut cache as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;

        valid_pool = Some(pool_id + 1);
    }

    // Log cache processed duration time
    info!("Pools #{} cached ({:?})", epoch_index, start.elapsed());

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

/// Cache session stats records every new session
/// The block hash given should be from the parent block where the
/// `NewSession` event is present
pub async fn try_run_cache_session_stats_records(
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
    ah_block_hash: H256,
    is_loading: bool,
) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    if config.cache_writer_enabled {
        async_std::task::spawn(async move {
            if let Err(e) = cache_session_stats_records(
                rc_block_number,
                rc_block_hash,
                ah_block_hash,
                is_loading,
            )
            .await
            {
                error!("try_run_cache_session_stats_records error: {:?}", e);
            }
        });
    }

    Ok(())
}

/// ---
/// cache all validators profile and snapshot session stats at the last block of the session
pub async fn cache_session_stats_records(
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
    ah_block_hash: H256,
    is_loading: bool,
) -> Result<(), OnetError> {
    let start = Instant::now();
    let config = CONFIG.clone();
    let onet: Onet = Onet::new().await;
    let rc_api = onet.client().clone();
    let ah_api = onet.asset_hub_client().clone();
    let mut cache = onet.cache.get().await.map_err(CacheError::RedisPoolError)?;

    // Load network details
    let network = Network::load(onet.rpc()).await?;

    let active_era_info = fetch_active_era_info(&ah_api, ah_block_hash).await?;
    let era_index = active_era_info.index;

    let epoch_index = fetch_session_index(&rc_api, rc_block_hash).await?;

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
    let authorities = fetch_authorities(&ah_api, ah_block_hash).await?;

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
        let mut v = ValidatorProfileRecord::new(stash.clone());
        // validator controller address
        let controller = fetch_bonded_controller_account(&ah_api, ah_block_hash, &stash).await?;
        v.controller = Some(controller.clone());
        // get own stake
        let staking_ledger =
            fetch_ledger_from_controller(&ah_api, ah_block_hash, &controller).await?;
        v.own_stake = staking_ledger.active;

        // deconstruct commisssion
        let Perbill(commission) = storage_resp.value.commission;
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

        // check if is in active set
        v.is_active = authorities.contains(&stash);

        // calculate session mvr and avg it with previous value
        v.mvr =
            try_calculate_avg_mvr_by_session_and_stash(&onet, epoch_index, stash.clone()).await?;
        // keep track of when mvr was updated
        if v.mvr.is_some() {
            v.mvr_session = Some(epoch_index);
        }

        // check if block nominations
        v.is_blocked = storage_resp.value.blocked;

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
            .query_async::<_, ()>(&mut cache as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?;

        validators.push(v);
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
                .query_async::<_, ()>(&mut cache as &mut Connection)
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
    let era_reward_points = fetch_era_reward_points(&ah_api, ah_block_hash, era_index).await?;

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

    // build stats
    //
    // general session stats
    //
    // total issuance
    let total_issuance = fetch_total_issuance(&rc_api, rc_block_hash).await?;
    nss.total_issuance = total_issuance;

    // total staked
    let total_staked = fetch_eras_total_stake(&ah_api, ah_block_hash, &era_index).await?;
    nss.total_staked = total_staked;

    // total rewarded from previous era
    let last_rewarded = fetch_eras_validator_reward(&ah_api, ah_block_hash, &era_index).await?;
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
        .query_async::<_, ()>(&mut cache as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    // Log sesssion cache processed duration time
    info!(
        "Session #{} stats cached ({:?})",
        epoch_index,
        start.elapsed()
    );

    // Set synced session associated with era (useful for nomi boards)
    let mut era_data: BTreeMap<String, String> = BTreeMap::new();
    era_data.insert(String::from("synced_session"), epoch_index.to_string());
    era_data.insert(
        String::from(format!("synced_at_block:{}", epoch_index)),
        rc_block_number.to_string(),
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
        .query_async::<_, ()>(&mut cache as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

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
/// Fetch active era at the specified block hash (AH)
async fn fetch_active_era_info(
    api: &OnlineClient<PolkadotConfig>,
    ah_block_hash: H256,
) -> Result<ActiveEraInfo, OnetError> {
    let addr = asset_hub_runtime::storage().staking().active_era();

    api.storage()
        .at(ah_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Active era not defined at block hash {ah_block_hash}"
            ))
        })
}

/// Fetch eras start sesson info at the specified block hash (AH)
async fn fetch_eras_start_session_index(
    api: &OnlineClient<PolkadotConfig>,
    ah_block_hash: H256,
    era: &EraIndex,
) -> Result<ErasStartSessionIndex, OnetError> {
    let addr = asset_hub_runtime::storage()
        .staking()
        .eras_start_session_index(era);

    api.storage()
        .at(ah_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!("Start session index at block hash {ah_block_hash}"))
        })
}

/// Fetch eras total stake at the specified block hash (AH)
async fn fetch_eras_total_stake(
    api: &OnlineClient<PolkadotConfig>,
    ah_block_hash: H256,
    era: &EraIndex,
) -> Result<ErasTotalStake, OnetError> {
    let addr = asset_hub_runtime::storage().staking().eras_total_stake(era);

    api.storage()
        .at(ah_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Eras total stake not defined at block hash {ah_block_hash}"
            ))
        })
}

/// Fetch eras validator reward at the specified block hash (AH)
async fn fetch_eras_validator_reward(
    api: &OnlineClient<PolkadotConfig>,
    ah_block_hash: H256,
    era: &EraIndex,
) -> Result<ErasTotalStake, OnetError> {
    let addr = asset_hub_runtime::storage()
        .staking()
        .eras_validator_reward(era);

    api.storage()
        .at(ah_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Eras validator reward not defined at block hash {ah_block_hash}"
            ))
        })
}

/// Fetch nominators at the specified block hash
async fn fetch_nominators(
    api: &OnlineClient<PolkadotConfig>,
    asset_hub_hash: H256,
    stash: &AccountId32,
) -> Result<Nominators, OnetError> {
    let addr = asset_hub_runtime::storage().staking().nominators(stash);

    api.storage()
        .at(asset_hub_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Nominators not defined at block hash {asset_hub_hash}"
            ))
        })
}

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
async fn fetch_asset_hub_block_hash(
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

/// Fetch relay chain block hash from a specified block number
async fn fetch_relay_chain_block_hash(
    onet: &Onet,
    block_number: BlockNumber,
) -> Result<H256, OnetError> {
    onet.rpc()
        .chain_get_block_hash(Some(block_number.into()))
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Relay block hash not available at block number {block_number}"
            ))
        })
}

/// Fetch the included asset hub block hash from a specified relay chain block number
#[async_recursion]
async fn fetch_asset_hub_block_hash_from_relay_chain(
    onet: &Onet,
    rc_block_number: BlockNumber,
    rc_block_hash: H256,
) -> Result<H256, OnetError> {
    let rc_api = onet.client().clone();
    if let Some(hash) = fetch_asset_hub_block_hash(&rc_api, rc_block_hash).await? {
        return Ok(hash);
    }

    let rc_next_block_number = rc_block_number + 1;
    let rc_next_block_hash = fetch_relay_chain_block_hash(onet, rc_next_block_number).await?;

    fetch_asset_hub_block_hash_from_relay_chain(onet, rc_next_block_number, rc_next_block_hash)
        .await
}

/// Fetch the set of authorities (validators) at the specified block hash
async fn fetch_authorities(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
) -> Result<ValidatorSet, OnetError> {
    let addr = relay_runtime::storage().session().validators();

    api.storage().at(hash).fetch(&addr).await?.ok_or_else(|| {
        OnetError::from(format!(
            "Current validators not defined at block hash {hash}"
        ))
    })
}

/// Fetch queued_keys at the specified block hash
async fn fetch_queued_keys(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
) -> Result<QueuedKeys, OnetError> {
    let addr = relay_runtime::storage().session().queued_keys();

    api.storage()
        .at(hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| OnetError::from(format!("Queued keys not defined at block hash {hash}")))
}

/// Fetch validator points at the specified block hash
async fn fetch_validator_points(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
    stash: &AccountId32,
) -> Result<Points, OnetError> {
    let addr = relay_runtime::storage()
        .staking_next_ah_client()
        .validator_points(stash);

    api.storage().at(hash).fetch(&addr).await?.ok_or_else(|| {
        OnetError::from(format!(
            "Validator points not defined at block hash {:?}",
            hash
        ))
    })
}

/// Fetch para validator groups at the specified block hash
async fn fetch_para_validator_groups(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
) -> Result<ValidatorGroups, OnetError> {
    let addr = relay_runtime::storage().para_scheduler().validator_groups();

    api.storage().at(hash).fetch(&addr).await?.ok_or_else(|| {
        OnetError::from(format!("Validator groups not defined at block hash {hash}"))
    })
}

/// Fetch session index at the specified block hash
async fn fetch_session_index(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
) -> Result<SessionIndex, OnetError> {
    let addr = relay_runtime::storage().session().current_index();

    api.storage().at(hash).fetch(&addr).await?.ok_or_else(|| {
        OnetError::from(format!(
            "Current session index not defined at block hash {hash}"
        ))
    })
}

/// Fetch last pool ID at the specified block hash
async fn fetch_last_pool_id(
    api: &OnlineClient<PolkadotConfig>,
    asset_hub_hash: H256,
) -> Result<u32, OnetError> {
    let addr = asset_hub_runtime::storage()
        .nomination_pools()
        .last_pool_id();

    api.storage()
        .at(asset_hub_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Last pool ID not defined at block hash {asset_hub_hash}"
            ))
        })
}

/// Fetch bonded pools at the specified block hash
async fn fetch_bonded_pools(
    api: &OnlineClient<PolkadotConfig>,
    asset_hub_hash: H256,
    pool_id: u32,
) -> Result<BondedPools, OnetError> {
    let addr = asset_hub_runtime::storage()
        .nomination_pools()
        .bonded_pools(&pool_id);

    api.storage()
        .at(asset_hub_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Bonded Pools not defined at block hash {asset_hub_hash}"
            ))
        })
}

/// Fetch nomination pools metadata at the specified block hash
async fn fetch_pool_metadata(
    api: &OnlineClient<PolkadotConfig>,
    asset_hub_hash: H256,
    pool_id: u32,
) -> Result<PoolMetadata, OnetError> {
    let addr = asset_hub_runtime::storage()
        .nomination_pools()
        .metadata(&pool_id);

    api.storage()
        .at(asset_hub_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "PoolMetadata not defined at block hash {asset_hub_hash}"
            ))
        })
}

/// Fetch era reward points at the specified block hash
async fn fetch_era_reward_points(
    api: &OnlineClient<PolkadotConfig>,
    asset_hub_hash: H256,
    era: EraIndex,
) -> Result<EraRewardPoints<AccountId32>, OnetError> {
    let addr = asset_hub_runtime::storage()
        .staking()
        .eras_reward_points(&era);

    api.storage()
        .at(asset_hub_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Era reward points not found at block hash {asset_hub_hash} and era {era}",
            ))
        })
}

/// Fetch controller bonded account given a stash at the specified block hash
async fn fetch_bonded_controller_account(
    api: &OnlineClient<PolkadotConfig>,
    asset_hub_hash: H256,
    stash: &AccountId32,
) -> Result<AccountId32, OnetError> {
    let addr = asset_hub_runtime::storage().staking().bonded(stash);

    api.storage()
        .at(asset_hub_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Bonded controller not found at block hash {asset_hub_hash} and era {stash}"
            ))
        })
}

/// Fetch staking ledger given a stash at the specified block hash
async fn fetch_ledger_from_controller(
    api: &OnlineClient<PolkadotConfig>,
    asset_hub_hash: H256,
    stash: &AccountId32,
) -> Result<StakingLedger, OnetError> {
    let addr = asset_hub_runtime::storage().staking().ledger(stash);

    api.storage()
        .at(asset_hub_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Bonded controller not found at block hash {asset_hub_hash}"
            ))
        })
}

/// Fetch account info given a stash at the specified block hash
async fn fetch_account_info(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
    stash: &AccountId32,
) -> Result<AccountInfo<u32, AccountData<u128>>, OnetError> {
    let addr = relay_runtime::storage().system().account(stash);

    api.storage()
        .at(hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| OnetError::from(format!("Account info not found at block hash {hash}")))
}

/// Fetch total issuance at the specified block hash
async fn fetch_total_issuance(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
) -> Result<TotalIssuance, OnetError> {
    let addr = relay_runtime::storage().balances().total_issuance();

    api.storage()
        .at(hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| OnetError::from(format!("Total issuance not found at block hash {hash}")))
}

/// Fetch validator groups at the specified block hash
async fn fetch_validator_groups(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
) -> Result<ValidatorGroups, OnetError> {
    let addr = relay_runtime::storage().para_scheduler().validator_groups();

    api.storage()
        .at(hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| OnetError::from(format!("Validator groups not found for block hash {hash}")))
}

/// Fetch validator indices at the specified block hash
async fn fetch_validator_indices(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
) -> Result<ActiveValidatorIndices, OnetError> {
    let addr = relay_runtime::storage()
        .paras_shared()
        .active_validator_indices();

    api.storage()
        .at(hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| OnetError::from(format!("Validator indices not found at block hash {hash}")))
}

/// Fetch on chain votes at the specified block hash
async fn fetch_on_chain_votes(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
) -> Result<OnChainVotes, OnetError> {
    let addr = relay_runtime::storage().para_inherent().on_chain_votes();

    api.storage()
        .at(hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| OnetError::from(format!("On chain votes not found at block hash {hash}")))
}

/// Fetch last runtime upgrade on chain votes at the specified block hash
async fn fetch_last_runtime_upgrade(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
) -> Result<LastRuntimeUpgradeInfo, OnetError> {
    let addr = relay_runtime::storage().system().last_runtime_upgrade();

    api.storage().at(hash).fetch(&addr).await?.ok_or_else(|| {
        OnetError::from(format!(
            "Last runtime upgrade not found at block hash {hash}"
        ))
    })
}

// TODO: Fetch availability cores at the specified block hash
// async fn fetch_availability_cores(
//     api: &OnlineClient<PolkadotConfig>,
//     hash: H256,
// ) -> Result<Vec<CoreOccupied<u32>>, OnetError> {
//     let addr = node_runtime::storage()
//         .para_scheduler()
//         .availability_cores();

//     api.storage()
//         .at(hash)
//         .fetch(&addr)
//         .await?
//         .ok_or_else(|| OnetError::from("Availability cores not found at block hash {hash}"))
// }
