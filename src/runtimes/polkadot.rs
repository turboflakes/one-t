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

use crate::config::CONFIG;
use crate::errors::OnetError;
use crate::matrix::FileInfo;
use crate::onet::ReportType;
use crate::onet::{
    get_account_id_from_storage_key, get_subscribers, get_subscribers_by_epoch,
    try_fetch_stashes_from_remote_url, Onet, EPOCH_FILENAME,
};
use crate::records::{
    decode_authority_index, AuthorityIndex, AuthorityRecord, EpochIndex, EpochKey, EraIndex,
    ParaId, ParaRecord, ParaStats, Points, Records, Subscribers,
};
use crate::report::{
    Callout, Metadata, Network, RawData, RawDataGroup, RawDataPara, RawDataParachains, RawDataRank,
    Report, Subset, Validator, Validators,
};

use async_recursion::async_recursion;
use futures::StreamExt;
use log::{debug, error, info};
use std::{
    collections::BTreeMap, convert::TryInto, fs, iter::FromIterator, result::Result, thread, time,
};
use subxt::{sp_runtime::AccountId32, DefaultConfig, SubstrateExtrinsicParams};

#[subxt::subxt(
    runtime_metadata_path = "metadata/polkadot_metadata.scale",
    generated_type_derives = "PartialEq, Clone"
)]
mod node_runtime {}

use node_runtime::{
    runtime_types::{
        pallet_identity::types::Data, polkadot_parachain::primitives::Id,
        polkadot_primitives::v0::ValidatorIndex, polkadot_primitives::v1::CoreIndex,
        polkadot_primitives::v1::GroupIndex, polkadot_primitives::v0::ValidityAttestation,
        sp_arithmetic::per_things::Perbill,
    },
    session::events::NewSession,
};

type Api = node_runtime::RuntimeApi<DefaultConfig, SubstrateExtrinsicParams<DefaultConfig>>;

pub async fn init_and_subscribe_on_chain_events(onet: &Onet) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let client = onet.client().clone();
    let api = client.to_runtime_api::<Api>();

    let finalized_hash = api.client.rpc().finalized_head().await?;

    let block_number = match api.client.rpc().block(Some(finalized_hash)).await? {
        Some(signed_block) => signed_block.block.header.number,
        None => return Err("Finalized hash not available. Check current API -> api.client.rpc().block(Some(finalized_hash))".into()),
    };

    // Fetch active era index
    let era_index = match api.storage().staking().active_era(None).await? {
        Some(active_era_info) => active_era_info.index,
        None => return Err("Active era not available. Check current API -> api.storage().staking().active_era(None)".into()),
    };

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

    // Subscribe to any events that occur:
    let mut sub = api.events().subscribe_finalized().await?;

    while let Some(events) = sub.next().await {
        let events = events?;
        let block_hash = events.block_hash();

        if let Some(signed_block) = api.client.rpc().block(Some(block_hash)).await? {
            if let Some(authority_index) = decode_authority_index(&signed_block) {
                let block_number = signed_block.block.header.number;
                info!("Finalized block #{block_number} received");

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
                }

                // Update current block number
                records.set_current_block_number(block_number.into());
            }
        }
    }
    // If subscription has closed for some reason await and subscribe again
    Err(OnetError::SubscriptionFinished)
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

    // Find groupIdx and peers for each authority
    for (auth_idx, stash) in authorities.iter().enumerate() {
        let auth_idx: AuthorityIndex = auth_idx.try_into().unwrap();
        // Find para groupIdx
        let active_validator_indices = api
            .storage()
            .paras_shared()
            .active_validator_indices(None)
            .await?;

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

    debug!("records {:?}", records);
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

    // Flag validators with poor performance in previous epoch
    flag_validators_with_poor_performance(records.current_era(), records.current_epoch(), records)?;

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

    // Fetch Era reward points
    let era_reward_points = api
        .storage()
        .staking()
        .eras_reward_points(&records.current_era(), None)
        .await?;

    // Fetch currently scheduled cores
    let scheduled_cores = api.storage().para_scheduler().scheduled(None).await?;

    // Fetch on chain votes
    let on_chain_votes = api.storage().para_inherent().on_chain_votes(None).await?;

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
                // Update current points and get the difference
                let diff_points = authority_record.update_current_points(current_points);

                if let Some(para_record) = records.get_mut_para_record(*authority_idx) {
                    // 1st. Check if the para_id assigned to this authority got any on chain votes
                    if let Some(ref backing_votes) = on_chain_votes {
                        // Verify that records are in the same session as on chain votes
                        if current_session == backing_votes.session {
                            for (candidate_receipt, group_authorities) in
                                backing_votes.backing_validators_per_candidate.iter()
                            {
                                // Destructure ParaId
                                let Id(para_id) = candidate_receipt.descriptor.para_id;
                                // If para id exists increment vote or missed vote
                                if para_record.is_para_id_assigned(para_id) {
                                    debug!(
                                        "para_id: {} group_authorities {:?}",
                                        para_id, group_authorities
                                    );

                                    if let Some((_, vote)) =
                                        group_authorities.iter().find(
                                            |(ValidatorIndex(para_idx), _)| {
                                                para_idx == para_record.para_index()
                                            },
                                        )
                                    {
                                        match vote {
                                            ValidityAttestation::Explicit(_) => {
                                                para_record.inc_explicit_votes(para_id);
                                            }
                                            ValidityAttestation::Implicit(_) => {
                                                para_record.inc_implicit_votes(para_id);
                                            }
                                        }
                                    } else {
                                        para_record.inc_missed_votes(para_id);
                                    }

                                    break;
                                }
                            }
                        }
                    }

                    // 2nd. Identify if groupIdx has been assigned to a core
                    if let Some(group_idx) = &para_record.group() {
                        if let Some(core_assignment) = scheduled_cores
                            .iter()
                            .find(|ca| ca.group_idx == GroupIndex(*group_idx))
                        {
                            debug!("core_assignment: {:?}", core_assignment);
                            // CoreAssignment { core: CoreIndex(16), para_id: Id(2087), kind: Parachain, group_idx: GroupIndex(31) }

                            // Destructure CoreIndex
                            let CoreIndex(core) = core_assignment.core;
                            // Destructure Id
                            let Id(para_id) = core_assignment.para_id;

                            // Update authority ParaRecord
                            para_record.update(
                                core,
                                para_id,
                                diff_points,
                                authority_index == *authority_idx,
                            );
                        }
                    }

                    debug!("para_record {:?}", para_record);
                }
            }
        }
    }

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
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();

    let network = Network::load(client).await?;
    // Set era/session details
    let start_block = records
        .start_block(EpochKey(era_index, epoch_index))
        .unwrap_or(&0);
    let end_block = records
        .end_block(EpochKey(era_index, epoch_index))
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
    let mut group_authorities_map: BTreeMap<u32, Vec<AuthorityRecord>> = BTreeMap::new();

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
                        auths.push(authority_record.clone());
                        auths.sort_by(|a, b| b.points().cmp(&a.points()));
                    }
                }
            }
        }
    }

    // Convert map to vec and sort group by points
    let mut group_authorities_sorted = Vec::from_iter(group_authorities_map);
    group_authorities_sorted.sort_by(|(_, a), (_, b)| {
        b.iter()
            .map(|x| x.points())
            .sum::<Points>()
            .cmp(&a.iter().map(|x| x.points()).sum::<Points>())
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
                is_first_record: records.is_initial_epoch(epoch_index),
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
                            if let Some(validator_rank) = authorities.iter().position(|a| {
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

// Poor performance validators are the ones who missed more than 50% of the blocks
// compared to the top performer in the group
pub fn flag_validators_with_poor_performance(
    era_index: EraIndex,
    epoch_index: EpochIndex,
    records: &mut Records,
) -> Result<(), OnetError> {
    // Populate some maps to get ranks
    let mut group_authorities_map: BTreeMap<u32, Vec<AuthorityRecord>> = BTreeMap::new();

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
                        auths.push(authority_record.clone());
                    }
                }
            }
        }
    }

    for (_, authorities) in group_authorities_map.iter() {
        // Get the maximum_para_points from the authorities in the val. group
        if let Some(maximum_points) = authorities.iter().map(|a| a.para_points()).max() {
            for authority_record in authorities.iter() {
                // Flag authorities with less than 50% points of the top authority
                if (authority_record.para_points() as f64 / maximum_points as f64) < 0.5 {
                    records.flag_authority(
                        authority_record.authority_index().clone(),
                        EpochKey(era_index, epoch_index),
                    );
                }
            }
        }
    }

    debug!("records {:?}", records);

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
        .start_block(EpochKey(era_index, epoch_index))
        .unwrap_or(&0);
    let end_block = records
        .end_block(EpochKey(era_index, epoch_index))
        .unwrap_or(&0);
    let metadata = Metadata {
        active_era_index: era_index,
        current_session_index: epoch_index,
        blocks_interval: Some((*start_block, *end_block)),
        ..Default::default()
    };

    // Populate some maps to get ranks
    let mut group_authorities_map: BTreeMap<u32, Vec<(AuthorityRecord, String, u32, f64)>> =
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
                        // collect core_assignments
                        let core_assignments: u32 = para_record.total_core_assignments();

                        // collect missed_votes_ratio
                        let missed_votes_ratio: f64 = para_record.missed_votes_ratio();

                        // get validator name
                        let name =
                            get_display_name(&onet, &authority_record.address(), None).await?;

                        //
                        let auths = group_authorities_map.entry(group_idx).or_insert(Vec::new());
                        auths.push((
                            authority_record.clone(),
                            name,
                            core_assignments,
                            missed_votes_ratio,
                        ));
                        auths.sort_by(|(a, _, _, _), (b, _, _, _)| b.points().cmp(&a.points()));
                    }
                }
            }
        }
    }

    // Convert map to vec and sort group by points
    let mut group_authorities_sorted = Vec::from_iter(group_authorities_map);
    group_authorities_sorted.sort_by(|(_, a), (_, b)| {
        b.iter()
            .map(|x| x.0.points())
            .sum::<Points>()
            .cmp(&a.iter().map(|x| x.0.points()).sum::<Points>())
    });

    let data = RawDataGroup {
        network: network.clone(),
        meta: metadata.clone(),
        report_type: ReportType::Groups,
        is_first_record: records.is_initial_epoch(epoch_index),
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
        .start_block(EpochKey(era_index, epoch_index))
        .unwrap_or(&0);
    let end_block = records
        .end_block(EpochKey(era_index, epoch_index))
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
                    s.points += stats.points();
                    s.core_assignments += stats.core_assignments();
                    s.authored_blocks += stats.authored_blocks();
                }
            }
        }
    }

    // Convert map to vec and sort group by points
    let mut parachains_sorted = Vec::from_iter(parachains_map);
    parachains_sorted.sort_by(|(_, a), (_, b)| b.points().cmp(&a.points()));

    let data = RawDataParachains {
        network: network.clone(),
        meta: metadata.clone(),
        report_type: ReportType::Parachains,
        is_first_record: records.is_initial_epoch(epoch_index),
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
    //
    // Trigger network report every 6 epochs (every era)
    if (epoch_index as f64 % 6.0_f64) == 0.0_f64 {
        let records_cloned = records.clone();
        async_std::task::spawn(async move {
            if let Err(e) = run_network_report(&records_cloned).await {
                error!("try_run_network_report error: {:?}", e);
            }
        });
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
        // Get nodes identity
        v.name = get_display_name(&onet, &stash, None).await?;
        // Check if validator is in active set
        v.is_active = active_validators.contains(&stash);

        // Fetch own stake
        v.own_stake = get_own_stake(&onet, &stash).await?;

        // Check if validator was active last era
        v.active_last_era =
            records.is_active_at(&stash, active_era_index - 1, current_session_index - 1);

        // Get flagged epochs from previous era
        let mut flagged_epochs =
            records.get_flagged_epochs(&stash, active_era_index - 1, current_session_index - 6);
        v.flagged_epochs.append(&mut flagged_epochs);

        // Get para epochs and missed blocks from previous era
        v.last_missed_ratio = records.get_missed_votes_ratio_for_previous_era(&stash);
        // Get very low performant nodes identity
        // if v.last_missed_ratio > 0.75 && v.name.is_empty() {
        //     v.name = get_display_name(&onet, &stash, None).await?;
        // }

        // Get performance data from all full eras
        if let Some((mut status_pattern, para_data)) =
            records.get_performance_data_for_all_records(&stash)
        {
            v.status_pattern.append(&mut status_pattern);
            if let Some((mut para_epochs, para_points, votes, missed_votes)) = para_data {
                v.para_epochs.append(&mut para_epochs);
                v.votes = Some(votes);
                v.missed_votes = Some(missed_votes);
                if votes + missed_votes > 0 {
                    v.missed_ratio = Some(missed_votes as f64 / (votes + missed_votes) as f64);
                }
                if para_epochs.len() > 0 {
                    v.avg_para_points = Some(para_points / para_epochs.len() as u32);
                }
            }
        }

        //
        validators.push(v);
    }

    // Collect era points for maximum_history_eras and incremental
    let start_era_index = active_era_index - config.maximum_history_eras;
    for era_index in start_era_index..active_era_index {
        let start_incremental_era_index = active_era_index - (1 * records.total_full_eras());
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
                    if era_index >= start_incremental_era_index {
                        (*v).total_eras += 1;
                        (*v).total_points += points;
                    }
                });
        }
    }

    debug!("validators {:?}", validators);

    // Network report data
    let data = RawData {
        network: network.clone(),
        meta: metadata.clone(),
        validators: validators.clone(),
        records_total_full_eras: records.total_full_eras(),
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
    let start_era = active_era_index - (1 * records.total_full_eras());
    let start_block = records
        .start_block(EpochKey(
            start_era,
            current_session_index - (6 * records.total_full_eras()),
        ))
        .unwrap_or(&0);
    let end_era = active_era_index - 1;
    let end_block = records
        .end_block(EpochKey(end_era, current_session_index - 1))
        .unwrap_or(&0);
    let metadata = Metadata {
        eras_interval: Some((start_era, end_era)),
        blocks_interval: Some((*start_block, *end_block)),
        ..Default::default()
    };

    let data = RawDataRank {
        network: network.clone(),
        meta: metadata.clone(),
        report_type: ReportType::Ranking,
        validators,
        records_total_full_eras: records.total_full_eras(),
    };

    let report = Report::from(data);

    let filename = format!(
        "onet_{}_vprr_{}_{}.txt.gz",
        config.chain_name.to_lowercase(),
        start_era,
        end_era
    );
    let path_filename = format!("{}{}", config.data_path, filename);
    report.save(&path_filename)?;
    // Get file size
    let file_size = fs::metadata(&path_filename)?.len();

    if let Some(url) = onet.matrix().upload_file(&path_filename)? {
        if let Ok(subs) = get_subscribers_by_epoch(ReportType::Ranking, None) {
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

    Ok(())
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
    format!("{}", String::from_utf8(bytes).expect("Identity not utf-8"))
}
