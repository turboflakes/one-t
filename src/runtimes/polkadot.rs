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
    ParaId, ParaRecord, ParaStats, Points, Records, Subscribers, Votes,
};
use crate::report::{
    Callout, Metadata, Network, RawData, RawDataGroup, RawDataPara, RawDataParachains, RawDataRank,
    Report, Subset, Validator, Validators,
};

use async_recursion::async_recursion;
use futures::StreamExt;
use log::{debug, error, info, warn};
use std::{
    collections::BTreeMap, convert::TryInto, fs, iter::FromIterator, result::Result, thread, time,
};
use subxt::{sp_runtime::AccountId32, DefaultConfig, PolkadotExtrinsicParams};

#[subxt::subxt(
    runtime_metadata_path = "metadata/polkadot_metadata.scale",
    derive_for_all_types = "PartialEq, Clone"
)]
mod node_runtime {}

use node_runtime::{
    runtime_types::{
        pallet_identity::types::Data, polkadot_parachain::primitives::Id,
        polkadot_primitives::v2::CoreIndex, polkadot_primitives::v2::GroupIndex,
        polkadot_primitives::v2::ValidatorIndex, polkadot_primitives::v2::ValidityAttestation,
        sp_arithmetic::per_things::Perbill,
    },
    session::events::NewSession,
};

type Api = node_runtime::RuntimeApi<DefaultConfig, PolkadotExtrinsicParams<DefaultConfig>>;

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

    // Fetch current session index
    let session_index = api.storage().session().current_index(None).await?;
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
        Records::with_era_epoch_and_block(era_index, session_index, block_number.into());

    // Initialize subscribers records
    initialize_records(&onet, &mut records).await?;

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
                    }

                    // Update current block number
                    records.set_current_block_number(block_number.into());
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
        for (account, user_id, param) in subs.iter() {
            subscribers.subscribe(account.clone(), user_id.to_string(), param.clone());
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

    // Fetch para validator groups
    let validator_groups = api
        .storage()
        .para_scheduler()
        .validator_groups(None)
        .await?;

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
                if authority_record.address().is_some() {
                    // Increment authored blocks if it is the current block author
                    if authority_index == *authority_idx {
                        authority_record.inc_authored_blocks();
                    }

                    // Collect current points
                    let current_points = if let Some((_s, points)) = era_reward_points
                        .individual
                        .iter()
                        .find(|(s, _p)| s == authority_record.address().unwrap())
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
                                                if let Some(group_idx) = para_record.group() {
                                                    let (para_val_idx, _) = &group_authorities[0];

                                                    for (idx, group) in
                                                        validator_groups.iter().enumerate()
                                                    {
                                                        if group.contains(&para_val_idx) {
                                                            if idx == group_idx as usize {
                                                                para_record
                                                                    .inc_missed_votes(para_id);
                                                                break;
                                                            }
                                                        }
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
                if para_epochs > 0 {
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
                    validators,
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

async fn get_display_name(onet: &Onet, stash: &AccountId32) -> Result<String, OnetError> {
    if let Some(identity) = get_identity(&onet, &stash, None).await? {
        return Ok(identity);
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
) -> Result<Option<String>, OnetError> {
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
            Ok(Some(name))
        }
        None => {
            if let Some((parent_account, data)) =
                api.storage().identity().super_of(stash, None).await?
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
