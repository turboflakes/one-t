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
use crate::onet::{
    get_account_id_from_storage_key, get_subscribers, try_fetch_stashes_from_remote_url, Onet,
};
use crate::records::{
    decode_authority_index, AddressKey, AuthoredBlocks, AuthorityIndex, AuthorityRecord,
    BlockNumber, EpochIndex, EpochKey, EraIndex, ParaId, ParaRecord, Points, Records, Subscribers,
};
use crate::report::{
    Network, RawData, RawDataPara, Report, Session, Subset, Validator, Validators,
};
use async_recursion::async_recursion;
use futures::StreamExt;
use log::{debug, info, warn};
use std::{
    collections::{BTreeMap, HashSet},
    convert::{TryFrom, TryInto},
    result::Result,
    str::FromStr,
    thread, time,
};
use subxt::{sp_runtime::AccountId32, DefaultConfig, DefaultExtra};

#[subxt::subxt(
    runtime_metadata_path = "metadata/kusama_metadata.scale",
    generated_type_derives = "PartialEq, Clone"
)]
mod node_runtime {}

use node_runtime::{
    runtime_types::{
        pallet_identity::types::Data, polkadot_parachain::primitives::Id,
        polkadot_primitives::v0::ValidatorIndex, polkadot_primitives::v1::CoreIndex,
        polkadot_primitives::v1::GroupIndex, sp_arithmetic::per_things::Perbill,
    },
    session::events::NewSession,
};

type Api = node_runtime::RuntimeApi<DefaultConfig, DefaultExtra<DefaultConfig>>;

pub async fn init_and_subscribe_on_chain_events(onet: &Onet) -> Result<(), OnetError> {
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

                let new_session_event = events.find_first::<NewSession>()?;

                track_new_session_event(
                    &onet,
                    block_number,
                    new_session_event,
                    &mut subscribers,
                    &mut records,
                )
                .await?;

                // Update current block number
                records.set_current_block_number(block_number.into());

                track_records(&onet, authority_index, &mut records, &subscribers).await?;

                // try_run_report(&onet, ev).await?;
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
                                let para_record = ParaRecord::with_group_and_peers(
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

pub async fn track_new_session_event<'a>(
    onet: &Onet,
    block_number: u32,
    event: Option<NewSession>,
    subscribers: &mut Subscribers,
    records: &mut Records,
) -> Result<(), OnetError> {
    if let Some(ev) = event {
        let client = onet.client();
        let api = client.clone().to_runtime_api::<Api>();

        let previous_era_index = records.current_era().clone();

        // Fetch active era index
        let current_era_index = match api.storage().staking().active_era(None).await? {
            Some(active_era_info) => active_era_info.index,
            None => return Err("Active era not available".into()),
        };

        // Update records current Era and Epoch
        records.start_new_epoch(current_era_index, ev.session_index);
        // Update records current block number
        records.set_current_block_number(block_number.into());

        // Update subscribers current Era and Epoch
        subscribers.start_new_epoch(current_era_index, ev.session_index);

        if let Ok(subs) = get_subscribers() {
            for (account, user_id) in subs.iter() {
                subscribers.subscribe(account.clone(), user_id.to_string());
            }
        }

        // Initialize records for new
        initialize_records(&onet, records).await?;

        // Send report from previous session
        let era_index: u32 = if current_era_index != previous_era_index {
            previous_era_index
        } else {
            current_era_index
        };

        let records_cloned = records.clone();
        let subscribers_cloned = subscribers.clone();
        async_std::task::spawn(async move {
            let t: Onet = Onet::new().await;
            try_run_para_report(
                &t,
                era_index,
                records_cloned.current_epoch() - 1,
                &records_cloned,
                &subscribers_cloned,
            )
            .await
            .unwrap();
        });

        // TODO: if new era clear previous era sessions from cache
    }
    Ok(())
}

pub async fn track_records(
    onet: &Onet,
    authority_index: AuthorityIndex,
    records: &mut Records,
    subscribers: &Subscribers,
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
                    // Identify if groupIdx has been assigned to a core
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
                }
            }
        }
    }

    // // TEST report
    // let block_number = *records.current_block().unwrap_or(&0);
    // let block_number: i64 = i64::try_from(block_number).unwrap();
    // warn!("block_number {}", block_number);
    // let remainder = block_number as f64 % 8.0_f64;
    // if remainder == 0.0_f64 {
    //     let mut records = records.clone();
    //     let mut subscribers = subscribers.clone();
    //     async_std::task::spawn(async move {
    //         let t: Onet = Onet::new().await;
    //         try_run_para_report(
    //             &t,
    //             records.current_era(),
    //             records.current_epoch(),
    //             &records,
    //             &subscribers,
    //         )
    //         .await
    //         .unwrap();
    //     });
    // }

    debug!("records {:?}", records);

    Ok(())
}

pub async fn try_run_para_report(
    onet: &Onet,
    era_index: EraIndex,
    epoch_index: EpochIndex,
    records: &Records,
    subscribers: &Subscribers,
) -> Result<(), OnetError> {
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();

    // Fetch parachains list
    // TODO: get parachains names
    let mut parachains: Vec<ParaId> = Vec::new();
    for Id(para_id) in api.storage().paras().parachains(None).await? {
        parachains.push(para_id);
    }
    let network = Network::load(client).await?;
    // Set era/session details
    let start_block = records
        .start_block(EpochKey(era_index, epoch_index))
        .unwrap_or(&0);
    let end_block = records
        .end_block(EpochKey(era_index, epoch_index))
        .unwrap_or(&0);
    let session = Session {
        active_era_index: era_index,
        current_session_index: epoch_index,
        start_block: *start_block,
        end_block: *end_block,
        ..Default::default()
    };

    if let Some(subs) = subscribers.get(Some(EpochKey(era_index, epoch_index))) {
        for (stash, user_id) in subs.iter() {
            let mut validator = Validator::new(stash.clone());
            validator.name = get_display_name(&onet, &stash, None).await?;
            let mut data = RawDataPara {
                network: network.clone(),
                session: session.clone(),
                parachains: parachains.clone(),
                validator,
                authority_record: None,
                para_record: None,
                peers: Vec::new(),
            };

            if let Some(authority_record) = records
                .get_authority_record_with_address(&stash, Some(EpochKey(era_index, epoch_index)))
            {
                data.authority_record = Some(authority_record.clone());

                if let Some(para_record) = records
                    .get_para_record_with_address(&stash, Some(EpochKey(era_index, epoch_index)))
                {
                    data.para_record = Some(para_record.clone());

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
                }
            }
            // TODO: get subscribers accounts

            let report = Report::from(data);

            onet.send_private_message(user_id, &report.message(), &report.formatted_message())
                .await?;
            // NOTE: To not overflow matrix with messages just send maximum 2 per second
            thread::sleep(time::Duration::from_millis(500));
        }
    }

    Ok(())
}

pub async fn try_run_report(onet: &Onet, event: Option<NewSession>) -> Result<(), OnetError> {
    if let Some(ev) = event {
        // ev =  NewSession { session_index: 19848 }
        let config = CONFIG.clone();
        info!("Event: {:?}", ev);
        // Verify if the remainder of the session_index divided by the session rate equals zero
        let remainder = ev.session_index as f64 % config.session_rate as f64;
        if remainder == 0.0_f64 {
            // Trigger report
            run_report(&onet).await?;
        }
    }
    Ok(())
}

pub async fn run_report(onet: &Onet) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let client = onet.client();
    let api = client.clone().to_runtime_api::<Api>();

    let network = Network::load(client).await?;

    // Fetch active era
    let active_era_index = match api.storage().staking().active_era(None).await? {
        Some(active_era_info) => active_era_info.index,
        None => return Err("Active era not available".into()),
    };

    // Fetch active era total stake

    let active_era_total_stake = api
        .storage()
        .staking()
        .eras_total_stake(&active_era_index, None)
        .await?;

    // Set era/session details
    let session = Session {
        active_era_index,
        active_era_total_stake,
        ..Default::default()
    };

    let mut validators: Validators = Vec::new();

    // Load TVP stashes
    let tvp_stashes: Vec<AccountId32> = match try_fetch_stashes_from_remote_url("kusama").await? {
        Some(stashes) => stashes,
        None => Vec::new(), // TODO load stashes from previoust request saved in a local temp file
    };

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
                // Get TVP nodes identity
                v.name = get_display_name(&onet, &stash, None).await?;
            }
            v.is_oversubscribed = verify_oversubscribed(&onet, active_era_index, &stash).await?;
        } else {
            v.subset = Subset::C100;
        }
        // Check if validator is in active set
        v.is_active = active_validators.contains(&stash);

        // Fetch own stake
        v.own_stake = get_own_stake(&onet, &stash).await?;

        //
        validators.push(v);
    }

    // Collect era points
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
                    (*v).total_eras += 1;
                    (*v).total_points += points;
                });
        }
    }

    debug!("validators {:?}", validators);

    let data = RawData {
        network,
        validators,
        session,
    };

    let report = Report::from(data);
    onet.send_public_message(&report.message(), &report.formatted_message())
        .await?;

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
