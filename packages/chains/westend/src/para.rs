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

use crate::westend::fetch_block_info;
use log::{info, warn};
use onet_asset_hub_westend as asset_hub;
use onet_bulletin_westend as bulletin;
use onet_chains::SupportedParasRuntime;
use onet_core::core::ChainClient;
use onet_core::error::OnetError;
use onet_people_westend as people;
use onet_records::{
    collators::{CollatorKind, Slot},
    BlockNumber, EraIndex, Records,
};
use subxt::{
    config::{
        substrate::{Digest, DigestItem},
        RpcConfigFor,
    },
    rpcs::LegacyRpcMethods,
    utils::{AccountId32, H256},
    OnlineClientAtBlock, PolkadotConfig,
};

/// Maximum number of para blocks followed back from the head in one go
const MAX_BLOCKS_WALK: u64 = 3600;

type ParaRpc = LegacyRpcMethods<RpcConfigFor<PolkadotConfig>>;

fn short(account: &AccountId32) -> String {
    account.to_string().chars().take(8).collect()
}

fn describe(collators: &[(AccountId32, CollatorKind)]) -> String {
    collators
        .iter()
        .enumerate()
        .map(|(i, (a, k))| format!("{i}:{}:{:?}", short(a), k))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Follow every parachain block from the last processed one up to the given head.
/// Blocks are processed oldest first.
pub async fn process_para_block(
    chain: &ChainClient,
    ah: &ChainClient,
    runtime: SupportedParasRuntime,
    head_number: BlockNumber,
    head_hash: H256,
    head_parent_hash: H256,
    records: &mut Records,
) -> Result<(), OnetError> {
    if !is_supported(runtime) {
        return Err(OnetError::from(format!(
            "Block tracking not supported for {runtime}"
        )));
    }
    let para_id = runtime.para_id();
    let mut blocks = vec![(head_number, head_hash)];
    if let Some(last) = records.para_slots(para_id).and_then(|t| t.last_block()) {
        if head_number <= last {
            return Ok(());
        }
        if head_number - last > MAX_BLOCKS_WALK {
            warn!(
                "{runtime}: head {head_number} is too far from last block {last}, restarting tracking"
            );
            records.para_slots_mut(para_id).break_continuity();
        } else {
            let mut number = head_number;
            let mut parent_hash = head_parent_hash;
            while number - 1 > last {
                number -= 1;
                blocks.push((number, parent_hash));
                parent_hash = fetch_block_info(&chain.rpc, parent_hash).await?.1;
            }
        }
    }
    blocks.reverse();

    for (number, hash) in blocks {
        process_block(chain, ah, runtime, number, hash, records).await?;
    }
    Ok(())
}

async fn process_block(
    chain: &ChainClient,
    ah: &ChainClient,
    runtime: SupportedParasRuntime,
    number: BlockNumber,
    hash: H256,
    records: &mut Records,
) -> Result<(), OnetError> {
    let para_id = runtime.para_id();
    let at = chain.client.at_block(hash).await?;

    if !records
        .para_slots(para_id)
        .is_some_and(|t| t.is_initialized())
    {
        initialize_tracker(&at, ah, runtime, number, records).await?;
    }

    // Right after a rotation print both candidates so the assumed owner can be confirmed
    let slot = fetch_aura_slot(&chain.rpc, hash).await?;
    if let (Some(previous), Some(slot)) = (
        records.para_slots_mut(para_id).take_previous_collators(),
        slot,
    ) {
        let owner = |set: &[(AccountId32, CollatorKind)]| {
            if set.is_empty() {
                "-".to_string()
            } else {
                let i = (slot % set.len() as u64) as usize;
                format!("{i}:{}", short(&set[i].0))
            }
        };
        info!(
            "{runtime}: block {number} slot {slot} first after rotation, owner with previous set {} | with current set {}",
            owner(&previous),
            owner(
                records
                    .para_slots(para_id)
                    .map(|t| t.collators())
                    .unwrap_or_default()
            )
        );
    }

    let (new_session, drawn) = fetch_session_events(runtime, &at).await?;

    // The session index changes in the block of the event, the collators only apply from the next block
    if let Some(session_index) = new_session {
        records.para_slots_mut(para_id).set_session(session_index);
        let era = fetch_era(ah, runtime, &at).await?;
        records.set_para_session_era(para_id, session_index, era);
        // era points per block are set by governance, so refresh them at every new session
        let points = fetch_points_per_block(ah, runtime).await?;
        if points != records.para_slots_mut(para_id).points_per_block() {
            info!("{runtime}: era points per collated block changed to {points}");
            records.para_slots_mut(para_id).set_points_per_block(points);
        }
    }
    match slot {
        Some(slot) => records.track_para_block(para_id, number, slot),
        None => warn!("{runtime}: no aura slot found in block {number}"),
    }
    if let Some(session_index) = new_session {
        let collators = fetch_collators(runtime, &at).await?;
        info!(
            "{runtime}: block {number} NewSession {session_index} slot {:?} drawn {:?} collators [{}]",
            slot,
            drawn,
            describe(&collators)
        );
        records.para_slots_mut(para_id).set_collators(collators);
    }
    Ok(())
}

async fn initialize_tracker(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    ah: &ChainClient,
    runtime: SupportedParasRuntime,
    number: BlockNumber,
    records: &mut Records,
) -> Result<(), OnetError> {
    let para_id = runtime.para_id();
    let slot_duration = fetch_aura_slot_duration(runtime, at)?;
    // slot_duration / relay chain slot duration (6s) * velocity (milli units)
    let blocks_per_slot = slot_duration / 6000 * runtime.block_processing_velocity() / 1000;

    let session = fetch_session_current_index(runtime, at).await?;
    let collators = fetch_collators(runtime, at).await?;
    let points_per_block = fetch_points_per_block(ah, runtime).await?;

    info!(
        "{runtime}: tracker initialized at block {number} session {session} slot_duration {slot_duration}ms blocks_per_slot {blocks_per_slot} points_per_block {points_per_block} collators [{}]",
        describe(&collators)
    );
    let tracker = records.para_slots_mut(para_id);
    tracker.set_blocks_per_slot(blocks_per_slot);
    tracker.set_points_per_block(points_per_block);
    tracker.set_session(session);
    tracker.set_collators(collators);
    // Note: kept if it was resumed from the cache
    let era = fetch_era(ah, runtime, at).await?;
    records.set_para_session_era(para_id, session, era);
    Ok(())
}

/// Era points a validator earns for each block collated on the parachain.
/// Note: points are set on asset hub (staking), for every parachain source.
async fn fetch_points_per_block(
    ah: &ChainClient,
    runtime: SupportedParasRuntime,
) -> Result<u32, OnetError> {
    let at = ah.client.at_current_block().await?;
    asset_hub::fetch_collation_points_per_block(&at, runtime.para_id()).await
}

/// Runtimes with the collators pallets wired
fn is_supported(runtime: SupportedParasRuntime) -> bool {
    matches!(
        runtime,
        SupportedParasRuntime::AssetHubWestend
            | SupportedParasRuntime::PeopleWestend
            | SupportedParasRuntime::BulletinWestend
    )
}

fn unsupported(runtime: SupportedParasRuntime) -> OnetError {
    OnetError::from(format!("Block tracking not supported for {runtime}"))
}

/// Era of the parachain sessions, the active era of staking on asset hub.
/// Note: asset hub is read at the block of the session and the other parachains at the asset hub head.
async fn fetch_era(
    ah: &ChainClient,
    runtime: SupportedParasRuntime,
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<EraIndex, OnetError> {
    if matches!(runtime, SupportedParasRuntime::AssetHubWestend) {
        return Ok(asset_hub::fetch_active_era_info(at).await?.index);
    }
    let at_ah = ah.client.at_current_block().await?;
    Ok(asset_hub::fetch_active_era_info(&at_ah).await?.index)
}

fn fetch_aura_slot_duration(
    runtime: SupportedParasRuntime,
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<u64, OnetError> {
    match runtime {
        SupportedParasRuntime::AssetHubWestend => asset_hub::fetch_aura_slot_duration(at),
        SupportedParasRuntime::PeopleWestend => people::fetch_aura_slot_duration(at),
        SupportedParasRuntime::BulletinWestend => bulletin::fetch_aura_slot_duration(at),
        _ => Err(unsupported(runtime)),
    }
}

async fn fetch_session_current_index(
    runtime: SupportedParasRuntime,
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<u32, OnetError> {
    match runtime {
        SupportedParasRuntime::AssetHubWestend => asset_hub::fetch_session_current_index(at).await,
        SupportedParasRuntime::PeopleWestend => people::fetch_session_current_index(at).await,
        SupportedParasRuntime::BulletinWestend => bulletin::fetch_session_current_index(at).await,
        _ => Err(unsupported(runtime)),
    }
}

/// Fetch the `NewSession` session index and the `CollatorsDrawn` event (as debug) of a block.
async fn fetch_session_events(
    runtime: SupportedParasRuntime,
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<(Option<u32>, Option<String>), OnetError> {
    let mut new_session = None;
    let mut drawn = None;
    for event in at.events().fetch().await?.iter() {
        let Ok(event) = event else { continue };
        match runtime {
            SupportedParasRuntime::AssetHubWestend => {
                if let Some(ev) = event
                    .decode_fields_as::<asset_hub::asset_hub_runtime::session::events::NewSession>()
                    .transpose()?
                {
                    new_session = Some(ev.session_index);
                } else if let Some(ev) = event
                    .decode_fields_as::<asset_hub::asset_hub_runtime::validator_collators::events::CollatorsDrawn>()
                    .transpose()?
                {
                    drawn = Some(format!("{ev:?}"));
                }
            }
            SupportedParasRuntime::PeopleWestend => {
                if let Some(ev) = event
                    .decode_fields_as::<people::people_runtime::session::events::NewSession>()
                    .transpose()?
                {
                    new_session = Some(ev.session_index);
                } else if let Some(ev) = event
                    .decode_fields_as::<people::people_runtime::validator_collators::events::CollatorsDrawn>()
                    .transpose()?
                {
                    drawn = Some(format!("{ev:?}"));
                }
            }
            SupportedParasRuntime::BulletinWestend => {
                if let Some(ev) = event
                    .decode_fields_as::<bulletin::bulletin_runtime::session::events::NewSession>()
                    .transpose()?
                {
                    new_session = Some(ev.session_index);
                } else if let Some(ev) = event
                    .decode_fields_as::<bulletin::bulletin_runtime::validator_collators::events::CollatorsDrawn>()
                    .transpose()?
                {
                    drawn = Some(format!("{ev:?}"));
                }
            }
            _ => return Err(unsupported(runtime)),
        }
    }
    Ok((new_session, drawn))
}

/// Collators ordered as the aura authorities (session validators).
async fn fetch_collators(
    runtime: SupportedParasRuntime,
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<Vec<(AccountId32, CollatorKind)>, OnetError> {
    let (validators, invulnerables, candidates, drawn) = match runtime {
        SupportedParasRuntime::AssetHubWestend => (
            asset_hub::fetch_session_validators(at).await?,
            asset_hub::fetch_invulnerables(at).await?,
            asset_hub::fetch_candidates(at).await?,
            asset_hub::fetch_drawn_collators(at).await?,
        ),
        SupportedParasRuntime::PeopleWestend => (
            people::fetch_session_validators(at).await?,
            people::fetch_invulnerables(at).await?,
            people::fetch_candidates(at).await?,
            people::fetch_drawn_collators(at).await?,
        ),
        SupportedParasRuntime::BulletinWestend => (
            bulletin::fetch_session_validators(at).await?,
            bulletin::fetch_invulnerables(at).await?,
            bulletin::fetch_candidates(at).await?,
            bulletin::fetch_drawn_collators(at).await?,
        ),
        _ => return Err(unsupported(runtime)),
    };

    Ok(validators
        .into_iter()
        .map(|a| {
            let kind = if invulnerables.contains(&a) {
                CollatorKind::Invulnerable
            } else if drawn.contains(&a) {
                CollatorKind::Validator
            } else if candidates.contains(&a) {
                CollatorKind::Permissionless
            } else {
                warn!("Session validator {a} is not an invulnerable, candidate or drawn collator");
                CollatorKind::Unknown
            };
            (a, kind)
        })
        .collect())
}

/// Aura slot from the pre-runtime digest of the block header.
async fn fetch_aura_slot(rpc: &ParaRpc, hash: H256) -> Result<Option<Slot>, OnetError> {
    if let Some(header) = rpc.chain_get_header(Some(hash)).await? {
        let Digest { logs } = header.digest;
        for digest in logs.iter() {
            if let DigestItem::PreRuntime(engine, data) = digest {
                if engine == b"aura" && data.len() >= 8 {
                    let mut bytes = [0u8; 8];
                    bytes.copy_from_slice(&data[..8]);
                    return Ok(Some(u64::from_le_bytes(bytes)));
                }
            }
        }
    }
    Ok(None)
}
