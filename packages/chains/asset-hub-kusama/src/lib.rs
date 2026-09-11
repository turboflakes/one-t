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

#[subxt::subxt(
    runtime_metadata_path = "artifacts/metadata/asset_hub_kusama_metadata.scale",
    derive_for_all_types = "PartialEq, Clone"
)]
pub mod asset_hub_runtime {}
pub use asset_hub_runtime::{
    balances::storage::total_issuance::Output as TotalIssuance,
    nomination_pools::storage::bonded_pools::Output as BondedPools,
    nomination_pools::storage::metadata::Output as PoolMetadata,
    parachain_system::calls::SetValidationData,
    runtime_types::bounded_collections::bounded_vec::BoundedVec,
    runtime_types::frame_system::AccountInfo,
    runtime_types::pallet_balances::types::AccountData,
    runtime_types::pallet_staking_async::{ledger::StakingLedger, ActiveEraInfo, EraRewardPoints},
    staking::storage::bonded_eras::Output as BondedEras,
    staking::storage::eras_total_stake::Output as ErasTotalStake,
    staking::storage::nominators::Output as Nominators,
};
use log::warn;
use onet_core::error::OnetError;
use onet_records::{EraIndex, Points};
use subxt::{utils::AccountId32, OnlineClientAtBlock, PolkadotConfig};

pub type AssetHubCall = asset_hub_runtime::runtime_types::asset_hub_kusama_runtime::RuntimeCall;
pub type NominationPoolsCall =
    asset_hub_runtime::runtime_types::pallet_nomination_pools::pallet::Call;

/// Fetch active era, at an already resolved block.
pub async fn fetch_active_era_info(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<ActiveEraInfo, OnetError> {
    let addr = asset_hub_runtime::storage().staking().active_era();

    at.storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Active era not defined at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch first session from active era, at an already resolved block.
pub async fn fetch_first_session_from_active_era(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<u32, OnetError> {
    let active_era = fetch_active_era_info(at).await?;
    let BoundedVec(bonded_eras) = fetch_bonded_eras(at).await?;

    for (era_index, session_index) in bonded_eras {
        if era_index == active_era.index {
            return Ok(session_index);
        }
    }
    Err(OnetError::from(format!(
        "First session not found for active era {active_era:?} at block hash {:?}",
        at.block_hash()
    )))
}

/// Fetch bonded eras, at an already resolved block.
pub async fn fetch_bonded_eras(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<BondedEras, OnetError> {
    let addr = asset_hub_runtime::storage().staking().bonded_eras();

    at.storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Bonded eras not defined at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch eras total stake for an era, at an already resolved block.
pub async fn fetch_eras_total_stake(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    era: EraIndex,
) -> Result<ErasTotalStake, OnetError> {
    let addr = asset_hub_runtime::storage().staking().eras_total_stake();

    at.storage()
        .try_fetch(addr, (era,))
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Eras total stake not defined at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch eras validator reward for an era, at an already resolved block.
pub async fn fetch_eras_validator_reward(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    era: EraIndex,
) -> Result<ErasTotalStake, OnetError> {
    let addr = asset_hub_runtime::storage()
        .staking()
        .eras_validator_reward();

    at.storage()
        .try_fetch(addr, (era,))
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Eras validator reward not defined at block hash {:?} for era {era}",
                at.block_hash()
            ))
        })
}

/// Fetch nominators for a stash, at an already resolved block.
pub async fn fetch_nominators(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    stash: AccountId32,
) -> Result<Nominators, OnetError> {
    let addr = asset_hub_runtime::storage().staking().nominators();

    at.storage()
        .try_fetch(addr, (stash,))
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Nominators not defined at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch last pool ID, at an already resolved block.
pub async fn fetch_last_pool_id(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<u32, OnetError> {
    let addr = asset_hub_runtime::storage()
        .nomination_pools()
        .last_pool_id();

    at.storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::PoolError(format!(
                "Last pool ID not defined at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch bonded pools for a pool ID, at an already resolved block.
pub async fn fetch_bonded_pools(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    pool_id: u32,
) -> Result<BondedPools, OnetError> {
    let addr = asset_hub_runtime::storage()
        .nomination_pools()
        .bonded_pools();

    at.storage()
        .try_fetch(addr, (pool_id,))
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::PoolError(format!(
                "Bonded Pool ID {pool_id} not defined at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch nomination pools metadata for a pool ID, at an already resolved block.
pub async fn fetch_pool_metadata(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    pool_id: u32,
) -> Result<PoolMetadata, OnetError> {
    let addr = asset_hub_runtime::storage().nomination_pools().metadata();

    at.storage()
        .try_fetch(addr, (pool_id,))
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::PoolError(format!(
                "PoolMetadata ID {pool_id} not defined at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch era reward points for an era, at an already resolved block.
pub async fn fetch_era_reward_points(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    era: EraIndex,
) -> Result<Option<EraRewardPoints>, OnetError> {
    let addr = asset_hub_runtime::storage().staking().eras_reward_points();

    at.storage()
        .try_fetch(addr, (era,))
        .await?
        .map(|v| v.decode())
        .transpose()
        .map_err(|e| e.into())
}

/// Fetch controller bonded account given a stash, at an already resolved block.
///
/// Note: takes a pre-resolved `at` client rather than an `(api, hash)` pair so that
/// callers iterating over many stashes at the same block only pay the `at_block`
/// RPC round-trip once, instead of once per stash.
pub async fn fetch_bonded_controller_account(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    stash: &AccountId32,
) -> Result<AccountId32, OnetError> {
    let addr = asset_hub_runtime::storage().staking().bonded();

    at.storage()
        .try_fetch(addr, (*stash,))
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Bonded controller not found at block hash {:?} and era {stash}",
                at.block_hash()
            ))
        })
}

/// Fetch staking ledger given a stash, at an already resolved block.
pub async fn fetch_ledger_from_controller(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    stash: &AccountId32,
) -> Result<StakingLedger, OnetError> {
    let addr = asset_hub_runtime::storage().staking().ledger();

    at.storage()
        .try_fetch(addr, (*stash,))
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Bonded controller not found at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch stash own stake given a stash, at an already resolved block.
pub async fn fetch_own_stake_via_stash(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    stash: &AccountId32,
) -> Result<u128, OnetError> {
    let Ok(staking_ledger) = fetch_ledger_from_controller(at, stash).await else {
        warn!("Failed to fetch staking_ledger for stash {:?}", stash);
        return Ok(0);
    };

    Ok(staking_ledger.active)
}

/// Fetch account info given a stash at the specified block hash
pub async fn fetch_account_info(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    stash: AccountId32,
) -> Result<AccountInfo<u32, AccountData<u128>>, OnetError> {
    let addr = asset_hub_runtime::storage().system().account();

    at.storage()
        .try_fetch(addr, (stash,))
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Account info not found at block hash {:?}",
                at.block_hash()
            ))
        })
}

// Fetch validator points at the specified block hash from era reward points
// Note: this function is deprecated and will be removed in the future
pub async fn fetch_validator_points_from_era_reward_points_deprecated(
    stash: AccountId32,
    era_reward_points: Option<EraRewardPoints>,
) -> Result<Points, OnetError> {
    let points = if let Some(ref erp) = era_reward_points {
        if let Some((_s, points)) = erp.individual.0.iter().find(|(s, _p)| *s == stash) {
            *points
        } else {
            0
        }
    } else {
        0
    };

    Ok(points)
}

/// Fetch total issuance, at an already resolved block.
pub async fn fetch_total_issuance(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<TotalIssuance, OnetError> {
    let addr = asset_hub_runtime::storage().balances().total_issuance();

    at.storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Total issuance not found at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch the RC parent block number from the persisted validation data in the AH block,
/// at an already resolved block.
pub async fn fetch_relay_parent_block_number(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<u64, OnetError> {
    let extrinsics = at.extrinsics().fetch().await?;
    if let Some(res) = extrinsics.find::<SetValidationData>().next() {
        let extrinsic = res?;
        return Ok(extrinsic.data.validation_data.relay_parent_number as u64);
    }

    Err(OnetError::RelayParentNumber(at.block_hash()))
}
