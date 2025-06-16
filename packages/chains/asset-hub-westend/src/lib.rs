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
    runtime_metadata_path = "artifacts/metadata/asset_hub_westend_metadata.scale",
    derive_for_all_types = "PartialEq, Clone"
)]
pub mod asset_hub_runtime {}
pub use asset_hub_runtime::{
    nomination_pools::storage::types::bonded_pools::BondedPools,
    nomination_pools::storage::types::metadata::Metadata as PoolMetadata,
    runtime_types::frame_system::AccountInfo,
    runtime_types::pallet_balances::types::AccountData,
    runtime_types::pallet_staking_async::{ledger::StakingLedger, ActiveEraInfo, EraRewardPoints},
    staking::storage::types::eras_total_stake::ErasTotalStake,
    staking::storage::types::nominators::Nominators,
};

use onet_errors::OnetError;
use onet_records::EraIndex;
use subxt::{
    utils::{AccountId32, H256},
    OnlineClient, PolkadotConfig,
};

pub type AssetHubCall = asset_hub_runtime::runtime_types::asset_hub_westend_runtime::RuntimeCall;
pub type NominationPoolsCall =
    asset_hub_runtime::runtime_types::pallet_nomination_pools::pallet::Call;

/// Fetch active era at the specified block hash (AH)
pub async fn fetch_active_era_info(
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
                "Active era not defined at block hash {ah_block_hash:?}"
            ))
        })
}

/// Fetch eras total stake at the specified block hash (AH)
pub async fn fetch_eras_total_stake(
    api: &OnlineClient<PolkadotConfig>,
    ah_block_hash: H256,
    era: EraIndex,
) -> Result<ErasTotalStake, OnetError> {
    let addr = asset_hub_runtime::storage().staking().eras_total_stake(era);

    api.storage()
        .at(ah_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Eras total stake not defined at block hash {ah_block_hash:?}"
            ))
        })
}

/// Fetch eras validator reward at the specified block hash (AH)
pub async fn fetch_eras_validator_reward(
    api: &OnlineClient<PolkadotConfig>,
    ah_block_hash: H256,
    era: EraIndex,
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
                "Eras validator reward not defined at block hash {ah_block_hash:?} for era {era}"
            ))
        })
}

/// Fetch nominators at the specified block hash
pub async fn fetch_nominators(
    api: &OnlineClient<PolkadotConfig>,
    ah_block_hash: H256,
    stash: AccountId32,
) -> Result<Nominators, OnetError> {
    let addr = asset_hub_runtime::storage().staking().nominators(stash);

    api.storage()
        .at(ah_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Nominators not defined at block hash {ah_block_hash:?}"
            ))
        })
}

/// Fetch last pool ID at the specified block hash
pub async fn fetch_last_pool_id(
    api: &OnlineClient<PolkadotConfig>,
    ah_block_hash: H256,
) -> Result<u32, OnetError> {
    let addr = asset_hub_runtime::storage()
        .nomination_pools()
        .last_pool_id();

    api.storage()
        .at(ah_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::PoolError(format!(
                "Last pool ID not defined at block hash {ah_block_hash:?}"
            ))
        })
}

/// Fetch bonded pools at the specified block hash
pub async fn fetch_bonded_pools(
    api: &OnlineClient<PolkadotConfig>,
    ah_block_hash: H256,
    pool_id: u32,
) -> Result<BondedPools, OnetError> {
    let addr = asset_hub_runtime::storage()
        .nomination_pools()
        .bonded_pools(pool_id);

    api.storage()
        .at(ah_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::PoolError(format!(
                "Bonded Pool ID {pool_id} not defined at block hash {ah_block_hash:?}",
            ))
        })
}

/// Fetch nomination pools metadata at the specified block hash
pub async fn fetch_pool_metadata(
    api: &OnlineClient<PolkadotConfig>,
    ah_block_hash: H256,
    pool_id: u32,
) -> Result<PoolMetadata, OnetError> {
    let addr = asset_hub_runtime::storage()
        .nomination_pools()
        .metadata(pool_id);

    api.storage()
        .at(ah_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::PoolError(format!(
                "PoolMetadata ID {pool_id} not defined at block hash {ah_block_hash:?}",
            ))
        })
}

/// Fetch era reward points at the specified block hash
pub async fn fetch_era_reward_points(
    api: &OnlineClient<PolkadotConfig>,
    ah_block_hash: H256,
    era: EraIndex,
) -> Result<EraRewardPoints<AccountId32>, OnetError> {
    let addr = asset_hub_runtime::storage()
        .staking()
        .eras_reward_points(era);

    api.storage()
        .at(ah_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Era reward points not found at block hash {ah_block_hash:?} and era {era}",
            ))
        })
}

/// Fetch controller bonded account given a stash at the specified block hash
pub async fn fetch_bonded_controller_account(
    api: &OnlineClient<PolkadotConfig>,
    ah_block_hash: H256,
    stash: &AccountId32,
) -> Result<AccountId32, OnetError> {
    let addr = asset_hub_runtime::storage().staking().bonded(stash.clone());

    api.storage()
        .at(ah_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Bonded controller not found at block hash {ah_block_hash:?} and era {stash}"
            ))
        })
}

/// Fetch staking ledger given a stash at the specified block hash
pub async fn fetch_ledger_from_controller(
    api: &OnlineClient<PolkadotConfig>,
    ah_block_hash: H256,
    stash: &AccountId32,
) -> Result<StakingLedger, OnetError> {
    let addr = asset_hub_runtime::storage().staking().ledger(stash.clone());

    api.storage()
        .at(ah_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Bonded controller not found at block hash {ah_block_hash:?}"
            ))
        })
}

/// Fetch account info given a stash at the specified block hash
async fn fetch_account_info(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
    stash: AccountId32,
) -> Result<AccountInfo<u32, AccountData<u128>>, OnetError> {
    let addr = asset_hub_runtime::storage().system().account(stash);

    api.storage()
        .at(hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| OnetError::from(format!("Account info not found at block hash {hash}")))
}
