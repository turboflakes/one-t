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

use crate::paseo::{
    relay_runtime,
    relay_runtime::{
        balances::storage::types::total_issuance::TotalIssuance,
        nomination_pools::storage::types::bonded_pools::BondedPools,
        nomination_pools::storage::types::metadata::Metadata as PoolMetadata,
        // historical::events::RootsPruned,
        // para_inclusion::storage::types::v1::V1 as CoreInfo,
        para_inherent::storage::types::on_chain_votes::OnChainVotes,
        para_scheduler::storage::types::validator_groups::ValidatorGroups,
        paras_shared::storage::types::active_validator_indices::ActiveValidatorIndices,
        runtime_types::frame_system::{AccountInfo, LastRuntimeUpgradeInfo},
        runtime_types::pallet_balances::types::AccountData,
        runtime_types::pallet_staking::{ActiveEraInfo, EraRewardPoints, StakingLedger},
        session::events::new_session::SessionIndex,
        session::storage::types::queued_keys::QueuedKeys,
        session::storage::types::validators::Validators as ValidatorSet,
        staking::storage::types::bonded_eras::BondedEras,
        staking::storage::types::eras_total_stake::ErasTotalStake,
        staking::storage::types::nominators::Nominators,
    },
};

use onet_core::error::OnetError;
use onet_records::{EraIndex, Points};
use subxt::{
    utils::{AccountId32, H256},
    OnlineClient, PolkadotConfig,
};

/// Fetch active era at the specified block hash (AH)
pub async fn fetch_active_era_info(
    api: &OnlineClient<PolkadotConfig>,
    rc_block_hash: H256,
) -> Result<ActiveEraInfo, OnetError> {
    let addr = relay_runtime::storage().staking().active_era();

    api.storage()
        .at(rc_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Active era not defined at block hash {rc_block_hash:?}"
            ))
        })
}

/// Fetch first session from active era at the specified block hash (AH)
pub async fn fetch_first_session_from_active_era(
    api: &OnlineClient<PolkadotConfig>,
    rc_block_hash: H256,
) -> Result<u32, OnetError> {
    let active_era = fetch_active_era_info(api, rc_block_hash).await?;
    let bonded_eras = fetch_bonded_eras(api, rc_block_hash).await?;

    for (era_index, session_index) in bonded_eras {
        if era_index == active_era.index {
            return Ok(session_index);
        }
    }
    Err(OnetError::from(format!(
        "First session not found for active era {active_era:?} at block hash {rc_block_hash:?}"
    )))
}

/// Fetch bonded eras at the specified block hash (AH)
pub async fn fetch_bonded_eras(
    api: &OnlineClient<PolkadotConfig>,
    rc_block_hash: H256,
) -> Result<BondedEras, OnetError> {
    let addr = relay_runtime::storage().staking().bonded_eras();

    api.storage()
        .at(rc_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Bonded eras not defined at block hash {rc_block_hash:?}"
            ))
        })
}

/// Fetch eras total stake at the specified block hash (AH)
pub async fn fetch_eras_total_stake(
    api: &OnlineClient<PolkadotConfig>,
    rc_block_hash: H256,
    era: EraIndex,
) -> Result<ErasTotalStake, OnetError> {
    let addr = relay_runtime::storage().staking().eras_total_stake(era);

    api.storage()
        .at(rc_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Eras total stake not defined at block hash {rc_block_hash:?}"
            ))
        })
}

/// Fetch eras validator reward at the specified block hash (AH)
pub async fn fetch_eras_validator_reward(
    api: &OnlineClient<PolkadotConfig>,
    rc_block_hash: H256,
    era: EraIndex,
) -> Result<ErasTotalStake, OnetError> {
    let addr = relay_runtime::storage()
        .staking()
        .eras_validator_reward(era);

    api.storage()
        .at(rc_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Eras validator reward not defined at block hash {rc_block_hash:?} for era {era}"
            ))
        })
}

/// Fetch nominators at the specified block hash
pub async fn fetch_nominators(
    api: &OnlineClient<PolkadotConfig>,
    rc_block_hash: H256,
    stash: AccountId32,
) -> Result<Nominators, OnetError> {
    let addr = relay_runtime::storage().staking().nominators(stash);

    api.storage()
        .at(rc_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Nominators not defined at block hash {rc_block_hash:?}"
            ))
        })
}

/// Fetch last pool ID at the specified block hash
pub async fn fetch_last_pool_id(
    api: &OnlineClient<PolkadotConfig>,
    rc_block_hash: H256,
) -> Result<u32, OnetError> {
    let addr = relay_runtime::storage().nomination_pools().last_pool_id();

    api.storage()
        .at(rc_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::PoolError(format!(
                "Last pool ID not defined at block hash {rc_block_hash:?}"
            ))
        })
}

/// Fetch bonded pools at the specified block hash
pub async fn fetch_bonded_pools(
    api: &OnlineClient<PolkadotConfig>,
    rc_block_hash: H256,
    pool_id: u32,
) -> Result<BondedPools, OnetError> {
    let addr = relay_runtime::storage()
        .nomination_pools()
        .bonded_pools(pool_id);

    api.storage()
        .at(rc_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::PoolError(format!(
                "Bonded Pool ID {pool_id} not defined at block hash {rc_block_hash:?}",
            ))
        })
}

/// Fetch nomination pools metadata at the specified block hash
pub async fn fetch_pool_metadata(
    api: &OnlineClient<PolkadotConfig>,
    rc_block_hash: H256,
    pool_id: u32,
) -> Result<PoolMetadata, OnetError> {
    let addr = relay_runtime::storage()
        .nomination_pools()
        .metadata(pool_id);

    api.storage()
        .at(rc_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::PoolError(format!(
                "PoolMetadata ID {pool_id} not defined at block hash {rc_block_hash:?}",
            ))
        })
}

/// Fetch era reward points at the specified block hash
pub async fn fetch_era_reward_points(
    api: &OnlineClient<PolkadotConfig>,
    rc_block_hash: H256,
    era: EraIndex,
) -> Result<EraRewardPoints<AccountId32>, OnetError> {
    let addr = relay_runtime::storage().staking().eras_reward_points(era);

    api.storage()
        .at(rc_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Era reward points not found at block hash {rc_block_hash:?} and era {era}",
            ))
        })
}

/// Fetch controller bonded account given a stash at the specified block hash
pub async fn fetch_bonded_controller_account(
    api: &OnlineClient<PolkadotConfig>,
    rc_block_hash: H256,
    stash: &AccountId32,
) -> Result<AccountId32, OnetError> {
    let addr = relay_runtime::storage().staking().bonded(stash.clone());

    api.storage()
        .at(rc_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Bonded controller not found at block hash {rc_block_hash:?} and era {stash}"
            ))
        })
}

/// Fetch staking ledger given a stash at the specified block hash
pub async fn fetch_ledger_from_controller(
    api: &OnlineClient<PolkadotConfig>,
    rc_block_hash: H256,
    stash: &AccountId32,
) -> Result<StakingLedger, OnetError> {
    let addr = relay_runtime::storage().staking().ledger(stash.clone());

    api.storage()
        .at(rc_block_hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Bonded controller not found at block hash {rc_block_hash:?}"
            ))
        })
}

/// Fetch the set of authorities (validators) at the specified block hash
pub async fn fetch_authorities(
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
pub async fn fetch_queued_keys(
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
pub async fn fetch_validator_points(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
    stash: AccountId32,
) -> Result<Points, OnetError> {
    let addr = relay_runtime::storage()
        .staking_ah_client()
        .validator_points(stash);

    api.storage()
        .at(hash)
        .fetch(&addr)
        .await?
        .map_or(Ok(0), |points| Ok(points))
}

// Fetch validator points at the specified block hash from era reward points
// Note: this function is deprecated and will be removed in the future
pub async fn fetch_validator_points_from_era_reward_points_deprecated(
    stash: AccountId32,
    era_reward_points: Option<EraRewardPoints<AccountId32>>
) -> Result<Points, OnetError> {

    let points = if let Some(ref erp) = era_reward_points {
        if let Some((_s, points)) =
            erp.individual.iter().find(|(s, _p)| *s == stash)
        {
            *points
        } else {
            0
        }
    } else {
        0
    };

    Ok(points)
}

/// Fetch para validator groups at the specified block hash
pub async fn _fetch_para_validator_groups(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
) -> Result<ValidatorGroups, OnetError> {
    let addr = relay_runtime::storage().para_scheduler().validator_groups();

    api.storage().at(hash).fetch(&addr).await?.ok_or_else(|| {
        OnetError::from(format!("Validator groups not defined at block hash {hash}"))
    })
}

/// Fetch session index at the specified block hash
pub async fn fetch_session_index(
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

/// Fetch account info given a stash at the specified block hash
pub async fn fetch_account_info(
    api: &OnlineClient<PolkadotConfig>,
    hash: H256,
    stash: AccountId32,
) -> Result<AccountInfo<u32, AccountData<u128>>, OnetError> {
    let addr = relay_runtime::storage().system().account(stash);

    api.storage()
        .at(hash)
        .fetch(&addr)
        .await?
        .ok_or_else(|| OnetError::from(format!("Account info not found at block hash {hash}")))
}

/// Fetch total issuance at the specified block hash
pub async fn fetch_total_issuance(
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
pub async fn fetch_validator_groups(
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
pub async fn fetch_validator_indices(
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
pub async fn fetch_on_chain_votes(
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
pub async fn _fetch_last_runtime_upgrade(
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
