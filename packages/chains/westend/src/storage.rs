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

use crate::westend::{
    relay_runtime,
    relay_runtime::{
        balances::storage::total_issuance::Output as TotalIssuance,
        para_inherent::storage::on_chain_votes::Output as OnChainVotes,
        para_scheduler::storage::validator_groups::Output as ValidatorGroups,
        paras_shared::storage::active_validator_indices::Output as ActiveValidatorIndices,
        runtime_types::frame_system::{AccountInfo, LastRuntimeUpgradeInfo},
        runtime_types::pallet_balances::types::AccountData,
        session::events::new_session::SessionIndex,
        session::storage::queued_keys::Output as QueuedKeys,
        session::storage::validators::Output as ValidatorSet,
    },
};
use onet_core::error::OnetError;
use onet_records::Points;
use subxt::{utils::AccountId32, OnlineClientAtBlock, PolkadotConfig};

// /// Fetch first session from active era, at an already resolved block.
// pub async fn fetch_first_session_from_active_era(
//     at: &OnlineClientAtBlock<PolkadotConfig>,
//     era_index: u32,
// ) -> Result<u32, OnetError> {
//     let bonded_eras = fetch_bonded_eras(at).await?;
//
//     for (bonded_era_index, session_index) in bonded_eras {
//         if bonded_era_index == era_index {
//             return Ok(session_index);
//         }
//     }
//     Err(OnetError::from(format!(
//         "First session not found for active era {era_index:?} at block hash {:?}",
//         at.block_hash()
//     )))
// }
//
// /// Fetch stash own stake given a stash, at an already resolved block.
// pub async fn fetch_own_stake_via_stash(
//     at: &OnlineClientAtBlock<PolkadotConfig>,
//     stash: &AccountId32,
// ) -> Result<u128, OnetError> {
//     let Ok(staking_ledger) = fetch_ledger_from_controller(at, stash).await else {
//         warn!("Failed to fetch staking_ledger for stash {:?}", stash);
//         return Ok(0);
//     };
//
//     Ok(staking_ledger.active)
// }

/// Fetch the set of authorities (validators), at an already resolved block.
pub async fn fetch_authorities(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<ValidatorSet, OnetError> {
    let addr = relay_runtime::storage().session().validators();

    at.storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Current validators not defined at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch queued_keys, at an already resolved block.
pub async fn fetch_queued_keys(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<QueuedKeys, OnetError> {
    let addr = relay_runtime::storage().session().queued_keys();

    at.storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Queued keys not defined at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch validator points for a stash, at an already resolved block.
pub async fn fetch_validator_points(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    stash: AccountId32,
) -> Result<Points, OnetError> {
    let addr = relay_runtime::storage()
        .staking_ah_client()
        .validator_points();

    let value = at
        .storage()
        .try_fetch(addr, (stash,))
        .await?
        .map(|v| v.decode())
        .transpose()?;

    value.map_or(Ok(0), Ok)
}

/// Fetch para validator groups, at an already resolved block.
pub async fn _fetch_para_validator_groups(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<ValidatorGroups, OnetError> {
    let addr = relay_runtime::storage().para_scheduler().validator_groups();

    at.storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Validator groups not defined at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch session index, at an already resolved block.
pub async fn fetch_session_index(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<SessionIndex, OnetError> {
    let addr = relay_runtime::storage().session().current_index();

    at.storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Current session index not defined at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch account info given a stash, at an already resolved block.
pub async fn fetch_account_info(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    stash: AccountId32,
) -> Result<AccountInfo<u32, AccountData<u128>>, OnetError> {
    let addr = relay_runtime::storage().system().account();

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

/// Fetch total issuance, at an already resolved block.
pub async fn fetch_total_issuance(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<TotalIssuance, OnetError> {
    let addr = relay_runtime::storage().balances().total_issuance();

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

/// Fetch validator groups, at an already resolved block.
pub async fn fetch_validator_groups(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<ValidatorGroups, OnetError> {
    let addr = relay_runtime::storage().para_scheduler().validator_groups();

    at.storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Validator groups not found for block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch validator indices, at an already resolved block.
pub async fn fetch_validator_indices(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<ActiveValidatorIndices, OnetError> {
    let addr = relay_runtime::storage()
        .paras_shared()
        .active_validator_indices();

    at.storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Validator indices not found at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch on chain votes, at an already resolved block.
pub async fn fetch_on_chain_votes(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<OnChainVotes, OnetError> {
    let addr = relay_runtime::storage().para_inherent().on_chain_votes();

    at.storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "On chain votes not found at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch last runtime upgrade info, at an already resolved block.
pub async fn _fetch_last_runtime_upgrade(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<LastRuntimeUpgradeInfo, OnetError> {
    let addr = relay_runtime::storage().system().last_runtime_upgrade();

    at.storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Last runtime upgrade not found at block hash {:?}",
                at.block_hash()
            ))
        })
}
