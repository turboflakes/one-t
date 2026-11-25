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
use onet_core::error::OnetError;
use std::result::Result;
use subxt::utils::AccountId32;
use subxt::{OnlineClientAtBlock, PolkadotConfig};

#[subxt::subxt(
    runtime_metadata_path = "artifacts/metadata/bulletin_polkadot_metadata.scale",
    derive_for_all_types = "PartialEq, Clone"
)]
pub mod bulletin_runtime {}

use bulletin_runtime::runtime_types::bounded_collections::bounded_vec::BoundedVec;

/// Fetch the parachain session current index, at an already resolved block.
pub async fn fetch_session_current_index(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<u32, OnetError> {
    let addr = bulletin_runtime::storage().session().current_index();

    at.storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .ok_or_else(|| {
            OnetError::from(format!(
                "Session current index not defined at block hash {:?}",
                at.block_hash()
            ))
        })
}

/// Fetch the session validators (ordered as the aura authorities), at an already resolved block.
pub async fn fetch_session_validators(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<Vec<AccountId32>, OnetError> {
    let addr = bulletin_runtime::storage().session().validators();

    Ok(at
        .storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .unwrap_or_default())
}

/// Fetch the invulnerable collators, at an already resolved block.
pub async fn fetch_invulnerables(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<Vec<AccountId32>, OnetError> {
    let addr = bulletin_runtime::storage()
        .collator_selection()
        .invulnerables();

    Ok(at
        .storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .map(|BoundedVec(v)| v)
        .unwrap_or_default())
}

/// Fetch the permissionless collator candidates, at an already resolved block.
pub async fn fetch_candidates(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<Vec<AccountId32>, OnetError> {
    let addr = bulletin_runtime::storage()
        .collator_selection()
        .candidate_list();

    Ok(at
        .storage()
        .try_fetch(addr, ())
        .await?
        .map(|v| v.decode())
        .transpose()?
        .map(|BoundedVec(v)| v.into_iter().map(|c| c.who).collect())
        .unwrap_or_default())
}

/// Fetch the validators drawn to collate, at an already resolved block.
/// Note: the runtime does not have the `ValidatorCollators` pallet yet, so there are no types to
/// read and no validators are drawn. Once it has, update the metadata and read `DrawnCollators`
/// like `onet-bulletin-westend` does.
pub async fn fetch_drawn_collators(
    _at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<Vec<AccountId32>, OnetError> {
    Ok(Vec::new())
}

/// Fetch the aura slot duration in milliseconds, at an already resolved block.
pub fn fetch_aura_slot_duration(
    at: &OnlineClientAtBlock<PolkadotConfig>,
) -> Result<u64, OnetError> {
    at.constants()
        .entry(bulletin_runtime::constants().aura().slot_duration())
        .map_err(|e| OnetError::from(format!("Aura slot duration not available: {e:?}")))
}
