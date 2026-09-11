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
use async_recursion::async_recursion;
use log::debug;
use onet_core::error::OnetError;
use onet_records::Identity;
use std::result::Result;
use subxt::utils::AccountId32;
use subxt::{OnlineClientAtBlock, PolkadotConfig};

#[subxt::subxt(
    runtime_metadata_path = "artifacts/metadata/people_kusama_metadata.scale",
    derive_for_all_types = "PartialEq, Clone"
)]
mod people_runtime {}

use people_runtime::identity::storage::{
    identity_of::Output as IdentityOf, super_of::Output as SuperOf,
};
use people_runtime::runtime_types::pallet_identity::types::Data;

pub async fn get_display_name(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    stash: &AccountId32,
) -> Result<String, OnetError> {
    if let Some(identity) = get_identity(at, stash, None).await? {
        Ok(identity.to_string())
    } else {
        let s = &stash.to_string();
        Ok(format!("{}...{}", &s[..6], &s[s.len() - 6..]))
    }
}

/// Fetch the identity for a stash, following `super_of` links up to the parent
/// account when the stash itself has no identity set.
#[async_recursion]
pub async fn get_identity(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    stash: &AccountId32,
    sub_account_name: Option<String>,
) -> Result<Option<Identity>, OnetError> {
    // First, fetch the main identity data
    if let Some(registration) = fetch_identity_of(at, stash).await? {
        debug!("identity {:?}", registration);
        let parent = parse_identity_data(registration.info.display);
        let identity = match sub_account_name {
            Some(child) => Identity::with_name_and_sub(parent, child),
            None => Identity::with_name(parent),
        };
        return Ok(Some(identity));
    }

    // If no main identity, check if this is a sub-account
    if let Some((parent_account, sub_data)) = fetch_super_of(at, stash).await? {
        let sub_account_name = parse_identity_data(sub_data);
        return get_identity(at, &parent_account, Some(sub_account_name.to_string())).await;
    }

    Ok(None)
}

/// Fetch the `identity_of` registration for a stash, at an already resolved block.
async fn fetch_identity_of(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    stash: &AccountId32,
) -> Result<Option<IdentityOf>, OnetError> {
    let addr = people_runtime::storage().identity().identity_of();

    at.storage()
        .try_fetch(addr, (*stash,))
        .await?
        .map(|v| v.decode())
        .transpose()
        .map_err(OnetError::from)
}

/// Fetch the `super_of` entry for a stash, at an already resolved block.
async fn fetch_super_of(
    at: &OnlineClientAtBlock<PolkadotConfig>,
    stash: &AccountId32,
) -> Result<Option<SuperOf>, OnetError> {
    let addr = people_runtime::storage().identity().super_of();

    at.storage()
        .try_fetch(addr, (*stash,))
        .await?
        .map(|v| v.decode())
        .transpose()
        .map_err(OnetError::from)
}

//
fn parse_identity_data(data: Data) -> String {
    match data {
        Data::Raw0(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw1(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw2(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw3(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw4(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw5(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw6(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw7(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw8(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw9(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw10(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw11(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw12(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw13(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw14(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw15(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw16(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw17(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw18(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw19(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw20(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw21(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw22(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw23(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw24(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw25(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw26(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw27(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw28(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw29(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw30(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw31(bytes) => bytes_to_str(bytes.to_vec()),
        Data::Raw32(bytes) => bytes_to_str(bytes.to_vec()),
        _ => "???".to_string(),
    }
}

pub fn bytes_to_str(bytes: Vec<u8>) -> String {
    format!("{}", String::from_utf8_lossy(&bytes))
}
