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

use crate::records::{BlockNumber, Identity, Validity};
use codec::{Decode, Encode};
use hex::ToHex;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use subxt::ext::sp_runtime::AccountId32;

pub type PoolId = u32;
pub type PoolCounter = u32;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Pool {
    #[serde(default)]
    pub id: PoolId,
    #[serde(default)]
    pub metadata: String,
    #[serde(default)]
    pub roles: Option<Roles>,
    #[serde(default)]
    pub state: PoolState,
    pub block_number: BlockNumber,
}

impl Pool {
    pub fn with_id(id: PoolId) -> Self {
        Self {
            id,
            ..Default::default()
        }
    }

    pub fn with_id_and_metadata(id: PoolId, metadata: String) -> Self {
        Self {
            id,
            metadata,
            ..Default::default()
        }
    }
}

impl Validity for Pool {
    fn is_empty(&self) -> bool {
        self.block_number == 0
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Roles {
    pub depositor: Account,
    pub root: Option<Account>,
    pub nominator: Option<Account>,
    pub state_toggler: Option<Account>,
}

impl Roles {
    pub fn with(
        depositor: Account,
        root: Option<Account>,
        nominator: Option<Account>,
        state_toggler: Option<Account>,
    ) -> Self {
        Self {
            depositor,
            root,
            nominator,
            state_toggler,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PoolState {
    Open,
    Blocked,
    Destroying,
    NotDefined,
}

impl PoolState {
    pub fn is_not_defined(&self) -> bool {
        match self {
            Self::NotDefined => true,
            _ => false,
        }
    }
}

impl Default for PoolState {
    fn default() -> PoolState {
        PoolState::NotDefined
    }
}

impl std::fmt::Display for PoolState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Blocked => write!(f, "blocked"),
            Self::Destroying => write!(f, "destroying"),
            Self::NotDefined => write!(f, "nd"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Account {
    pub account: AccountId32,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
}

impl Account {
    pub fn with_address(account: AccountId32) -> Self {
        Self {
            account,
            identity: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PoolNominees {
    #[serde(default)]
    pub nominees: Vec<AccountId32>,
    #[serde(default)]
    pub apr: f64,
    #[serde(default)]
    pub active: Vec<ActiveNominee>,
    #[serde(default)]
    pub block_number: BlockNumber,
}

impl PoolNominees {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

impl Validity for PoolNominees {
    fn is_empty(&self) -> bool {
        self.block_number == 0
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PoolNomineesStats {
    #[serde(default)]
    pub nominees: u32,
    #[serde(default)]
    pub apr: f64,
    #[serde(default)]
    pub active: u32,
    #[serde(default)]
    pub block_number: BlockNumber,
}

impl Validity for PoolNomineesStats {
    fn is_empty(&self) -> bool {
        self.block_number == 0
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ActiveNominee {
    pub account: AccountId32,
    #[serde(default)]
    pub value: u128,
}

impl ActiveNominee {
    pub fn with(account: AccountId32, value: u128) -> Self {
        Self { account, value }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PoolStats {
    #[serde(default)]
    pub points: u128,
    #[serde(default)]
    pub member_counter: u32,
    #[serde(default)]
    pub staked: u128,
    #[serde(default)]
    pub reward: u128,
    #[serde(default)]
    pub block_number: BlockNumber,
}

impl PoolStats {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
}

impl Validity for PoolStats {
    fn is_empty(&self) -> bool {
        self.block_number == 0
    }
}

// #[derive(Serialize, Deserialize, Debug, Clone)]
// pub struct PoolNomination {
//     #[serde(default)]
//     pub id: u32,
//     #[serde(default)]
//     pub sessions_counter: u32,
//     #[serde(default)]
//     pub block_number: u32,
//     #[serde(default)]
//     pub extrinsic_hash: H256,
//     #[serde(default)]
//     pub ts: u64,
// }

// impl PoolNomination {
//     pub fn cache(&self) -> Result<(), OnetError> {
//         let config = CONFIG.clone();
//         // Pool cache filename
//         let filename = format!(
//             "{}{}_{}_nomination_{}",
//             config.data_path,
//             POOL_FILENAME,
//             self.id,
//             config.chain_name.to_lowercase()
//         );
//         // Serialize and cache
//         let serialized = serde_json::to_string(&self)?;
//         fs::write(&filename, serialized)?;

//         Ok(())
//     }
// }

/// The type of account being created.
#[derive(Encode, Decode)]
pub enum AccountType {
    Bonded,
    Reward,
}

impl AccountType {
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Self::Bonded => vec![0u8],
            Self::Reward => vec![1u8],
        }
    }
}

impl std::fmt::Display for AccountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bonded => write!(f, "bonded"),
            Self::Reward => write!(f, "reward"),
        }
    }
}

pub fn nomination_pool_account(account_type: AccountType, pool_id: u32) -> AccountId32 {
    // NOTE: nomination pools pallet id could be retrieved
    // from metadata constants nomination_pools.pallet_id()
    let pallet_module = b"modlpy/nopls";
    // concatenate all information
    let mut buffer = Vec::<u8>::new();
    buffer.extend(pallet_module);
    buffer.extend(account_type.as_bytes());
    buffer.extend(pool_id.to_le_bytes());
    buffer.extend(vec![0u8; 15]);
    // convert to hex
    let buffer_hex = buffer.encode_hex::<String>();
    // return account
    return AccountId32::from_str(&buffer_hex).unwrap();
}

#[test]
fn test_pools() {
    assert_eq!(
        nomination_pool_account(AccountType::Reward, 2),
        AccountId32::from_str("13UVJyLnbVp8c4FQeiGUcWddfDNNLSajaPyfpYzx9QbrvLfR").unwrap()
    );
    assert_eq!(
        nomination_pool_account(AccountType::Bonded, 2),
        AccountId32::from_str("13UVJyLnbVp8c4FQeiGCsV63YihAstUrqj3AGcK7gaj8eubS").unwrap()
    );
}
