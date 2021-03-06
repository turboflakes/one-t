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

use crate::records::{AuthorityIndex, BlockNumber, EpochIndex, EraIndex};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub type AuthorityKeyCache = BTreeMap<String, String>;

#[derive(Debug, Serialize, PartialEq)]
pub struct AuthorityKey {
    pub era_index: EraIndex,
    pub epoch_index: EpochIndex,
    pub authority_index: AuthorityIndex,
}

impl From<AuthorityKeyCache> for AuthorityKey {
    fn from(data: AuthorityKeyCache) -> Self {
        let zero = "0".to_string();
        AuthorityKey {
            era_index: data
                .get("era")
                .unwrap_or(&zero)
                .parse::<EraIndex>()
                .unwrap_or_default(),
            epoch_index: data
                .get("session")
                .unwrap_or(&zero)
                .parse::<EpochIndex>()
                .unwrap_or_default(),
            authority_index: data
                .get("authority")
                .unwrap_or(&zero)
                .parse::<AuthorityIndex>()
                .unwrap_or_default(),
        }
    }
}

impl std::fmt::Display for AuthorityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "e:{}:s:{}:a:{}",
            self.era_index, self.epoch_index, self.authority_index
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BlockResult {
    bix: BlockNumber,
}

impl From<BlockNumber> for BlockResult {
    fn from(bix: BlockNumber) -> Self {
        BlockResult { bix }
    }
}

pub type CacheMap = BTreeMap<String, String>;

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionResult {
    six: EpochIndex,
    eix: EraIndex,
    sbix: BlockNumber,
}

impl From<CacheMap> for SessionResult {
    fn from(data: CacheMap) -> Self {
        let zero = "0".to_string();
        SessionResult {
            eix: data
                .get("era")
                .unwrap_or(&zero)
                .parse::<EraIndex>()
                .unwrap_or_default(),
            six: data
                .get("session")
                .unwrap_or(&zero)
                .parse::<EpochIndex>()
                .unwrap_or_default(),
            sbix: data
                .get("start_block")
                .unwrap_or(&zero)
                .parse::<BlockNumber>()
                .unwrap_or_default(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ValidatorResult {
    address: String,
    identity: String,
    session: EpochIndex,
    is_auth: bool,
    is_para: bool,
    auth: BTreeMap<String, Value>,
    para: BTreeMap<String, Value>,
}

impl From<CacheMap> for ValidatorResult {
    fn from(data: CacheMap) -> Self {
        let zero = "0".to_string();
        let serialized = data.get("auth").unwrap_or(&"{}".to_string()).to_string();
        let auth: BTreeMap<String, Value> = serde_json::from_str(&serialized).unwrap();

        let serialized = data.get("para").unwrap_or(&"{}".to_string()).to_string();
        let para: BTreeMap<String, Value> = serde_json::from_str(&serialized).unwrap();

        ValidatorResult {
            is_auth: !auth.is_empty(),
            is_para: !para.is_empty(),
            identity: data.get("identity").unwrap_or(&"".to_string()).to_string(),
            address: data.get("address").unwrap_or(&"".to_string()).to_string(),
            session: data
                .get("session")
                .unwrap_or(&zero)
                .parse::<EpochIndex>()
                .unwrap_or_default(),
            auth,
            para,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ValidatorsResult {
    pub data: Vec<ValidatorResult>,
}

impl From<Vec<ValidatorResult>> for ValidatorsResult {
    fn from(data: Vec<ValidatorResult>) -> Self {
        ValidatorsResult { data }
    }
}
