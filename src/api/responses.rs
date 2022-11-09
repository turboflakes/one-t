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

use crate::records::{
    AuthorityIndex, AuthorityRecord, BlockNumber, EpochIndex, EraIndex, ParaId, ParaStats,
    ParachainRecord, SessionStats, ValidatorProfileRecord, Validity,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub type AuthorityKeyCache = BTreeMap<String, String>;
pub type CacheMap = BTreeMap<String, String>;

#[derive(Debug, Serialize, PartialEq, Clone)]
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
    // block_number
    #[serde(skip_serializing_if = "BlockNumber::is_empty")]
    block_number: BlockNumber,
    // is_finalized
    #[serde(skip_serializing_if = "default")]
    is_finalized: bool,
    // session stats
    #[serde(skip_serializing_if = "SessionStats::is_empty")]
    stats: SessionStats,
}

impl From<CacheMap> for BlockResult {
    fn from(data: CacheMap) -> Self {
        let zero = "0".to_string();
        let serialized = data.get("stats").unwrap_or(&"{}".to_string()).to_string();
        let stats: SessionStats = serde_json::from_str(&serialized).unwrap_or_default();
        BlockResult {
            block_number: data
                .get("block_number")
                .unwrap_or(&zero)
                .parse::<BlockNumber>()
                .unwrap_or_default(),
            is_finalized: data
                .get("is_finalized")
                .unwrap_or(&zero)
                .parse::<bool>()
                .unwrap_or_default(),
            stats,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BlocksResult {
    pub data: Vec<BlockResult>,
}

impl From<Vec<BlockResult>> for BlocksResult {
    fn from(data: Vec<BlockResult>) -> Self {
        BlocksResult { data }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SessionResult {
    six: EpochIndex,
    eix: EraIndex,
    sbix: BlockNumber,
    ebix: BlockNumber,
    esix: u8,
    #[serde(skip_serializing_if = "default")]
    is_current: bool,
    #[serde(skip_serializing_if = "SessionStats::is_empty")]
    stats: SessionStats,
}

fn default<T: Default + PartialEq>(t: &T) -> bool {
    *t == Default::default()
}

impl From<CacheMap> for SessionResult {
    fn from(data: CacheMap) -> Self {
        let zero = "0".to_string();
        let serialized = data.get("stats").unwrap_or(&"{}".to_string()).to_string();
        let stats: SessionStats = serde_json::from_str(&serialized).unwrap_or_default();
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
            ebix: data
                .get("current_block")
                .unwrap_or(&zero)
                .parse::<BlockNumber>()
                .unwrap_or_default(),
            esix: data
                .get("era_session_index")
                .unwrap_or(&zero)
                .parse::<u8>()
                .unwrap_or_default(),
            is_current: data
                .get("is_current")
                .unwrap_or(&zero)
                .parse::<bool>()
                .unwrap_or_default(),
            stats,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SessionsResult {
    pub data: Vec<SessionResult>,
}

impl From<Vec<SessionResult>> for SessionsResult {
    fn from(data: Vec<SessionResult>) -> Self {
        SessionsResult { data }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ValidatorResult {
    pub address: String,
    #[serde(skip_serializing_if = "ValidatorProfileResult::is_empty")]
    pub profile: ValidatorProfileResult,
    #[serde(skip_serializing_if = "EpochIndex::is_empty")]
    pub session: EpochIndex,
    pub is_auth: bool,
    pub is_para: bool,
    #[serde(skip_serializing_if = "AuthorityRecord::is_empty")]
    pub auth: AuthorityRecord,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub para: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "ParaStats::is_empty")]
    pub para_summary: ParaStats,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub para_stats: BTreeMap<ParaId, ParaStats>,
}

impl From<CacheMap> for ValidatorResult {
    fn from(data: CacheMap) -> Self {
        let zero = "0".to_string();

        let serialized = data.get("auth").unwrap_or(&"{}".to_string()).to_string();
        let auth: AuthorityRecord = serde_json::from_str(&serialized).unwrap_or_default();

        let serialized = data.get("para").unwrap_or(&"{}".to_string()).to_string();
        let para: BTreeMap<String, Value> = serde_json::from_str(&serialized).unwrap();

        // para_summary
        let serialized = data
            .get("para_summary")
            .unwrap_or(&"{}".to_string())
            .to_string();
        let para_summary: ParaStats = serde_json::from_str(&serialized).unwrap_or_default();

        // para_stats
        let serialized = data
            .get("para_stats")
            .unwrap_or(&"{}".to_string())
            .to_string();
        let para_stats: BTreeMap<ParaId, ParaStats> =
            serde_json::from_str(&serialized).unwrap_or_default();

        // profile
        let serialized = data.get("profile").unwrap_or(&"{}".to_string()).to_string();
        let profile: ValidatorProfileResult = serialized.into();

        ValidatorResult {
            is_auth: !auth.is_empty(),
            is_para: !para.is_empty(),
            address: data.get("address").unwrap_or(&"".to_string()).to_string(),
            profile,
            session: data
                .get("session")
                .unwrap_or(&zero)
                .parse::<EpochIndex>()
                .unwrap_or_default(),
            auth,
            para,
            para_summary,
            para_stats,
        }
    }
}

#[derive(Debug, Serialize, Default)]
pub struct ValidatorsResult {
    #[serde(skip_serializing_if = "EpochIndex::is_empty")]
    pub session: EpochIndex,
    pub data: Vec<ValidatorResult>,
}

// Parachains
pub type ParachainResult = ParachainRecord;

impl From<&std::string::String> for ParachainResult {
    fn from(serialized: &std::string::String) -> Self {
        serde_json::from_str(&serialized).unwrap()
    }
}

#[derive(Debug, Serialize)]
pub struct ParachainsResult {
    #[serde(skip_serializing_if = "EpochIndex::is_empty")]
    pub session: EpochIndex,
    pub data: Vec<ParachainResult>,
}

impl From<CacheMap> for ParachainsResult {
    fn from(data: CacheMap) -> Self {
        let zero = "0".to_string();

        let mut out: Vec<ParachainResult> = Vec::new();
        for (para_id, serialized) in data.iter() {
            if para_id == "session" {
                continue;
            }
            out.push(serialized.into());
        }

        ParachainsResult {
            session: data
                .get("session")
                .unwrap_or(&zero)
                .parse::<EpochIndex>()
                .unwrap_or_default(),
            data: out,
        }
    }
}

pub type ValidatorProfileResult = ValidatorProfileRecord;

impl From<String> for ValidatorProfileResult {
    fn from(serialized_data: String) -> Self {
        serde_json::from_str(&serialized_data).unwrap_or_default()
    }
}
