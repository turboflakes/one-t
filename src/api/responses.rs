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
    ParachainRecord, Validity,
};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
pub type AuthorityKeyCache = BTreeMap<String, String>;

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
    ebix: BlockNumber,
    esix: u8,
    is_full: bool,
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
            is_full: data
                .get("is_full")
                .unwrap_or(&zero)
                .parse::<bool>()
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
    #[serde(skip_serializing_if = "String::is_empty")]
    pub identity: String,
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

        let serialized = data
            .get("para_summary")
            .unwrap_or(&"{}".to_string())
            .to_string();

        let para_summary: ParaStats = serde_json::from_str(&serialized).unwrap_or_default();

        let serialized = data
            .get("para_stats")
            .unwrap_or(&"{}".to_string())
            .to_string();
        let para_stats: BTreeMap<ParaId, ParaStats> =
            serde_json::from_str(&serialized).unwrap_or_default();

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

pub type SessionStats = ParaStats;

impl From<Vec<ValidatorResult>> for SessionStats {
    fn from(data: Vec<ValidatorResult>) -> Self {
        let core_assignments: u32 = data
            .iter()
            .filter(|v| v.is_para)
            .map(|v| v.para_summary.core_assignments())
            .reduce(|a, b| a + b)
            .unwrap_or_default();

        let explicit_votes: u32 = data
            .iter()
            .filter(|v| v.is_para)
            .map(|v| v.para_summary.explicit_votes())
            .reduce(|a, b| a + b)
            .unwrap_or_default();

        let implicit_votes: u32 = data
            .iter()
            .filter(|v| v.is_para)
            .map(|v| v.para_summary.implicit_votes())
            .reduce(|a, b| a + b)
            .unwrap_or_default();

        let missed_votes: u32 = data
            .iter()
            .filter(|v| v.is_para)
            .map(|v| v.para_summary.missed_votes())
            .reduce(|a, b| a + b)
            .unwrap_or_default();

        let authored_blocks: u32 = data
            .iter()
            .filter(|v| v.is_auth)
            .map(|v| v.auth.authored_blocks())
            .reduce(|a, b| a + b)
            .unwrap_or_default();

        let points: u32 = data
            .iter()
            .filter(|v| v.is_auth)
            .map(|v| v.auth.points())
            .reduce(|a, b| a + b)
            .unwrap_or_default();

        SessionStats {
            points,
            core_assignments,
            authored_blocks,
            explicit_votes,
            implicit_votes,
            missed_votes,
        }
    }
}
