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

use onet_pools::PoolId;
use onet_prediction::{NominatorStatus, TargetValidators};
use onet_records::{AuthorityIndex, EpochIndex, EraIndex};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use subxt::utils::{AccountId32, H256};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum Index {
    Num(u64),
    Str(String),
    Current,
    Best,
    Finalized,
}

impl std::fmt::Display for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Num(index) => write!(f, "{}", index),
            Self::Str(name) => write!(f, "{}", name),
            Self::Current => write!(f, "current"),
            Self::Best => write!(f, "best"),
            Self::Finalized => write!(f, "finalized"),
        }
    }
}

#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ChainKey {
    #[default]
    RC,
    AH,
    #[serde(rename = "pp")]
    PEOPLE,
    #[serde(rename = "bu")]
    BULLETIN,
}

impl ChainKey {
    /// Parachain id of the chain as configured, none for the relay chain
    pub fn para_id(&self, config: &onet_config::Config) -> Option<u32> {
        match self {
            Self::RC => None,
            Self::AH => Some(config.asset_hub_para_id),
            Self::PEOPLE => Some(config.people_para_id),
            Self::BULLETIN => Some(config.bulletin_para_id),
        }
    }
}

impl std::fmt::Display for ChainKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RC => write!(f, "rc"),
            Self::AH => write!(f, "ah"),
            Self::PEOPLE => write!(f, "pp"),
            Self::BULLETIN => write!(f, "bu"),
        }
    }
}

impl FromStr for ChainKey {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rc" => Ok(ChainKey::RC),
            "ah" => Ok(ChainKey::AH),
            "pp" => Ok(ChainKey::PEOPLE),
            "bu" => Ok(ChainKey::BULLETIN),
            _ => Err(format!("Unknown chain key: {}", s)),
        }
    }
}

pub type AuthorityRecordKey = String;

#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub enum Verbosity {
    Stats,
    Summary,
    Discovery,
}

impl std::fmt::Display for Verbosity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stats => write!(f, "stats"),
            Self::Summary => write!(f, "summary"),
            Self::Discovery => write!(f, "discovery"),
        }
    }
}

pub type QueryString = String;

#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub enum Trait {
    OwnStake,
    NominatorsStake,
    NominatorsCounter,
}

impl std::fmt::Display for Trait {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OwnStake => write!(f, "t:own_stake"),
            Self::NominatorsStake => write!(f, "t:nom_stake"),
            Self::NominatorsCounter => write!(f, "t:nom_counter"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CacheType {
    Session,
    Validator,
    NotImplemented,
}

impl std::fmt::Display for CacheType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session => write!(f, "session"),
            Self::Validator => write!(f, "validator"),
            Self::NotImplemented => write!(f, ""),
        }
    }
}

impl From<&String> for CacheType {
    fn from(data: &String) -> Self {
        match data.as_ref() {
            "session" => CacheType::Session,
            "validator" => CacheType::Validator,
            _ => CacheType::NotImplemented,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CacheKey {
    Network,
    FinalizedBlock(ChainKey),
    BestBlock(ChainKey),
    // TODO: Deprecate PushedBlockByClientId after RC -> AH migration
    PushedBlockByClientId(usize),
    PushedBlockByClientIdV2(String, usize),
    BlockByIndexStats(Index),
    BlocksBySession(Index),
    LastAuthoredBlock(ChainKey),
    EraByIndex(Index),
    SessionByIndex(Index),
    SessionByIndexStats(Index),
    NetworkStatsBySession(Index),
    AuthorityRecord(EraIndex, EpochIndex, AuthorityIndex),
    AuthorityRecordVerbose(AuthorityRecordKey, Verbosity),
    AuthorityKeyByAccountAndSession(AccountId32, EpochIndex),
    AuthorityKeysBySession(EpochIndex),
    AuthorityKeysBySessionParaOnly(EpochIndex),
    ParachainsBySession(EpochIndex),
    ValidatorAccountsBySession(EpochIndex),
    WaitingValidatorAccountsBySession(EpochIndex),
    ValidatorProfileByAccount(AccountId32),
    // Collators (keyed by the parachain and its session, or the relay chain session)
    CollatorRecord(ChainKey, EpochIndex, AccountId32),
    CollatorKeysBySession(ChainKey, EpochIndex),
    CollatorEpochRecord(ChainKey, EpochIndex, AccountId32),
    CollatorKeysByEpoch(ChainKey, EpochIndex),
    CollatorCurrentSession(ChainKey),
    CollatorStatsBySession(ChainKey, EpochIndex),
    CollatorStatsByEpoch(EpochIndex),
    CollatorLastBlock(ChainKey),
    CollatorLiveSlot(ChainKey),
    // Events
    Event(ChainKey, Index),
    // NominationPools
    NominationPoolRecord(PoolId),
    NominationPoolIdsBySession(EpochIndex),
    NominationPoolStatsByPoolAndSession(PoolId, EpochIndex),
    NominationPoolNomineesByPoolAndSession(PoolId, EpochIndex),
    // Queries
    QueryValidators(QueryString),
    QuerySessions(QueryString),
    // Nomi Boards
    NomiBoardBySessionAndHash(EpochIndex, H256),
    NomiBoardEraBySession(EpochIndex),
    NomiBoardScoresBySessionAndHash(EpochIndex, H256),
    NomiBoardMetaBySessionAndHash(EpochIndex, H256),
    NomiBoardBySessionAndTrait(EpochIndex, Trait),
    NomiBoardStats,
    // Predictions (keyed by the number of target validators)
    PredictionIndex,
    PredictionMetaByTarget(TargetValidators),
    PredictionValidatorAccountsByTarget(TargetValidators),
    PredictionValidatorByTargetAndAccount(TargetValidators, AccountId32),
    PredictionValidatorNominatorsByTargetAndAccount(TargetValidators, AccountId32),
    PredictionNominatorAccountsByTarget(TargetValidators),
    PredictionNominatorAccountsByTargetAndStatus(TargetValidators, NominatorStatus),
    PredictionNominatorsMetaByTarget(TargetValidators),
    PredictionNominatorByTargetAndAccount(TargetValidators, AccountId32),
}

impl CacheKey {
    pub fn hash(&self) -> H256 {
        let data = self.to_string();
        let hash = sp_core_hashing::blake2_256(data.as_bytes());
        H256::from(&hash)
    }
}

impl std::fmt::Display for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network => write!(f, "network"),
            Self::BestBlock(chain) => write!(f, "{}:best", chain),
            Self::FinalizedBlock(chain) => write!(f, "{}:finalized", chain),
            Self::PushedBlockByClientId(client_id) => {
                write!(f, "pushed:{}", client_id)
            }
            Self::PushedBlockByClientIdV2(cache_key, client_id) => {
                write!(f, "{}:pushed:{}", cache_key, client_id)
            }
            Self::BlockByIndexStats(block_index) => write!(f, "b:{}:s", block_index),
            Self::BlocksBySession(session_index) => write!(f, "bs:{}", session_index),
            Self::EraByIndex(era_index) => write!(f, "e:{}", era_index),
            Self::SessionByIndex(session_index) => write!(f, "s:{}", session_index),
            Self::SessionByIndexStats(session_index) => write!(f, "s:{}:s", session_index),
            Self::NetworkStatsBySession(session_index) => {
                write!(f, "ns:{}", session_index)
            }
            Self::AuthorityRecord(era_index, session_index, authority_index) => write!(
                f,
                "e:{}:s:{}:a:{}",
                era_index, session_index, authority_index
            ),
            Self::AuthorityRecordVerbose(authority_key, verbosity) => {
                write!(f, "{}:{}", authority_key, verbosity)
            }
            Self::AuthorityKeyByAccountAndSession(account, session_index) => {
                write!(f, "ak:{}:{}", session_index, account)
            }
            Self::AuthorityKeysBySession(session_index) => write!(f, "aks:{}", session_index),
            Self::AuthorityKeysBySessionParaOnly(session_index) => {
                write!(f, "aks:{}:p", session_index)
            }
            Self::ParachainsBySession(session_index) => {
                write!(f, "ps:{}", session_index)
            }
            Self::ValidatorAccountsBySession(session_index) => {
                write!(f, "vas:{}", session_index)
            }
            Self::WaitingValidatorAccountsBySession(session_index) => {
                write!(f, "wvas:{}", session_index)
            }
            Self::ValidatorProfileByAccount(account) => {
                write!(f, "vpa:{}", account)
            }
            Self::CollatorRecord(chain, session_index, account) => {
                write!(f, "col:{}:{}:{}", chain, session_index, account)
            }
            Self::CollatorKeysBySession(chain, session_index) => {
                write!(f, "cks:{}:{}", chain, session_index)
            }
            Self::CollatorEpochRecord(chain, epoch_index, account) => {
                write!(f, "cole:{}:{}:{}", chain, epoch_index, account)
            }
            Self::CollatorKeysByEpoch(chain, epoch_index) => {
                write!(f, "cke:{}:{}", chain, epoch_index)
            }
            Self::CollatorCurrentSession(chain) => write!(f, "cs:{}", chain),
            Self::CollatorStatsBySession(chain, session_index) => {
                write!(f, "css:{}:{}", chain, session_index)
            }
            Self::CollatorStatsByEpoch(epoch_index) => write!(f, "cse:{}", epoch_index),
            Self::CollatorLastBlock(chain) => write!(f, "cl:{}", chain),
            Self::CollatorLiveSlot(chain) => write!(f, "cls:{}", chain),
            Self::LastAuthoredBlock(chain) => write!(f, "lab:{}", chain),
            Self::Event(chain, block_index) => {
                write!(f, "ev:{}:{}", chain, block_index)
            }
            Self::NominationPoolRecord(pool_id) => {
                write!(f, "np:{}", pool_id)
            }
            Self::NominationPoolIdsBySession(session_index) => write!(f, "nps:{}", session_index),
            Self::NominationPoolStatsByPoolAndSession(pool_id, session_index) => {
                write!(f, "nps:{}:{}", session_index, pool_id)
            }
            Self::NominationPoolNomineesByPoolAndSession(pool_id, session_index) => {
                write!(f, "npn:{}:{}", session_index, pool_id)
            }
            //
            Self::QueryValidators(params) => write!(f, "qry:val:{}", params),
            Self::QuerySessions(params) => write!(f, "qry:ses:{}", params),
            //
            Self::NomiBoardBySessionAndHash(session_index, hash) => {
                write!(f, "nb:{}:{:#x}", session_index, hash)
            }
            Self::NomiBoardEraBySession(session_index) => {
                write!(f, "nb:{}:era", session_index)
            }
            Self::NomiBoardScoresBySessionAndHash(session_index, hash) => {
                write!(f, "nb:{}:{:#x}:scores", session_index, hash)
            }
            Self::NomiBoardMetaBySessionAndHash(session_index, hash) => {
                write!(f, "nb:{}:{:#x}:meta", session_index, hash)
            }
            Self::NomiBoardBySessionAndTrait(session_index, attribute) => {
                write!(f, "nb:{}:{}", session_index, attribute)
            }
            Self::NomiBoardStats => {
                write!(f, "nb:stats")
            }
            Self::PredictionIndex => write!(f, "pred:idx"),
            Self::PredictionMetaByTarget(n) => write!(f, "pred:{}:meta", n),
            Self::PredictionValidatorAccountsByTarget(n) => write!(f, "pred:{}:vals", n),
            Self::PredictionValidatorByTargetAndAccount(n, account) => {
                write!(f, "pred:{}:v:{}", n, account)
            }
            Self::PredictionValidatorNominatorsByTargetAndAccount(n, account) => {
                write!(f, "pred:{}:v:{}:noms", n, account)
            }
            Self::PredictionNominatorAccountsByTarget(n) => write!(f, "pred:{}:noms", n),
            Self::PredictionNominatorAccountsByTargetAndStatus(n, status) => {
                write!(f, "pred:{}:noms:{}", n, status)
            }
            Self::PredictionNominatorsMetaByTarget(n) => write!(f, "pred:{}:noms:meta", n),
            Self::PredictionNominatorByTargetAndAccount(n, account) => {
                write!(f, "pred:{}:n:{}", n, account)
            }
        }
    }
}

impl redis::ToRedisArgs for CacheKey {
    fn write_redis_args<W>(&self, out: &mut W)
    where
        W: ?Sized + redis::RedisWrite,
    {
        out.write_arg(self.to_string().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_key_serde_uses_abbreviations() {
        assert_eq!(serde_json::to_string(&ChainKey::PEOPLE).unwrap(), "\"pp\"");
        assert_eq!(
            serde_json::from_str::<ChainKey>("\"pp\"").unwrap(),
            ChainKey::PEOPLE
        );
        assert_eq!(
            serde_json::from_str::<ChainKey>("\"ah\"").unwrap(),
            ChainKey::AH
        );
        assert!(serde_json::from_str::<ChainKey>("\"people\"").is_err());
        assert_eq!(
            serde_json::to_string(&ChainKey::BULLETIN).unwrap(),
            "\"bu\""
        );
        assert_eq!("bu".parse::<ChainKey>(), Ok(ChainKey::BULLETIN));
        assert_eq!(
            CacheKey::BestBlock(ChainKey::BULLETIN).to_string(),
            "bu:best"
        );
    }

    #[test]
    fn chain_key_para_id_is_the_configured_one() {
        let config = onet_config::CONFIG.clone();
        assert_eq!(ChainKey::RC.para_id(&config), None);
        assert_eq!(
            ChainKey::AH.para_id(&config),
            Some(config.asset_hub_para_id)
        );
        assert_eq!(
            ChainKey::PEOPLE.para_id(&config),
            Some(config.people_para_id)
        );
        assert_eq!(
            ChainKey::BULLETIN.para_id(&config),
            Some(config.bulletin_para_id)
        );
    }

    #[test]
    fn collator_cache_keys() {
        let account = AccountId32([0; 32]);
        assert_eq!(ChainKey::PEOPLE.to_string(), "pp");
        assert_eq!("pp".parse::<ChainKey>(), Ok(ChainKey::PEOPLE));
        assert_eq!(
            CacheKey::CollatorRecord(ChainKey::AH, 7, account).to_string(),
            format!("col:ah:7:{}", account)
        );
        assert_eq!(
            CacheKey::CollatorEpochRecord(ChainKey::PEOPLE, 9, account).to_string(),
            format!("cole:pp:9:{}", account)
        );
        assert_eq!(
            CacheKey::CollatorKeysBySession(ChainKey::AH, 7).to_string(),
            "cks:ah:7"
        );
        assert_eq!(
            CacheKey::CollatorKeysByEpoch(ChainKey::AH, 9).to_string(),
            "cke:ah:9"
        );
        assert_eq!(
            CacheKey::CollatorCurrentSession(ChainKey::PEOPLE).to_string(),
            "cs:pp"
        );
        assert_eq!(
            CacheKey::CollatorStatsBySession(ChainKey::PEOPLE, 7).to_string(),
            "css:pp:7"
        );
        assert_eq!(CacheKey::CollatorStatsByEpoch(9).to_string(), "cse:9");
        assert_eq!(
            CacheKey::CollatorLastBlock(ChainKey::AH).to_string(),
            "cl:ah"
        );
        assert_eq!(
            CacheKey::CollatorLiveSlot(ChainKey::PEOPLE).to_string(),
            "cls:pp"
        );
        assert_eq!(
            CacheKey::LastAuthoredBlock(ChainKey::BULLETIN).to_string(),
            "lab:bu"
        );
        assert_eq!(
            CacheKey::LastAuthoredBlock(ChainKey::RC).to_string(),
            "lab:rc"
        );
    }
}
