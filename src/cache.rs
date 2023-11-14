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

use crate::config::{Config, CONFIG};
use crate::errors::CacheError;
use crate::pools::PoolId;
use crate::records::{AuthorityIndex, EpochIndex, EraIndex};

use actix_web::web;
use log::{error, info};
use mobc::{Connection, Pool};
use mobc_redis::RedisConnectionManager;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{thread, time};
use subxt::{ext::sp_core::H256, utils::AccountId32};

pub type RedisPool = Pool<RedisConnectionManager>;
pub type RedisConn = Connection<RedisConnectionManager>;

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

pub type AuthorityRecordKey = String;

#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub enum Verbosity {
    Stats,
    Summary,
}

impl std::fmt::Display for Verbosity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stats => write!(f, "stats"),
            Self::Summary => write!(f, "summary"),
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
pub enum CacheKey {
    Network,
    FinalizedBlock,
    BestBlock,
    PushedBlockByClientId(usize),
    BlockByIndexStats(Index),
    BlocksBySession(Index),
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
    ValidatorProfileByAccount(AccountId32),
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
}

impl std::fmt::Display for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network => write!(f, "network"),
            Self::BestBlock => write!(f, "best"),
            Self::FinalizedBlock => write!(f, "finalized"),
            Self::PushedBlockByClientId(client_id) => write!(f, "pushed:{}", client_id),
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
            Self::ValidatorProfileByAccount(account) => {
                write!(f, "vpa:{}", account)
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
                write!(f, "nb:{}:{:#02x}", session_index, hash)
            }
            Self::NomiBoardEraBySession(session_index) => {
                write!(f, "nb:{}:era", session_index)
            }
            Self::NomiBoardScoresBySessionAndHash(session_index, hash) => {
                write!(f, "nb:{}:{:#02x}:scores", session_index, hash)
            }
            Self::NomiBoardMetaBySessionAndHash(session_index, hash) => {
                write!(f, "nb:{}:{:#02x}:meta", session_index, hash)
            }
            Self::NomiBoardBySessionAndTrait(session_index, attribute) => {
                write!(f, "nb:{}:{}", session_index, attribute)
            }
            Self::NomiBoardStats => {
                write!(f, "nb:stats")
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

fn get_redis_url(config: Config) -> String {
    format!(
        "redis://:{}@{}/{}",
        config.redis_password, config.redis_hostname, config.redis_database
    )
    .to_string()
}

pub fn create_pool(config: Config) -> Result<RedisPool, CacheError> {
    let redis_url = get_redis_url(config.clone());
    let client = redis::Client::open(redis_url).map_err(CacheError::RedisClientError)?;
    let manager = RedisConnectionManager::new(client);
    Ok(Pool::builder()
        .get_timeout(Some(Duration::from_secs(config.redis_pool_timeout_seconds)))
        .max_open(config.redis_pool_max_open)
        .max_idle(config.redis_pool_max_idle)
        .max_lifetime(Some(Duration::from_secs(config.redis_pool_expire_seconds)))
        .build(manager))
}

pub fn create_or_await_pool(config: Config) -> RedisPool {
    loop {
        match create_pool(config.clone()) {
            Ok(pool) => break pool,
            Err(e) => {
                error!("{}", e);
                info!("Awaiting for Redis to be ready");
                thread::sleep(time::Duration::from_secs(6));
            }
        }
    }
}

pub fn add_pool(cfg: &mut web::ServiceConfig) {
    let pool = create_pool(CONFIG.clone()).expect("failed to create Redis pool");
    cfg.app_data(web::Data::new(pool));
}

pub async fn get_conn(pool: &RedisPool) -> Result<RedisConn, CacheError> {
    pool.get().await.map_err(CacheError::RedisPoolError)
}
