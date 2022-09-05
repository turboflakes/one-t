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
use crate::records::{AuthorityIndex, EpochIndex, EraIndex};

use actix_web::web;
use log::{error, info};
use mobc::{Connection, Pool};
use mobc_redis::RedisConnectionManager;
use serde::Deserialize;
use std::time::Duration;
use std::{thread, time};
use subxt::sp_runtime::AccountId32;

const CACHE_POOL_MAX_OPEN: u64 = 20;
const CACHE_POOL_MAX_IDLE: u64 = 8;
const CACHE_POOL_TIMEOUT_SECONDS: u64 = 30;
const CACHE_POOL_EXPIRE_SECONDS: u64 = 60;

pub type RedisPool = Pool<RedisConnectionManager>;
pub type RedisConn = Connection<RedisConnectionManager>;

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum Index {
    Num(u32),
    Str(String),
    Current,
}

impl std::fmt::Display for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Num(index) => write!(f, "{}", index),
            Self::Str(name) => write!(f, "{}", name),
            Self::Current => write!(f, "current"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CacheKey {
    Network,
    BestBlock,
    SessionByIndex(Index),
    AuthorityRecord(EraIndex, EpochIndex, AuthorityIndex),
    AuthorityKeyByAccountAndSession(AccountId32, EpochIndex),
    AuthorityKeysBySession(EpochIndex),
    AuthorityKeysBySessionParaOnly(EpochIndex),
}

impl std::fmt::Display for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network => write!(f, "network"),
            Self::BestBlock => write!(f, "best"),
            Self::SessionByIndex(index) => write!(f, "s:{}", index),
            Self::AuthorityRecord(era_index, session_index, authority_index) => write!(
                f,
                "e:{}:s:{}:a:{}",
                era_index, session_index, authority_index
            ),
            Self::AuthorityKeyByAccountAndSession(account, session) => {
                write!(f, "akas:{}:{}", account, session)
            }
            Self::AuthorityKeysBySession(session_index) => write!(f, "aks:{}", session_index),
            Self::AuthorityKeysBySessionParaOnly(session_index) => {
                write!(f, "aks:{}:p", session_index)
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
    let redis_url = get_redis_url(config);
    let client = redis::Client::open(redis_url).map_err(CacheError::RedisClientError)?;
    let manager = RedisConnectionManager::new(client);
    Ok(Pool::builder()
        .get_timeout(Some(Duration::from_secs(CACHE_POOL_TIMEOUT_SECONDS)))
        .max_open(CACHE_POOL_MAX_OPEN)
        .max_idle(CACHE_POOL_MAX_IDLE)
        .max_lifetime(Some(Duration::from_secs(CACHE_POOL_EXPIRE_SECONDS)))
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
