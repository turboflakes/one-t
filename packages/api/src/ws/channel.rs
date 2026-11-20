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

use crate::error::ApiError;
use crate::{
    handlers::blocks::get_collation_stats_by_chain,
    handlers::collators::{attach_collation_live, get_collators_result, get_live_slot},
    handlers::sessions::{get_para_current_session, get_para_session_result, get_session_data},
    responses::{
        AuthorityKey, AuthorityKeyCache, BlockResult, BlocksResult, CacheMap, CollatorSlotResult,
        ParachainsResult, SessionResult, ValidatorResult, ValidatorsResult,
    },
    ws::server::{Message, Remove, Server, WsResponseMessage},
};
use actix::prelude::*;
use onet_cache::{
    cache_latest_pushed_block_by_key, cache_latest_pushed_block_v2,
    provider::{get_conn, RedisPool},
    types::{CacheKey, ChainKey, Index, Verbosity},
};
use onet_config::{Config, CONFIG};
use onet_records::{collators::CollatorKind, BlockNumber, EpochIndex, SS58};

use log::{info, warn};
use redis::aio::MultiplexedConnection as Connection;
use std::{
    collections::HashMap,
    str::FromStr,
    time::{Duration, Instant},
};
use subxt::utils::AccountId32;

const BLOCK_INTERVAL: Duration = Duration::from_secs(6);
// a channel interval that takes longer than this is reported, it means the cache is slow
const SLOW_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub enum Topic {
    // number of previous sessions, optionally the only chain to follow (the relay chain if none) and
    // whether the collation stats of asset hub and people are sent with their blocks
    FinalizedBlock(u8, Option<ChainKey>, bool),
    // optionally the only chain to follow, the relay chain if none
    BestBlock(Option<ChainKey>),
    Block(BlockNumber),
    // optionally the parachain of the sessions, the relay chain if none
    NewSession(Option<ChainKey>),
    // current session, pushed at every new finalized block
    CurrentSession(Option<ChainKey>),
    Validator(SS58),
    ParaAuthorities(EpochIndex, Verbosity),
    Parachains(EpochIndex),
    // chain and optionally the only kind of collators to send, with nothing else but the collators
    Collators(ChainKey, Option<CollatorKind>),
    // only the slot the parachain is in, which changes with every block
    CollatorSlot(ChainKey),
}

impl std::fmt::Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FinalizedBlock(previous_sessions, chain_key, stats) => {
                write!(f, "finalized_block:{}", previous_sessions)?;
                if let Some(chain_key) = chain_key {
                    write!(f, ":{}", chain_key)?;
                }
                if *stats {
                    write!(f, ":stats")?;
                }
                Ok(())
            }
            Self::BestBlock(None) => write!(f, "best_block"),
            Self::BestBlock(Some(chain_key)) => write!(f, "best_block:{}", chain_key),
            Self::Block(block_number) => write!(f, "block:{}", block_number),
            Self::NewSession(None) => write!(f, "new_session"),
            Self::NewSession(Some(chain_key)) => write!(f, "new_session:{}", chain_key),
            Self::CurrentSession(None) => write!(f, "current_session"),
            Self::CurrentSession(Some(chain_key)) => write!(f, "current_session:{}", chain_key),
            Self::Validator(account) => write!(f, "v:{}", account),
            Self::ParaAuthorities(index, verbosity) => write!(f, "pas:{}:{}", index, verbosity),
            Self::Parachains(index) => write!(f, "parachains:{}", index),
            Self::Collators(chain_key, None) => write!(f, "collators:{}", chain_key),
            Self::CollatorSlot(chain_key) => write!(f, "collators:{}:slot", chain_key),
            Self::Collators(chain_key, Some(kind)) => {
                write!(f, "collators:{}:{}", chain_key, kind.code())
            }
        }
    }
}

type ClientId = usize;

/// Tell a client something about its subscriptions, e.g. `subscribed to <topic>`
pub(crate) fn send_notification(addr: &Recipient<Message>, text: String) {
    let resp = WsResponseMessage {
        r#type: String::from("notifications"),
        result: text,
    };
    if let Ok(serialized) = serde_json::to_string(&resp) {
        addr.do_send(Message(serialized));
    }
}

/// `Channel` manages topic subscriptions.
///
#[derive(Clone)]
pub struct Channel {
    topic: Topic,
    sessions: HashMap<ClientId, Recipient<Message>>,
    cache: RedisPool,
    server_addr: Addr<Server>,
    // when the interval still being processed started, none if it has finished
    busy_since: Option<Instant>,
}

impl Channel {
    pub fn new(topic: Topic, addr: Addr<Server>, cache: RedisPool) -> Channel {
        Channel {
            topic,
            sessions: HashMap::new(),
            cache,
            server_addr: addr,
            busy_since: None,
        }
    }

    /// Publish message to all subscribers in the channel
    fn publish_message(&self, message: &str, skip_id: usize) {
        for (id, addr) in &self.sessions {
            if *id != skip_id {
                addr.do_send(Message(message.to_owned()));
            }
        }
    }

    fn reply_message(&self, id: usize, message: &str) {
        if let Some(addr) = self.sessions.get(&id) {
            addr.do_send(Message(message.to_owned()));
        }
    }

    /// helper method that fetches data from cache and send it to subscribers at every block rate.
    /// Note: the clients are processed by a spawned future, so the thread is never blocked waiting
    /// for the cache. An interval is skipped if the previous one has not finished.
    fn run(&self, ctx: &mut Context<Self>) {
        ctx.run_interval(BLOCK_INTERVAL, |act, ctx| {
            // stop actor if no registered sessions
            if act.sessions.is_empty() {
                ctx.stop();
                return;
            }
            if let Some(since) = act.busy_since {
                warn!(
                    "channel {} skipped an interval, the previous one is still running after {:?} with {} clients",
                    act.topic,
                    since.elapsed(),
                    act.sessions.len()
                );
                return;
            }
            let started = Instant::now();
            act.busy_since = Some(started);

            // the clients subscribed now, the ones that subscribe later are processed in the next interval
            let channel = act.clone();
            let task = async move {
                let clients = channel.sessions.len();
                for client_id in channel.sessions.keys().copied() {
                    if let Err(e) = Self::process_session_client(
                        &channel.cache,
                        &channel.topic,
                        client_id,
                        &channel,
                    )
                    .await
                    {
                        warn!("Error processing client_id {}: {:?}", client_id, e);
                    }
                }
                let elapsed = started.elapsed();
                if elapsed > SLOW_INTERVAL {
                    warn!(
                        "channel {} took {:?} to process {} clients",
                        channel.topic, elapsed, clients
                    );
                }
            };
            ctx.spawn(task.into_actor(act).map(|_, act, _| act.busy_since = None));
        });
    }

    async fn process_session_client(
        cache: &RedisPool,
        topic: &Topic,
        client_id: ClientId,
        act: &Channel,
    ) -> Result<(), ApiError> {
        let config = CONFIG.clone();
        let mut conn = get_conn(cache).await?;

        match &topic {
            Topic::FinalizedBlock(number_previous_sessions, chain_key, stats) => {
                Self::handle_finalized_blocks(
                    &mut conn,
                    &config,
                    client_id,
                    *number_previous_sessions,
                    chain_key.as_ref(),
                    *stats,
                    act,
                )
                .await?
            }
            Topic::BestBlock(only_chain_key) => {
                Self::handle_best_blocks(&mut conn, &config, client_id, only_chain_key, act).await?
            }
            Topic::NewSession(None) => Self::handle_new_session(&mut conn, act).await?,
            Topic::NewSession(Some(chain_key)) => {
                Self::handle_new_para_session(&mut conn, &config, client_id, chain_key, act).await?
            }
            Topic::CurrentSession(None) => {
                Self::handle_current_session(&mut conn, &config, client_id, act).await?
            }
            Topic::CurrentSession(Some(chain_key)) => {
                Self::handle_current_para_session(&mut conn, &config, client_id, chain_key, act)
                    .await?
            }
            Topic::Validator(account) => {
                Self::handle_validator(&mut conn, client_id, account, act).await?
            }
            Topic::ParaAuthorities(index, verbosity) => {
                Self::handle_para_authorities(&mut conn, client_id, *index, verbosity, act).await?
            }
            Topic::Parachains(index) => {
                Self::handle_parachains(&mut conn, client_id, *index, act).await?
            }
            Topic::CollatorSlot(chain_key) => {
                Self::handle_collator_slot(&mut conn, &config, client_id, chain_key, act).await?
            }
            Topic::Collators(chain_key, kind) => {
                Self::handle_collators(&mut conn, &config, client_id, chain_key, *kind, act).await?
            }
            _ => return Ok(()),
        }
        Ok(())
    }

    async fn handle_finalized_blocks(
        conn: &mut Connection,
        config: &Config,
        client_id: ClientId,
        number_previous_sessions: u8,
        only_chain_key: Option<&ChainKey>,
        with_stats: bool,
        act: &Channel,
    ) -> Result<(), ApiError> {
        // Note: only the relay chain is followed unless a chain is given, so the parachains are explicitly subscribed
        let follows = |chain_key: &ChainKey| match only_chain_key {
            Some(only) => only == chain_key,
            None => *chain_key == ChainKey::RC,
        };

        // Process Relay Chain finalized blocks
        if follows(&ChainKey::RC) {
            Self::process_relay_chain_finalized_blocks(
                conn,
                config,
                client_id,
                number_previous_sessions,
                act,
            )
            .await?;
        }

        // Process Asset Hub and People finalized blocks
        for chain_key in [ChainKey::AH, ChainKey::PEOPLE] {
            if follows(&chain_key) {
                Self::process_parachain_finalized_blocks(
                    conn, config, client_id, chain_key, with_stats, act,
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn process_relay_chain_finalized_blocks(
        conn: &mut Connection,
        config: &Config,
        client_id: ClientId,
        number_previous_sessions: u8,
        act: &Channel,
    ) -> Result<(), ApiError> {
        let chain_key = ChainKey::RC;
        let cache_key = CacheKey::FinalizedBlock(chain_key.clone());
        if let Ok(finalized_block_number) = redis::cmd("GET")
            .arg(CacheKey::FinalizedBlock(chain_key.clone()))
            .query_async::<BlockNumber>(conn)
            .await
        {
            if let Ok(Some(pushed_block_number)) = redis::cmd("GET")
                .arg(CacheKey::PushedBlockByClientIdV2(
                    cache_key.to_string(),
                    client_id,
                ))
                .query_async::<Option<BlockNumber>>(conn)
                .await
            {
                // Note: if latest pushed block is different than the finalized block in the cache
                // just send all finalized blocks not pushed to clients yet.
                if finalized_block_number != pushed_block_number {
                    let mut data: Vec<BlockResult> = Vec::new();

                    let mut latest_block_number_pushed: Option<BlockNumber> =
                        Some(pushed_block_number);

                    while let Some(pushed_block_number) = latest_block_number_pushed {
                        if finalized_block_number == pushed_block_number {
                            latest_block_number_pushed = None;
                        } else {
                            let block_number = pushed_block_number + 1;
                            if let Ok(serialized_data) = redis::cmd("GET")
                                .arg(CacheKey::BlockByIndexStats(Index::Num(block_number)))
                                .query_async::<String>(conn)
                                .await
                            {
                                let mut block_data = CacheMap::new();
                                block_data
                                    .insert(String::from("block_number"), block_number.to_string());
                                block_data.insert(String::from("is_finalized"), (true).to_string());
                                block_data.insert(String::from("stats"), serialized_data);

                                //
                                data.push(block_data.into());
                            }
                            //
                            latest_block_number_pushed = Some(block_number);
                        }
                    }
                    // add blocks from previous sessions
                    for i in 0..number_previous_sessions {
                        let previous_session_block_number = finalized_block_number
                            - (config.blocks_per_session * (i as u32 + 1)) as u64;
                        if let Ok(serialized_data) = redis::cmd("GET")
                            .arg(CacheKey::BlockByIndexStats(Index::Num(
                                previous_session_block_number,
                            )))
                            .query_async::<String>(conn)
                            .await
                        {
                            let mut block_data = CacheMap::new();
                            block_data.insert(
                                String::from("block_number"),
                                previous_session_block_number.to_string(),
                            );
                            block_data.insert(String::from("is_finalized"), (true).to_string());
                            block_data.insert(String::from("stats"), serialized_data);
                            data.push(block_data.into());
                        }
                    }

                    let resp = WsResponseMessage {
                        r#type: String::from("blocks"),
                        result: BlocksResult::from(data),
                    };
                    if let Ok(serialized) = serde_json::to_string(&resp) {
                        act.publish_message(&serialized, 0);
                    }

                    // cache latest pushed block
                    if let Err(e) = cache_latest_pushed_block_v2(
                        conn,
                        config,
                        &client_id,
                        cache_key.clone(),
                        finalized_block_number,
                    )
                    .await
                    {
                        warn!("Cache PushedBlock failed with error: {:?}", e);
                    }
                }
            } else {
                // first time just push to clients the last finalized block
                if let Ok(serialized_data) = redis::cmd("GET")
                    .arg(CacheKey::BlockByIndexStats(Index::Num(
                        finalized_block_number,
                    )))
                    .query_async::<String>(conn)
                    .await
                {
                    let mut block_data = CacheMap::new();
                    block_data.insert(
                        String::from("block_number"),
                        finalized_block_number.to_string(),
                    );
                    block_data.insert(String::from("is_finalized"), (true).to_string());
                    block_data.insert(String::from("stats"), serialized_data);

                    let resp = WsResponseMessage {
                        r#type: String::from("block"),
                        result: BlockResult::from(block_data),
                    };
                    let serialized = serde_json::to_string(&resp).unwrap();
                    act.publish_message(&serialized, 0);

                    // cache latest pushed block
                    if let Err(e) = cache_latest_pushed_block_v2(
                        conn,
                        config,
                        &client_id,
                        cache_key.clone(),
                        finalized_block_number,
                    )
                    .await
                    {
                        warn!("Cache PushedBlock failed with error: {:?}", e);
                    }
                }
            }
        }
        Ok(())
    }

    async fn process_parachain_finalized_blocks(
        conn: &mut Connection,
        config: &Config,
        client_id: ClientId,
        chain_key: ChainKey,
        with_stats: bool,
        act: &Channel,
    ) -> Result<(), ApiError> {
        let cache_key = CacheKey::FinalizedBlock(chain_key.clone());
        // Note: with and without stats are different subscriptions, so each has its own cursor
        let pushed_key = match with_stats {
            true => format!("{}:stats", cache_key),
            false => cache_key.to_string(),
        };
        if let Ok(Some(block_number)) = redis::cmd("GET")
            .arg(CacheKey::FinalizedBlock(chain_key.clone()))
            .query_async::<Option<BlockNumber>>(conn)
            .await
        {
            if let Ok(pushed_block_number) = redis::cmd("GET")
                .arg(CacheKey::PushedBlockByClientIdV2(
                    pushed_key.clone(),
                    client_id,
                ))
                .query_async::<Option<BlockNumber>>(conn)
                .await
            {
                // Note: Check if it has not been sent to client already.
                if Some(block_number) != pushed_block_number {
                    let mut block_data = CacheMap::new();
                    block_data.insert(String::from("chain_key"), chain_key.to_string());
                    block_data.insert(String::from("block_number"), block_number.to_string());
                    block_data.insert(String::from("is_finalized"), (true).to_string());
                    // collation stats of the current parachain session
                    if with_stats {
                        match get_collation_stats_by_chain(conn, &chain_key).await {
                            Ok(Some(stats)) => {
                                block_data.insert(String::from("stats"), stats);
                            }
                            Ok(None) => {}
                            Err(e) => warn!("Collation stats of {chain_key} not available: {e:?}"),
                        }
                    }

                    let resp = WsResponseMessage {
                        r#type: String::from("block"),
                        result: BlockResult::from(block_data),
                    };
                    let serialized = serde_json::to_string(&resp).unwrap();
                    act.publish_message(&serialized, 0);

                    // cache latest pushed block
                    if let Err(e) = cache_latest_pushed_block_by_key(
                        conn,
                        config,
                        &client_id,
                        pushed_key.clone(),
                        block_number,
                    )
                    .await
                    {
                        warn!("Cache PushedBlock failed with error: {:?}", e);
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_best_blocks(
        conn: &mut Connection,
        config: &Config,
        client_id: ClientId,
        only_chain_key: &Option<ChainKey>,
        act: &Channel,
    ) -> Result<(), ApiError> {
        for chain_key in [ChainKey::RC, ChainKey::AH, ChainKey::PEOPLE] {
            // Note: only the relay chain is followed unless a chain is given, so the parachains are explicitly subscribed
            let follows = match only_chain_key {
                Some(only) => *only == chain_key,
                None => chain_key == ChainKey::RC,
            };
            if !follows {
                continue;
            }
            let cache_key = CacheKey::BestBlock(chain_key.clone());
            if let Ok(Some(block_number)) = redis::cmd("GET")
                .arg(CacheKey::BestBlock(chain_key.clone()))
                .query_async::<Option<BlockNumber>>(conn)
                .await
            {
                if let Ok(pushed_block_number) = redis::cmd("GET")
                    .arg(CacheKey::PushedBlockByClientIdV2(
                        cache_key.to_string(),
                        client_id,
                    ))
                    .query_async::<Option<BlockNumber>>(conn)
                    .await
                {
                    // Note: Check if it has not been sent to client already.
                    if Some(block_number) != pushed_block_number {
                        let mut block_data = CacheMap::new();
                        block_data.insert(String::from("chain_key"), chain_key.to_string());
                        block_data.insert(String::from("block_number"), block_number.to_string());
                        block_data.insert(String::from("is_finalized"), "false".to_string());

                        let resp = WsResponseMessage {
                            r#type: String::from("block"),
                            result: BlockResult::from(block_data),
                        };
                        let serialized = serde_json::to_string(&resp).unwrap();
                        act.publish_message(&serialized, 0);

                        // cache latest pushed block
                        if let Err(e) = cache_latest_pushed_block_v2(
                            conn,
                            config,
                            &client_id,
                            cache_key.clone(),
                            block_number,
                        )
                        .await
                        {
                            warn!("Cache PushedBlock failed with error: {:?}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_new_session(conn: &mut Connection, act: &Channel) -> Result<(), ApiError> {
        if let Ok(current) = redis::cmd("GET")
            .arg(CacheKey::SessionByIndex(Index::Str(String::from(
                "current",
            ))))
            .query_async::<EpochIndex>(conn)
            .await
        {
            if let Ok(mut current_data) = redis::cmd("HGETALL")
                .arg(CacheKey::SessionByIndex(Index::Num(current.into())))
                .query_async::<CacheMap>(conn)
                .await
            {
                let zero = "0".to_string();
                let current_block = current_data
                    .get("current_block")
                    .unwrap_or(&zero)
                    .parse::<BlockNumber>()
                    .unwrap_or_default();
                let start_block = current_data
                    .get("start_block")
                    .unwrap_or(&zero)
                    .parse::<BlockNumber>()
                    .unwrap_or_default();
                let diff = current_block - start_block;

                // let's push the current_session to clients every
                // the first 10 blocks of each session
                if diff < 10 {
                    // send previous session (clients might find it useful
                    // since is no longer the current session)
                    if let Ok(mut previous_data) = redis::cmd("HGETALL")
                        .arg(CacheKey::SessionByIndex(Index::Num((current - 1).into())))
                        .query_async::<CacheMap>(conn)
                        .await
                    {
                        // set is_current to false and send previous session
                        previous_data.insert(String::from("is_current"), (false).to_string());
                        let resp = WsResponseMessage {
                            r#type: String::from("session"),
                            result: SessionResult::from(previous_data),
                        };
                        let serialized = serde_json::to_string(&resp).unwrap();
                        act.publish_message(&serialized, 0);
                    }
                    // set is_current to true and send new session
                    current_data.insert(String::from("is_current"), (true).to_string());
                    let resp = WsResponseMessage {
                        r#type: String::from("session"),
                        result: SessionResult::from(current_data),
                    };
                    let serialized = serde_json::to_string(&resp).unwrap();
                    act.publish_message(&serialized, 0);
                }
            }
        }

        Ok(())
    }

    /// Send the current session, when a new relay block was finalized
    async fn handle_current_session(
        conn: &mut Connection,
        config: &Config,
        client_id: ClientId,
        act: &Channel,
    ) -> Result<(), ApiError> {
        let cache_key = CacheKey::SessionByIndex(Index::Current);
        let Some(finalized_block) = redis::cmd("GET")
            .arg(CacheKey::FinalizedBlock(ChainKey::RC))
            .query_async::<Option<BlockNumber>>(conn)
            .await
            .map_err(onet_cache::error::CacheError::RedisCMDError)?
        else {
            return Ok(());
        };
        let pushed_block = redis::cmd("GET")
            .arg(CacheKey::PushedBlockByClientIdV2(
                cache_key.to_string(),
                client_id,
            ))
            .query_async::<Option<BlockNumber>>(conn)
            .await
            .map_err(onet_cache::error::CacheError::RedisCMDError)?;
        // nothing new since the last push to this client
        if pushed_block == Some(finalized_block) {
            return Ok(());
        }
        let Some(session) = redis::cmd("GET")
            .arg(&cache_key)
            .query_async::<Option<EpochIndex>>(conn)
            .await
            .map_err(onet_cache::error::CacheError::RedisCMDError)?
        else {
            return Ok(());
        };

        let (mut data, _) = get_session_data(conn, session, false, false, false).await?;
        data.insert(String::from("is_current"), (true).to_string());
        let result = SessionResult::from(data);
        let resp = WsResponseMessage {
            r#type: String::from("session"),
            result,
        };
        let serialized = serde_json::to_string(&resp).unwrap();
        // Note: only this client is waiting for this block
        act.reply_message(client_id, &serialized);

        if let Err(e) =
            cache_latest_pushed_block_v2(conn, config, &client_id, cache_key, finalized_block).await
        {
            warn!("Cache PushedBlock failed with error: {:?}", e);
        }
        Ok(())
    }

    /// Send the current session of a parachain with its stats and open slot, when a new parachain block was followed
    async fn handle_current_para_session(
        conn: &mut Connection,
        config: &Config,
        client_id: ClientId,
        chain_key: &ChainKey,
        act: &Channel,
    ) -> Result<(), ApiError> {
        // Note: the last block followed is written together with the stats
        let block_key = CacheKey::CollatorLastBlock(chain_key.clone());
        let Some(last_block) = redis::cmd("GET")
            .arg(block_key.to_string())
            .query_async::<Option<BlockNumber>>(conn)
            .await
            .map_err(onet_cache::error::CacheError::RedisCMDError)?
        else {
            return Ok(());
        };
        // Note: collators and sessions of a parachain have their own cursor
        let pushed_key = format!("{}:session", block_key);
        let pushed_block = redis::cmd("GET")
            .arg(CacheKey::PushedBlockByClientIdV2(
                pushed_key.clone(),
                client_id,
            ))
            .query_async::<Option<BlockNumber>>(conn)
            .await
            .map_err(onet_cache::error::CacheError::RedisCMDError)?;
        if pushed_block == Some(last_block) {
            return Ok(());
        }
        let current = get_para_current_session(conn, chain_key).await?;
        let Some(session) = current else {
            return Ok(());
        };
        let Some(result) =
            get_para_session_result(conn, chain_key, session, current, true, true).await?
        else {
            return Ok(());
        };
        let resp = WsResponseMessage {
            r#type: String::from("session"),
            result,
        };
        let serialized = serde_json::to_string(&resp).unwrap();
        // Note: only this client is waiting for this block
        act.reply_message(client_id, &serialized);

        if let Err(e) =
            cache_latest_pushed_block_by_key(conn, config, &client_id, pushed_key, last_block).await
        {
            warn!("Cache PushedBlock failed with error: {:?}", e);
        }
        Ok(())
    }

    /// Send the new session of a parachain, with the previous one that is no longer the current, once for each session.
    /// Note: nothing is sent when the client starts following, only when the session changes after that.
    async fn handle_new_para_session(
        conn: &mut Connection,
        config: &Config,
        client_id: ClientId,
        chain_key: &ChainKey,
        act: &Channel,
    ) -> Result<(), ApiError> {
        let current = get_para_current_session(conn, chain_key).await?;
        let Some(session) = current else {
            return Ok(());
        };
        // Note: the cursor has the last session sent to the client, as the block cursors do
        let pushed_key = format!(
            "{}:new_session",
            CacheKey::CollatorLastBlock(chain_key.clone())
        );
        let pushed_session = redis::cmd("GET")
            .arg(CacheKey::PushedBlockByClientIdV2(
                pushed_key.clone(),
                client_id,
            ))
            .query_async::<Option<EpochIndex>>(conn)
            .await
            .map_err(onet_cache::error::CacheError::RedisCMDError)?;
        if pushed_session == Some(session) {
            return Ok(());
        }
        if pushed_session.is_some() {
            for index in [session.checked_sub(1), Some(session)]
                .iter()
                .flatten()
                .copied()
            {
                if let Some(result) =
                    get_para_session_result(conn, chain_key, index, current, true, false).await?
                {
                    let resp = WsResponseMessage {
                        r#type: String::from("session"),
                        result,
                    };
                    let serialized = serde_json::to_string(&resp).unwrap();
                    act.reply_message(client_id, &serialized);
                }
            }
        }
        if let Err(e) =
            cache_latest_pushed_block_by_key(conn, config, &client_id, pushed_key, session.into())
                .await
        {
            warn!("Cache PushedBlock failed with error: {:?}", e);
        }
        Ok(())
    }

    async fn handle_validator(
        conn: &mut Connection,
        client_id: ClientId,
        account: &SS58,
        act: &Channel,
    ) -> Result<(), ApiError> {
        let cache_key = CacheKey::FinalizedBlock(ChainKey::RC);
        if let Ok(finalized_block_number) = redis::cmd("GET")
            .arg(cache_key.to_string())
            .query_async::<BlockNumber>(conn)
            .await
        {
            if let Ok(pushed_block_number) = redis::cmd("GET")
                .arg(CacheKey::PushedBlockByClientIdV2(
                    cache_key.to_string(),
                    client_id,
                ))
                .query_async::<BlockNumber>(conn)
                .await
            {
                // Note: if latest pushed block equals finalized block in cache
                // just send latest cached data.
                if pushed_block_number == finalized_block_number {
                    if let Ok(current_session) = redis::cmd("GET")
                        .arg(CacheKey::SessionByIndex(Index::Str(String::from(
                            "current",
                        ))))
                        .query_async::<EpochIndex>(conn)
                        .await
                    {
                        if let Ok(data) = redis::cmd("HGETALL")
                            .arg(CacheKey::AuthorityKeyByAccountAndSession(
                                AccountId32::from_str(account).unwrap(),
                                current_session,
                            ))
                            .query_async::<AuthorityKeyCache>(conn)
                            .await
                        {
                            if !data.is_empty() {
                                let key: AuthorityKey = data.into();

                                if let Ok(mut data) = redis::cmd("HGETALL")
                                    .arg(key.to_string())
                                    .query_async::<CacheMap>(conn)
                                    .await
                                {
                                    if let Ok(tmp) = redis::cmd("HGETALL")
                                        .arg(CacheKey::AuthorityRecordVerbose(
                                            key.to_string(),
                                            Verbosity::Stats,
                                        ))
                                        .query_async::<CacheMap>(conn)
                                        .await
                                    {
                                        data.extend(tmp);
                                    }
                                    if let Ok(tmp) = redis::cmd("HGETALL")
                                        .arg(CacheKey::AuthorityRecordVerbose(
                                            key.to_string(),
                                            Verbosity::Summary,
                                        ))
                                        .query_async::<CacheMap>(conn)
                                        .await
                                    {
                                        data.extend(tmp);
                                    }
                                    data.insert(
                                        String::from("session"),
                                        current_session.to_string(),
                                    );
                                    let mut result = ValidatorResult::from(data);
                                    // Note: the slot is not cached, a failure only omits it
                                    if let Err(e) = attach_collation_live(
                                        conn,
                                        std::slice::from_mut(&mut result),
                                    )
                                    .await
                                    {
                                        warn!("Collation live slot not attached: {:?}", e);
                                    }
                                    let resp = WsResponseMessage {
                                        r#type: String::from("validator"),
                                        result,
                                    };
                                    let serialized = serde_json::to_string(&resp).unwrap();
                                    act.publish_message(&serialized, 0);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_para_authorities(
        conn: &mut Connection,
        client_id: ClientId,
        index: EpochIndex,
        verbosity: &Verbosity,
        act: &Channel,
    ) -> Result<(), ApiError> {
        let cache_key = CacheKey::FinalizedBlock(ChainKey::RC);
        if let Ok(finalized_block_number) = redis::cmd("GET")
            .arg(cache_key.to_string())
            .query_async::<BlockNumber>(conn)
            .await
        {
            if let Ok(pushed_block_number) = redis::cmd("GET")
                .arg(CacheKey::PushedBlockByClientIdV2(
                    cache_key.to_string(),
                    client_id,
                ))
                .query_async::<BlockNumber>(conn)
                .await
            {
                // Note: if latest pushed block equals finalized block in cache
                // just send latest cached data.
                if pushed_block_number == finalized_block_number {
                    if let Ok(authority_keys) = redis::cmd("SMEMBERS")
                        .arg(CacheKey::AuthorityKeysBySessionParaOnly(index))
                        .query_async::<Vec<String>>(conn)
                        .await
                    {
                        if !authority_keys.is_empty() {
                            let mut data: Vec<ValidatorResult> = Vec::new();
                            for key in authority_keys.iter() {
                                if let Ok(mut auth) = redis::cmd("HGETALL")
                                    .arg(key)
                                    .query_async::<CacheMap>(conn)
                                    .await
                                {
                                    // Extend with requested verbosity data
                                    if let Ok(tmp) = redis::cmd("HGETALL")
                                        .arg(CacheKey::AuthorityRecordVerbose(
                                            key.to_string(),
                                            verbosity.clone(),
                                        ))
                                        .query_async::<CacheMap>(conn)
                                        .await
                                    {
                                        auth.extend(tmp);
                                    }
                                    // NOTE: discovery data is only updated once very X sessions
                                    // until there is a strong reason to update this data over socket
                                    // it will remain commented out
                                    //
                                    // let attempts = config
                                    //     .discovery_epoch_rate
                                    //     * config.discovery_history_attempts;
                                    // if let Ok(discovery) =
                                    //     get_discovery_data(
                                    //         key,
                                    //         &mut conn,
                                    //         attempts.try_into().unwrap(),
                                    //         None,
                                    //     )
                                    //     .await
                                    // {
                                    //     if !discovery.is_empty() {
                                    //         auth.extend(discovery);
                                    //     }
                                    // }
                                    data.push(auth.into());
                                }
                            }
                            // Note: the slot is not cached, a failure only omits it
                            if let Err(e) = attach_collation_live(conn, &mut data).await {
                                warn!("Collation live slot not attached: {:?}", e);
                            }
                            let resp = WsResponseMessage {
                                r#type: String::from("validators"),
                                result: ValidatorsResult {
                                    session: index,
                                    data,
                                },
                            };
                            let serialized = serde_json::to_string(&resp).unwrap();
                            act.publish_message(&serialized, 0);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Send the collators of the current session of a parachain, when a new block was followed
    async fn handle_collators(
        conn: &mut Connection,
        config: &Config,
        client_id: ClientId,
        chain_key: &ChainKey,
        kind: Option<CollatorKind>,
        act: &Channel,
    ) -> Result<(), ApiError> {
        // Note: the last block followed is written together with the collators
        let cache_key = CacheKey::CollatorLastBlock(chain_key.clone());
        let Some(last_block) = redis::cmd("GET")
            .arg(cache_key.to_string())
            .query_async::<Option<BlockNumber>>(conn)
            .await
            .map_err(onet_cache::error::CacheError::RedisCMDError)?
        else {
            return Ok(());
        };
        // Note: each kind is followed on its own, so it has its own cursor
        let pushed_key = match kind {
            Some(kind) => format!("{}:{}", cache_key, kind.code()),
            None => cache_key.to_string(),
        };
        let pushed_block = redis::cmd("GET")
            .arg(CacheKey::PushedBlockByClientIdV2(
                cache_key.to_string(),
                client_id,
            ))
            .query_async::<Option<BlockNumber>>(conn)
            .await
            .map_err(onet_cache::error::CacheError::RedisCMDError)?;
        // nothing new since the last push to this client
        if pushed_block == Some(last_block) {
            return Ok(());
        }

        // Note: the slot is not sent, it changes with every block and has its own topic.
        // With a kind only the collators of that kind are sent.
        let mut result = get_collators_result(
            conn,
            chain_key,
            &Index::Current,
            kind.is_none(),
            false,
            false,
            false,
        )
        .await?;
        if let Some(kind) = kind {
            result.retain_kind(kind);
        }
        let resp = WsResponseMessage {
            r#type: String::from("collators"),
            result,
        };
        let serialized = serde_json::to_string(&resp).unwrap();
        // Note: only this client is waiting for this block
        act.reply_message(client_id, &serialized);

        if let Err(e) =
            cache_latest_pushed_block_by_key(conn, config, &client_id, pushed_key, last_block).await
        {
            warn!("Cache PushedBlock failed with error: {:?}", e);
        }
        Ok(())
    }

    /// Send the slot a parachain is in, when there is a new parachain block in it
    async fn handle_collator_slot(
        conn: &mut Connection,
        config: &Config,
        client_id: ClientId,
        chain_key: &ChainKey,
        act: &Channel,
    ) -> Result<(), ApiError> {
        let Some(slot) = get_live_slot(conn, chain_key).await? else {
            return Ok(());
        };
        // Note: the session is cached as soon as it changes, regardless of the slots closed
        let Some(session) = get_para_current_session(conn, chain_key).await? else {
            return Ok(());
        };
        // Note: the last parachain block of the slot is the cursor
        let pushed_key = format!("{}:slot", CacheKey::CollatorLiveSlot(chain_key.clone()));
        let pushed_block = redis::cmd("GET")
            .arg(CacheKey::PushedBlockByClientIdV2(
                pushed_key.clone(),
                client_id,
            ))
            .query_async::<Option<BlockNumber>>(conn)
            .await
            .map_err(onet_cache::error::CacheError::RedisCMDError)?;
        if pushed_block == Some(slot.bix) {
            return Ok(());
        }
        let bix = slot.bix;
        let para_id = match chain_key {
            ChainKey::PEOPLE => config.people_para_id,
            _ => config.asset_hub_para_id,
        };
        let resp = WsResponseMessage {
            r#type: String::from("collators"),
            result: CollatorSlotResult {
                chain_key: chain_key.to_string(),
                para_id,
                session,
                slot,
            },
        };
        let serialized = serde_json::to_string(&resp).unwrap();
        act.reply_message(client_id, &serialized);

        if let Err(e) =
            cache_latest_pushed_block_by_key(conn, config, &client_id, pushed_key, bix).await
        {
            warn!("Cache PushedBlock failed with error: {:?}", e);
        }
        Ok(())
    }

    async fn handle_parachains(
        conn: &mut Connection,
        client_id: ClientId,
        index: EpochIndex,
        act: &Channel,
    ) -> Result<(), ApiError> {
        let cache_key = CacheKey::FinalizedBlock(ChainKey::RC);
        if let Ok(finalized_block_number) = redis::cmd("GET")
            .arg(cache_key.to_string())
            .query_async::<BlockNumber>(conn)
            .await
        {
            if let Ok(pushed_block_number) = redis::cmd("GET")
                .arg(CacheKey::PushedBlockByClientIdV2(
                    cache_key.to_string(),
                    client_id,
                ))
                .query_async::<BlockNumber>(conn)
                .await
            {
                // Note: if latest pushed block equals finalized block in cache
                // just send latest cached data.
                if pushed_block_number == finalized_block_number {
                    if let Ok(mut data) = redis::cmd("HGETALL")
                        .arg(CacheKey::ParachainsBySession(index))
                        .query_async::<CacheMap>(conn)
                        .await
                    {
                        if !data.is_empty() {
                            data.insert(String::from("session"), index.to_string());
                            let resp = WsResponseMessage {
                                r#type: String::from("parachains"),
                                result: ParachainsResult::from(data),
                            };
                            let serialized = serde_json::to_string(&resp).unwrap();
                            act.publish_message(&serialized, 0);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Make actor from `Channel`
impl Actor for Channel {
    /// We are going to use simple Context, we just need ability to communicate
    /// with other actors.
    type Context = Context<Self>;

    /// Method is called on actor start.
    fn started(&mut self, ctx: &mut Context<Self>) {
        // start fetching data fro cache at every block rate
        self.run(ctx);
    }

    fn stopping(&mut self, _: &mut Context<Self>) -> Running {
        // notify server
        self.server_addr.do_send(Remove {
            topic: self.topic.clone(),
        });
        Running::Stop
    }
}

/// Get to a topic, if channel for the topic does not exists create new channel.
#[derive(Message)]
#[rtype(result = "()")]
pub struct Get {
    /// Client ID
    pub id: usize,

    /// Client Addr
    pub addr: Recipient<Message>,

    /// Topic
    pub topic: Topic,
}

/// Get to a topic, remove client from old subscription with the same type
/// send successful subscription to the client
impl Handler<Get> for Channel {
    type Result = ();

    fn handle(&mut self, msg: Get, ctx: &mut Context<Self>) {
        let Get { id, addr, topic } = msg;

        info!("channel {} requested by session {}", topic, id);

        // only this client gets the reply
        let reply_to = addr.clone();

        // add session to this channel
        self.sessions.entry(id).or_insert(addr);

        // TODO handle all topics here
        if let Topic::Block(block_number) = &topic {
            let block_number = *block_number;
            let cache = self.cache.clone();
            let future = async move {
                if let Ok(mut conn) = get_conn(&cache).await {
                    if let Ok(serialized_data) = redis::cmd("GET")
                        .arg(CacheKey::BlockByIndexStats(Index::Num(block_number)))
                        .query_async::<String>(&mut conn as &mut Connection)
                        .await
                    {
                        let mut block_data = CacheMap::new();
                        block_data.insert(String::from("block_number"), block_number.to_string());
                        block_data.insert(String::from("is_finalized"), (true).to_string());
                        block_data.insert(String::from("stats"), serialized_data);

                        let resp = WsResponseMessage {
                            r#type: String::from("block"),
                            result: BlockResult::from(block_data),
                        };
                        if let Ok(serialized) = serde_json::to_string(&resp) {
                            reply_to.do_send(Message(serialized));
                        }
                    }
                }
            };
            ctx.spawn(future.into_actor(self));
        }

        // remove address
        if self.sessions.remove(&id).is_some() {
            info!("session {} removed from channel {}", id, topic);
        }
    }
}

/// Subscribe to a topic, if channel for the topic does not exists create new channel.
#[derive(Message)]
#[rtype(result = "()")]
pub struct Subscribe {
    /// Client ID
    pub id: usize,

    /// Client Addr
    pub addr: Recipient<Message>,

    /// Topic
    pub topic: Topic,
}

/// Subscribe to a topic, remove client from old subscription with the same type
/// send successful subscription to the client
impl Handler<Subscribe> for Channel {
    type Result = ();

    fn handle(&mut self, msg: Subscribe, _ctx: &mut Context<Self>) {
        let Subscribe { id, addr, topic } = msg;

        info!("channel {} subscribed by session {}", topic, id);

        // add session to this channel
        self.sessions.entry(id).or_insert(addr);

        // build reply message
        let resp = WsResponseMessage {
            r#type: String::from("notifications"),
            result: format!("subscribed to {}", topic),
        };

        // serialize and send message only to the client
        if let Ok(serialized) = serde_json::to_string(&resp) {
            self.reply_message(id, &serialized);
        }
    }
}

/// Unsubscribe to a topic
#[derive(Message)]
#[rtype(result = "()")]
pub struct Unsubscribe {
    /// Client ID
    pub id: usize,

    /// Where the client is told if it was unsubscribed or not, none if it is not to be told
    /// (the client disconnected)
    pub reply_to: Option<Recipient<Message>>,
}

/// Unsubscribe to a topic, remove client from channel
impl Handler<Unsubscribe> for Channel {
    type Result = ();

    fn handle(&mut self, msg: Unsubscribe, ctx: &mut Context<Self>) {
        let Unsubscribe { id, reply_to } = msg;

        // remove address
        let removed = self.sessions.remove(&id).is_some();
        if let Some(reply_to) = reply_to {
            let text = match removed {
                true => format!("unsubscribed from {}", self.topic),
                false => format!("not subscribed to {}", self.topic),
            };
            send_notification(&reply_to, text);
        }
        if removed {
            info!("session {} unsubscribed from channel {}", id, self.topic);
            // delete unsubscribed clientes from cache
            if let Topic::FinalizedBlock(..) = self.topic {
                let cache = self.cache.clone();
                let future = async move {
                    if let Ok(mut conn) = get_conn(&cache).await {
                        if let Err(e) = redis::cmd("DEL")
                            .arg(CacheKey::PushedBlockByClientId(id))
                            .query_async::<u8>(&mut conn as &mut Connection)
                            .await
                        {
                            warn!(
                                "DEL cache key {} failed with error: {:?}",
                                CacheKey::PushedBlockByClientId(id),
                                e
                            );
                        }
                    }
                };
                ctx.spawn(future.into_actor(self));
            }
        }
    }
}
