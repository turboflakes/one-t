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

use crate::api::{
    responses::{
        AuthorityKey, AuthorityKeyCache, BlockResult, CacheMap, SessionResult, ValidatorResult,
    },
    ws::server::{Message, Remove, Server, WsResponseMessage},
};
use crate::cache::{create_or_await_pool, get_conn, CacheKey, Index, RedisPool};
use crate::config::CONFIG;
use crate::records::{BlockNumber, EpochIndex};

use actix::prelude::*;

use futures::executor::block_on;
use log::info;
use redis::aio::Connection;
use std::{collections::HashMap, time::Duration};
use subxt::sp_runtime::AccountId32;

const BLOCK_INTERVAL: Duration = Duration::from_secs(6);

#[derive(Clone, Eq, Hash, PartialEq, Debug)]
pub enum Topic {
    BestBlock,
    CurrentSession,
    Validator(AccountId32),
    ParaAuthorities(EpochIndex),
}

impl std::fmt::Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BestBlock => write!(f, "best_block"),
            Self::CurrentSession => write!(f, "current_session"),
            Self::Validator(account) => write!(f, "v:{}", account),
            Self::ParaAuthorities(index) => write!(f, "pas:{}", index),
        }
    }
}

/// `Channel` manages topic subscriptions.
///
pub struct Channel {
    topic: Topic,
    sessions: HashMap<usize, Recipient<Message>>,
    cache: RedisPool,
    server_addr: Addr<Server>,
}

impl Channel {
    pub fn new(topic: Topic, addr: Addr<Server>) -> Channel {
        Channel {
            topic,
            sessions: HashMap::new(),
            cache: create_or_await_pool(CONFIG.clone()),
            server_addr: addr,
        }
    }
}

impl Channel {
    /// Publish message to all subscribers in the channel
    fn publish_message(&self, message: &str, skip_id: usize) {
        for (id, addr) in &self.sessions {
            if *id != skip_id {
                let _ = addr.do_send(Message(message.to_owned()));
            }
        }
    }

    fn reply_message(&self, id: usize, message: &str) {
        if let Some(addr) = self.sessions.get(&id) {
            let _ = addr.do_send(Message(message.to_owned()));
        }
    }
}

impl Channel {
    /// helper method that fetches data from cache and send it to subscribers at every block rate.
    fn run(&self, ctx: &mut Context<Self>) {
        ctx.run_interval(BLOCK_INTERVAL, |act, ctx| {
            // stop actor if no registered sessions
            if act.sessions.len() == 0 {
                ctx.stop();
                return;
            }

            // TODO handle all topics here
            match &act.topic {
                Topic::BestBlock => {
                    let future = async {
                        if let Ok(mut conn) = get_conn(&act.cache).await {
                            if let Ok(data) = redis::cmd("GET")
                                .arg(CacheKey::BestBlock)
                                .query_async::<Connection, BlockNumber>(&mut conn)
                                .await
                            {
                                let resp = WsResponseMessage {
                                    r#type: String::from("best_block"),
                                    result: BlockResult::from(data),
                                };
                                let serialized = serde_json::to_string(&resp).unwrap();
                                act.publish_message(&serialized, 0);
                            }
                        }
                    };
                    block_on(future);
                }
                Topic::CurrentSession => {
                    let future = async {
                        if let Ok(mut conn) = get_conn(&act.cache).await {
                            if let Ok(data) = redis::cmd("HGETALL")
                                .arg(CacheKey::SessionByIndex(Index::Str(String::from(
                                    "current",
                                ))))
                                .query_async::<Connection, CacheMap>(&mut conn)
                                .await
                            {
                                let resp = WsResponseMessage {
                                    r#type: String::from("session"),
                                    result: SessionResult::from(data),
                                };
                                let serialized = serde_json::to_string(&resp).unwrap();
                                act.publish_message(&serialized, 0);
                            }
                        }
                    };
                    block_on(future);
                }
                Topic::Validator(account) => {
                    let future = async {
                        if let Ok(mut conn) = get_conn(&act.cache).await {
                            if let Ok(current_session) = redis::cmd("HGET")
                                .arg(CacheKey::SessionByIndex(Index::Str(String::from(
                                    "current",
                                ))))
                                .arg("session")
                                .query_async::<Connection, EpochIndex>(&mut conn)
                                .await
                            {
                                if let Ok(data) = redis::cmd("HGETALL")
                                    .arg(CacheKey::AuthorityKeyByAccountAndSession(
                                        account.clone(),
                                        current_session,
                                    ))
                                    .query_async::<Connection, AuthorityKeyCache>(&mut conn)
                                    .await
                                {
                                    if !data.is_empty() {
                                        let authority_key: AuthorityKey = data.into();

                                        if let Ok(data) = redis::cmd("HGETALL")
                                            .arg(authority_key.to_string())
                                            .query_async::<Connection, CacheMap>(&mut conn)
                                            .await
                                        {
                                            let resp = WsResponseMessage {
                                                r#type: String::from("validator"),
                                                result: ValidatorResult::from(data),
                                            };
                                            let serialized = serde_json::to_string(&resp).unwrap();
                                            act.publish_message(&serialized, 0);
                                        }
                                    }
                                }
                            }
                        }
                    };
                    block_on(future);
                }
                Topic::ParaAuthorities(index) => {
                    let future = async {
                        if let Ok(mut conn) = get_conn(&act.cache).await {
                            if let Ok(authority_keys) = redis::cmd("SMEMBERS")
                                .arg(CacheKey::AuthorityKeysBySessionParaOnly(*index))
                                .query_async::<Connection, Vec<String>>(&mut conn)
                                .await
                            {
                                if !authority_keys.is_empty() {
                                    let mut data: Vec<ValidatorResult> = Vec::new();
                                    for key in authority_keys.iter() {
                                        if let Ok(auth) = redis::cmd("HGETALL")
                                            .arg(key)
                                            .query_async::<Connection, CacheMap>(&mut conn)
                                            .await
                                        {
                                            data.push(auth.into());
                                        }
                                    }
                                    let resp = WsResponseMessage {
                                        r#type: String::from("validators"),
                                        result: data,
                                    };
                                    let serialized = serde_json::to_string(&resp).unwrap();
                                    act.publish_message(&serialized, 0);
                                }
                            }
                        }
                    };
                    block_on(future);
                } // _ => (),
            }
        });
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
}

/// Unsubscribe to a topic, remove client from channel
impl Handler<Unsubscribe> for Channel {
    type Result = ();

    fn handle(&mut self, msg: Unsubscribe, _ctx: &mut Context<Self>) {
        let Unsubscribe { id } = msg;

        // remove address
        if self.sessions.remove(&msg.id).is_some() {
            info!("session {} unsubscribed from channel {}", id, self.topic);
        }
    }
}
