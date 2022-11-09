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

use crate::api::ws::{
    channel,
    channel::{Channel, Topic},
};
use actix::prelude::*;
use log::info;
use rand::{self, rngs::ThreadRng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Server sends this messages to session
#[derive(Message)]
#[rtype(result = "()")]
pub struct Message(pub String);

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Methods {
    GetBlock,
    SubscribeBlock,
    SubscribeSession,
    SubscribeValidator,
    SubscribeParaAuthoritiesStats,
    SubscribeParaAuthoritiesSummary,
    SubscribeParachains,
    UnsubscribeBlock,
    UnsubscribeSession,
    UnsubscribeValidator,
    UnsubscribeParaAuthoritiesStats,
    UnsubscribeParaAuthoritiesSummary,
    UnsubscribeParachains,
    NotSupported,
}

impl Default for Methods {
    fn default() -> Self {
        Self::NotSupported
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct WsRequestMessage {
    #[serde(default)]
    pub method: Methods,
    #[serde(default)]
    pub params: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WsResponseMessage<T> {
    #[serde(default)]
    pub r#type: String,

    pub result: T,
}

/// `Server` manages chat rooms and responsible for coordinating chat session.
///
/// Implementation is very naïve.
pub struct Server {
    sessions: HashMap<usize, Recipient<Message>>,
    channels: HashMap<Topic, Addr<Channel>>,
    rng: ThreadRng,
}

impl Server {
    pub fn new() -> Server {
        Server {
            sessions: HashMap::new(),
            channels: HashMap::new(),
            rng: rand::thread_rng(),
        }
    }
}

/// Make actor from `Server`
impl Actor for Server {
    /// We are going to use simple Context, we just need ability to communicate
    /// with other actors.
    type Context = Context<Self>;
}

/// New chat session is created
#[derive(Message)]
#[rtype(usize)]
pub struct Connect {
    pub addr: Recipient<Message>,
}

/// Handler for Connect message.
///
/// Register new session and assign unique id to this session
impl Handler<Connect> for Server {
    type Result = usize;

    fn handle(&mut self, msg: Connect, _: &mut Context<Self>) -> Self::Result {
        info!("new session connected");

        // register session with random id
        let id = self.rng.gen::<usize>();
        self.sessions.insert(id, msg.addr);

        // send id back
        id
    }
}

/// Session is disconnected
#[derive(Message)]
#[rtype(result = "()")]
pub struct Disconnect {
    pub id: usize,
}

/// Handler for Disconnect message.
impl Handler<Disconnect> for Server {
    type Result = ();

    fn handle(&mut self, msg: Disconnect, _: &mut Context<Self>) {
        info!("session {} disconnected", msg.id);

        // remove address
        if self.sessions.remove(&msg.id).is_some() {
            // remove session from all channels
            for (_, addr) in &mut self.channels {
                addr.do_send(channel::Unsubscribe { id: msg.id });
            }
        }
    }
}

/// Get channel, if channel does not exists create new one.
#[derive(Message)]
#[rtype(result = "()")]
pub struct Get {
    /// Client ID
    pub id: usize,

    /// Channel topic to fetch data
    pub topic: Topic,
}

/// Get report, remove client from old subscription with the same type
/// send join message to the client
impl Handler<Get> for Server {
    type Result = ();

    fn handle(&mut self, msg: Get, ctx: &mut Context<Self>) {
        let Get { id, topic } = msg;

        if let Some(session_addr) = self.sessions.get(&id) {
            // subscribe to a channel; if doesn't exist yet start a new channel and subscribe to it
            if let Some(channel_addr) = self.channels.get(&topic) {
                channel_addr.do_send(channel::Get {
                    id,
                    addr: session_addr.clone(),
                    topic,
                });
            } else {
                let channel_addr = Channel::new(topic.clone(), ctx.address()).start();
                self.channels
                    .entry(topic.clone())
                    .or_insert(channel_addr.clone());
                channel_addr.do_send(channel::Get {
                    id,
                    addr: session_addr.clone(),
                    topic,
                });
            }
        }
    }
}

/// Subscribe channel, if channel does not exists create new one.
#[derive(Message)]
#[rtype(result = "()")]
pub struct Subscribe {
    /// Client ID
    pub id: usize,

    /// Channel topic to subscribe
    pub topic: Topic,
}

/// Subscribe report, remove client from old subscription with the same type
/// send join message to the client
impl Handler<Subscribe> for Server {
    type Result = ();

    fn handle(&mut self, msg: Subscribe, ctx: &mut Context<Self>) {
        let Subscribe { id, topic } = msg;

        if let Some(session_addr) = self.sessions.get(&id) {
            // subscribe to a channel; if doesn't exist yet start a new channel and subscribe to it
            if let Some(channel_addr) = self.channels.get(&topic) {
                channel_addr.do_send(channel::Subscribe {
                    id,
                    addr: session_addr.clone(),
                    topic,
                });
            } else {
                let channel_addr = Channel::new(topic.clone(), ctx.address()).start();
                self.channels
                    .entry(topic.clone())
                    .or_insert(channel_addr.clone());
                channel_addr.do_send(channel::Subscribe {
                    id,
                    addr: session_addr.clone(),
                    topic,
                });
            }
        }
    }
}

/// Unsubscribe channel
#[derive(Message)]
#[rtype(result = "()")]
pub struct Unsubscribe {
    /// Client ID
    pub id: usize,

    /// Channel topic to unsubscribe
    pub topic: Topic,
}

/// Unsubscribe report, remove client from old subscription with the same type
/// send join message to the client
impl Handler<Unsubscribe> for Server {
    type Result = ();

    fn handle(&mut self, msg: Unsubscribe, _: &mut Context<Self>) {
        let Unsubscribe { id, topic } = msg;

        if self.sessions.get(&id).is_some() {
            // unsubscribe to a channel
            if let Some(channel_addr) = self.channels.get(&topic) {
                channel_addr.do_send(channel::Unsubscribe { id });
            }
        }
    }
}

/// Channel will be soon dropped just remove it from the server
#[derive(Message)]
#[rtype(result = "()")]
pub struct Remove {
    pub topic: Topic,
}

/// Handler for Remove channel from server.
impl Handler<Remove> for Server {
    type Result = ();

    fn handle(&mut self, msg: Remove, _: &mut Context<Self>) {
        // remove address
        if self.channels.remove(&msg.topic).is_some() {
            info!("channel {} removed from server", msg.topic);
        }
    }
}
