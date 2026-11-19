use std::{
    str::FromStr,
    time::{Duration, Instant},
};

use crate::ws::{
    channel::Topic,
    server,
    server::{Methods, WsRequestMessage},
};
use actix::prelude::*;
use actix_web_actors::ws;
use log::{debug, warn};
use onet_cache::types::{ChainKey, Verbosity};
use onet_records::{BlockNumber, EpochIndex};
use subxt::utils::AccountId32;

/// How often heartbeat pings are sent
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// How long before lack of client response causes a timeout
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct WsSession {
    /// unique session id
    pub id: usize,

    /// Client must send ping at least once per 10 seconds (CLIENT_TIMEOUT),
    /// otherwise we drop connection.
    pub hb: Instant,

    /// peer name
    pub name: Option<String>,

    /// server
    pub server_addr: Addr<server::Server>,
}

impl WsSession {
    /// helper method that sends ping to client every second.
    ///
    /// also this method checks heartbeats from client
    fn hb(&self, ctx: &mut ws::WebsocketContext<Self>) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            // check client heartbeats
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                // heartbeat timed out
                println!("Websocket Client heartbeat failed, disconnecting!");

                // notify server
                act.server_addr.do_send(server::Disconnect { id: act.id });

                // stop actor
                ctx.stop();

                // don't try to send a ping
                return;
            }

            ctx.ping(b"");
        });
    }
}

impl Actor for WsSession {
    type Context = ws::WebsocketContext<Self>;

    /// Method is called on actor start.
    /// We register ws session with ChatServer
    fn started(&mut self, ctx: &mut Self::Context) {
        // we'll start heartbeat process on session start.
        self.hb(ctx);

        // register self in server. `AsyncContext::wait` register
        // future within context, but context waits until this future resolves
        // before processing any other events.
        // HttpContext::state() is instance of WsSession, state is shared
        // across all routes within application
        let addr = ctx.address();
        self.server_addr
            .send(server::Connect {
                addr: addr.recipient(),
            })
            .into_actor(self)
            .then(|res, act, ctx| {
                match res {
                    Ok(res) => act.id = res,
                    // something is wrong with server
                    _ => ctx.stop(),
                }
                fut::ready(())
            })
            .wait(ctx);
    }

    fn stopping(&mut self, _: &mut Self::Context) -> Running {
        // notify server
        self.server_addr.do_send(server::Disconnect { id: self.id });
        Running::Stop
    }
}

/// Handle messages from server, we simply send it to peer websocket
impl Handler<server::Message> for WsSession {
    type Result = ();

    fn handle(&mut self, msg: server::Message, ctx: &mut Self::Context) {
        ctx.text(msg.0);
    }
}

/// WebSocket message handler
impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for WsSession {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        let msg = match msg {
            Err(_) => {
                ctx.stop();
                return;
            }
            Ok(msg) => msg,
        };

        debug!("WEBSOCKET MESSAGE: {msg:?}");
        match msg {
            ws::Message::Ping(msg) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            ws::Message::Pong(_) => {
                self.hb = Instant::now();
            }
            ws::Message::Text(text) => {
                let m = text.trim();
                // check for message with the following format
                // { method: "subscribe_validator", params: ["stash_address"] }

                let req: WsRequestMessage = serde_json::from_str(m).unwrap_or_default();
                // TODO handle all methods
                match req.method {
                    Methods::GetBlock => {
                        for block_number_str in req.params.iter() {
                            if let Ok(block_number) = block_number_str.parse::<BlockNumber>() {
                                self.server_addr.do_send(server::Get {
                                    id: self.id,
                                    topic: Topic::Block(block_number),
                                })
                            }
                        }
                    }
                    Methods::SubscribeBlock => match req.params[0].as_str() {
                        "best" => self.server_addr.do_send(server::Subscribe {
                            id: self.id,
                            topic: best_topic(&req.params),
                        }),
                        "finalized" => self.server_addr.do_send(server::Subscribe {
                            id: self.id,
                            topic: finalized_topic(&req.params),
                        }),
                        _ => (),
                    },
                    Methods::SubscribeSession => {
                        // "new" at the start of every session, "current" at every new finalized block
                        match req.params.first().map(|p| p.as_str()) {
                            Some("new") => self.server_addr.do_send(server::Subscribe {
                                id: self.id,
                                topic: Topic::NewSession,
                            }),
                            Some("current") => self.server_addr.do_send(server::Subscribe {
                                id: self.id,
                                topic: Topic::CurrentSession,
                            }),
                            _ => (),
                        }
                    }
                    Methods::SubscribeValidator => {
                        for stash in req.params.iter() {
                            if AccountId32::from_str(stash).is_ok() {
                                self.server_addr.do_send(server::Subscribe {
                                    id: self.id,
                                    topic: Topic::Validator(stash.to_string()),
                                });
                            }
                        }
                    }
                    Methods::SubscribeParaAuthoritiesSummary => {
                        for index in req.params.iter() {
                            if let Ok(index) = &index.parse::<EpochIndex>() {
                                self.server_addr.do_send(server::Subscribe {
                                    id: self.id,
                                    topic: Topic::ParaAuthorities(*index, Verbosity::Summary),
                                });
                            }
                        }
                    }
                    Methods::SubscribeParaAuthoritiesStats => {
                        for index in req.params.iter() {
                            if let Ok(index) = &index.parse::<EpochIndex>() {
                                self.server_addr.do_send(server::Subscribe {
                                    id: self.id,
                                    topic: Topic::ParaAuthorities(*index, Verbosity::Stats),
                                });
                            }
                        }
                    }
                    Methods::SubscribeParachains => {
                        for index in req.params.iter() {
                            if let Ok(index) = &index.parse::<EpochIndex>() {
                                self.server_addr.do_send(server::Subscribe {
                                    id: self.id,
                                    topic: Topic::Parachains(*index),
                                });
                            }
                        }
                    }
                    Methods::SubscribeCollators => {
                        for chain_key in req.params.iter() {
                            if let Ok(chain_key @ (ChainKey::AH | ChainKey::PEOPLE)) =
                                ChainKey::from_str(chain_key)
                            {
                                self.server_addr.do_send(server::Subscribe {
                                    id: self.id,
                                    topic: Topic::Collators(chain_key),
                                });
                            }
                        }
                    }
                    Methods::UnsubscribeBlock => match req.params[0].as_str() {
                        "best" => self.server_addr.do_send(server::Unsubscribe {
                            id: self.id,
                            topic: best_topic(&req.params),
                        }),
                        "finalized" => self.server_addr.do_send(server::Unsubscribe {
                            id: self.id,
                            topic: finalized_topic(&req.params),
                        }),
                        _ => (),
                    },
                    Methods::UnsubscribeSession => {
                        // "new" at the start of every session, "current" at every new finalized block
                        match req.params.first().map(|p| p.as_str()) {
                            Some("new") => self.server_addr.do_send(server::Unsubscribe {
                                id: self.id,
                                topic: Topic::NewSession,
                            }),
                            Some("current") => self.server_addr.do_send(server::Unsubscribe {
                                id: self.id,
                                topic: Topic::CurrentSession,
                            }),
                            _ => (),
                        }
                    }
                    Methods::UnsubscribeValidator => {
                        for stash in req.params.iter() {
                            if AccountId32::from_str(stash).is_ok() {
                                self.server_addr.do_send(server::Unsubscribe {
                                    id: self.id,
                                    topic: Topic::Validator(stash.to_string()),
                                });
                            }
                        }
                    }
                    Methods::UnsubscribeParaAuthoritiesSummary => {
                        for index in req.params.iter() {
                            if let Ok(index) = &index.parse::<EpochIndex>() {
                                self.server_addr.do_send(server::Unsubscribe {
                                    id: self.id,
                                    topic: Topic::ParaAuthorities(*index, Verbosity::Summary),
                                });
                            }
                        }
                    }
                    Methods::UnsubscribeParaAuthoritiesStats => {
                        for index in req.params.iter() {
                            if let Ok(index) = &index.parse::<EpochIndex>() {
                                self.server_addr.do_send(server::Unsubscribe {
                                    id: self.id,
                                    topic: Topic::ParaAuthorities(*index, Verbosity::Stats),
                                });
                            }
                        }
                    }
                    Methods::UnsubscribeParachains => {
                        for index in req.params.iter() {
                            if let Ok(index) = &index.parse::<EpochIndex>() {
                                self.server_addr.do_send(server::Unsubscribe {
                                    id: self.id,
                                    topic: Topic::Parachains(*index),
                                });
                            }
                        }
                    }
                    Methods::UnsubscribeCollators => {
                        for chain_key in req.params.iter() {
                            if let Ok(chain_key) = ChainKey::from_str(chain_key) {
                                self.server_addr.do_send(server::Unsubscribe {
                                    id: self.id,
                                    topic: Topic::Collators(chain_key),
                                });
                            }
                        }
                    }
                    _ => warn!("Not Implemented: {:?}", req),
                }
            }
            ws::Message::Binary(_) => println!("Unexpected binary"),
            ws::Message::Close(reason) => {
                ctx.close(reason);
                ctx.stop();
            }
            ws::Message::Continuation(_) => {
                ctx.stop();
            }
            ws::Message::Nop => (),
        }
    }
}

/// Topic of the best blocks from the params `["best", previous_sessions, chain_key]`.
/// Note: `previous_sessions` is not used by best blocks, it is kept so the params
/// are the same as the finalized ones. If `chain_key` is not given, all chains are followed.
fn best_topic(params: &[String]) -> Topic {
    Topic::BestBlock(params.get(2).and_then(|c| ChainKey::from_str(c).ok()))
}

/// Topic of the finalized blocks from the params `["finalized", previous_sessions, chain_key]`.
/// Note: `previous_sessions` is 0 if not valid and, if `chain_key` is not given, all chains are followed.
fn finalized_topic(params: &[String]) -> Topic {
    let previous_sessions = params
        .get(1)
        .and_then(|p| p.parse::<u8>().ok())
        .unwrap_or_default();
    let chain_key = params.get(2).and_then(|c| ChainKey::from_str(c).ok());
    Topic::FinalizedBlock(previous_sessions, chain_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(p: &[&str]) -> Vec<String> {
        p.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn best_topic_follows_all_chains_unless_one_is_given() {
        assert_eq!(best_topic(&params(&["best"])).to_string(), "best_block");
        assert_eq!(
            best_topic(&params(&["best", "0", "pp"])).to_string(),
            "best_block:pp"
        );
        assert_eq!(
            best_topic(&params(&["best", "0", "xx"])).to_string(),
            "best_block"
        );
    }

    #[test]
    fn finalized_topic_follows_all_chains_unless_one_is_given() {
        let topic = finalized_topic(&params(&["finalized", "2"]));
        assert_eq!(topic.to_string(), "finalized_block:2");
        let topic = finalized_topic(&params(&["finalized"]));
        assert_eq!(topic.to_string(), "finalized_block:0");
        let topic = finalized_topic(&params(&["finalized", "0", "pp"]));
        assert_eq!(topic.to_string(), "finalized_block:0:pp");
        // not a chain
        let topic = finalized_topic(&params(&["finalized", "1", "xx"]));
        assert_eq!(topic.to_string(), "finalized_block:1");
    }
}
