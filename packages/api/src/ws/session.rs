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
use onet_records::{collators::CollatorKind, BlockNumber, EpochIndex};
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
                                topic: Topic::NewSession(session_chain(&req.params)),
                            }),
                            Some("current") => self.server_addr.do_send(server::Subscribe {
                                id: self.id,
                                topic: Topic::CurrentSession(session_chain(&req.params)),
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
                        for topic in collators_topics(&req.params) {
                            self.server_addr
                                .do_send(server::Subscribe { id: self.id, topic });
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
                                topic: Topic::NewSession(session_chain(&req.params)),
                            }),
                            Some("current") => self.server_addr.do_send(server::Unsubscribe {
                                id: self.id,
                                topic: Topic::CurrentSession(session_chain(&req.params)),
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
                        for topic in collators_topics(&req.params) {
                            self.server_addr
                                .do_send(server::Unsubscribe { id: self.id, topic });
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

/// Topics of the collators from the params `[chain_key, ..., kind]`, where chain_key is `ah` or `pp`.
/// Note: the optional kind (`i`, `p`, `v` or `u`) applies to all chains given, and the
/// collators sent are only the ones of that kind.
fn collators_topics(params: &[String]) -> Vec<Topic> {
    let kind = params.iter().find_map(|p| CollatorKind::from_code(p));
    params
        .iter()
        .filter_map(|p| ChainKey::from_str(p).ok())
        .filter(|c| matches!(c, ChainKey::AH | ChainKey::PEOPLE))
        .map(|c| Topic::Collators(c, kind))
        .collect()
}

/// Parachain of the session topics from the params `["new" | "current", chain_key]`, the relay chain if none.
fn session_chain(params: &[String]) -> Option<ChainKey> {
    params
        .get(1)
        .and_then(|c| ChainKey::from_str(c).ok())
        .filter(|c| matches!(c, ChainKey::AH | ChainKey::PEOPLE))
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
    fn collators_topics_have_an_optional_kind() {
        let topics = |p: &[&str]| -> Vec<String> {
            collators_topics(&params(p))
                .iter()
                .map(|t| t.to_string())
                .collect()
        };
        assert_eq!(topics(&["ah", "pp"]), ["collators:ah", "collators:pp"]);
        assert_eq!(topics(&["pp", "I"]), ["collators:pp:i"]);
        assert_eq!(
            topics(&["ah", "pp", "V"]),
            ["collators:ah:v", "collators:pp:v"]
        );
        // not collators chains
        assert_eq!(topics(&["rc", "xx", "I"]), Vec::<String>::new());
    }

    #[test]
    fn session_topics_follow_the_relay_chain_unless_a_parachain_is_given() {
        assert_eq!(session_chain(&params(&["current"])), None);
        assert_eq!(session_chain(&params(&["current", "rc"])), None);
        assert_eq!(session_chain(&params(&["new", "xx"])), None);
        assert_eq!(session_chain(&params(&["new", "ah"])), Some(ChainKey::AH));
        assert_eq!(
            Topic::CurrentSession(session_chain(&params(&["current", "pp"]))).to_string(),
            "current_session:pp"
        );
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
