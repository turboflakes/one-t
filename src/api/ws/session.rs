use std::{
    str::FromStr,
    time::{Duration, Instant},
};

use crate::api::ws::{
    channel::Topic,
    server,
    server::{Methods, WsRequestMessage},
};
use crate::records::EpochIndex;
use actix::prelude::*;
use actix_web_actors::ws;
use log::{debug, warn};
use subxt::sp_runtime::AccountId32;

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

                let req: WsRequestMessage = serde_json::from_str(&m).unwrap_or_default();
                // TODO handle all methods
                match req.method {
                    Methods::SubscribeBlock => {
                        if &req.params[0] == "best" {
                            self.server_addr.do_send(server::Subscribe {
                                id: self.id,
                                topic: Topic::BestBlock,
                            });
                        }
                    }
                    Methods::SubscribeSession => {
                        if &req.params[0] == "current" {
                            self.server_addr.do_send(server::Subscribe {
                                id: self.id,
                                topic: Topic::CurrentSession,
                            });
                        }
                    }
                    Methods::SubscribeValidator => {
                        for stash in req.params.iter() {
                            if let Ok(acc) = AccountId32::from_str(&stash) {
                                self.server_addr.do_send(server::Subscribe {
                                    id: self.id,
                                    topic: Topic::Validator(acc),
                                });
                            }
                        }
                    }
                    Methods::SubscribeParaAuthorities => {
                        for index in req.params.iter() {
                            if let Ok(index) = &index.parse::<EpochIndex>() {
                                self.server_addr.do_send(server::Subscribe {
                                    id: self.id,
                                    topic: Topic::ParaAuthorities(*index),
                                });
                            }
                        }
                    }
                    Methods::UnsubscribeValidator => {
                        for stash in req.params.iter() {
                            if let Ok(acc) = AccountId32::from_str(&stash) {
                                self.server_addr.do_send(server::Unsubscribe {
                                    id: self.id,
                                    topic: Topic::Validator(acc),
                                });
                            }
                        }
                    }
                    Methods::UnsubscribeParaAuthorities => {
                        for index in req.params.iter() {
                            if let Ok(index) = &index.parse::<EpochIndex>() {
                                self.server_addr.do_send(server::Unsubscribe {
                                    id: self.id,
                                    topic: Topic::ParaAuthorities(*index),
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
