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
//

use actix::Actor;
use actix_cors::Cors;
use actix_web::{dev::ServerHandle, http, middleware, rt, web, App, HttpServer};
use log::{error, info, warn};
use onet_api::{routes::routes, ws::server};
use onet_cache::provider::add_pool;
use onet_chains::SupportedRuntime;
use onet_config::CONFIG;
use onet_core::{core::Onet, error::OnetError};
use onet_dn::try_fetch_stashes_from_remote_url;
use onet_kusama::kusama;
use onet_matrix::Matrix;
use onet_paseo::paseo;
// use onet_polkadot::polkadot;
// use onet_westend::westend;
// use onet_westend_next::westend_next;
use sp_core::crypto;
use std::{env, sync::mpsc, thread, time};

// #[actix_web::main]
fn main() {
    // load configuration
    let config = CONFIG.clone();

    if config.is_debug {
        env::set_var(
            "RUST_LOG",
            "onet=debug,subxt=debug,actix_cors=debug,actix_web=debug,actix_server=debug",
        );
    } else {
        env::set_var("RUST_LOG", "onet=info,subxt=info");
    }
    env_logger::try_init().unwrap_or_default();

    info!(
        "{} v{} * {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_DESCRIPTION")
    );

    start();
}

fn start() {
    let config = CONFIG.clone();
    info!("Starting ONET");
    let (ctrlc_tx, ctrlc_rx) = mpsc::channel();

    ctrlc::set_handler(move || {
        ctrlc_tx
            .send(())
            .expect("Could not send signal on channel.")
    })
    .expect("Error setting Ctrl-C handler");

    if config.api_enabled {
        let (server_tx, server_rx) = mpsc::channel();
        // start one-t API as a standalone service without depending on other services
        spawn_api(server_tx);
        let server_handle = server_rx
            .recv()
            .expect("could not receive server handle from channel.");

        // wait for SIGINT, SIGTERM, SIGHUP
        ctrlc_rx
            .recv()
            .expect("could not receive signal from channel.");

        // close gracefully http server api
        rt::System::new().block_on(server_handle.stop(true));
    } else {
        // Authenticate matrix and spawn lazy load commands
        spawn_and_restart_matrix_lazy_load_on_error();

        if !config.matrix_only {
            // Subscribe on-chain events
            spawn_and_restart_on_chain_events_on_error();
        }

        // wait for SIGINT, SIGTERM, SIGHUP
        ctrlc_rx
            .recv()
            .expect("could not receive signal from channel.");
    }
}

fn spawn_api(tx: mpsc::Sender<ServerHandle>) {
    async_std::task::spawn(async {
        let server_future = run_api(tx);
        rt::System::new().block_on(server_future)
    });
}

async fn run_api(tx: mpsc::Sender<ServerHandle>) -> std::io::Result<()> {
    let config = CONFIG.clone();
    // set ss58 version globally based on config.chain_name
    crypto::set_default_ss58_version(crypto::Ss58AddressFormat::custom(
        SupportedRuntime::from(config.chain_name).chain_prefix(),
    ));
    // start http server with an websocket /ws endpoint
    let addr = format!("{}:{}", config.api_host, config.api_port);
    info!("Starting HTTP server at http://{}", addr);
    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin_fn(|origin, _req_head| {
                let allowed_origins =
                    env::var("ONET_API_CORS_ALLOW_ORIGIN").unwrap_or("*".to_string());
                let allowed_origins = allowed_origins.split(",").collect::<Vec<_>>();
                allowed_origins
                    .iter()
                    .any(|e| e.as_bytes() == origin.as_bytes())
            })
            .allowed_methods(vec!["GET", "OPTIONS"])
            .allowed_headers(vec![http::header::CONTENT_TYPE])
            .supports_credentials()
            .max_age(3600);
        App::new()
            .app_data(web::Data::new(server::Server::new().start()))
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .configure(add_pool)
            .configure(routes)
    })
    .bind(addr)?
    .run();

    // Send server handle back to the main thread
    let _ = tx.send(server.handle());

    server.await
}

fn spawn_and_restart_matrix_lazy_load_on_error() {
    async_std::task::spawn(async {
        let config = CONFIG.clone();
        if !config.matrix_disabled {
            loop {
                let mut m = Matrix::new();
                if let Err(e) = m.authenticate(config.chain_name.clone().into()).await {
                    error!("authenticate error: {}", e);
                    thread::sleep(time::Duration::from_secs(config.error_interval));
                    continue;
                }
                if let Err(e) = m.lazy_load_and_process_commands().await {
                    error!("lazy_load_and_process_commands error: {}", e);
                    thread::sleep(time::Duration::from_secs(config.error_interval));
                    continue;
                }
            }
        }
    });
}

fn spawn_and_restart_on_chain_events_on_error() {
    async_std::task::spawn(async {
        let config = CONFIG.clone();
        loop {
            // Initialize a new instance
            let onet = Onet::init().await;

            if let Err(e) = subscribe_on_chain_events(&onet).await {
                match e {
                    OnetError::SubscriptionFinished => warn!("{}", e),
                    _ => {
                        error!("subscribe_on_chain_events error: {}", e);
                        thread::sleep(time::Duration::from_secs(config.error_interval));
                        continue;
                    }
                }
                thread::sleep(time::Duration::from_secs(1));
            };
        }
    });
}

async fn subscribe_on_chain_events(onet: &Onet) -> Result<(), OnetError> {
    info!("Subscribing to on-chain events");
    // initialize and load TVP stashes
    match onet.runtime() {
        SupportedRuntime::Polkadot | SupportedRuntime::Kusama => {
            try_fetch_stashes_from_remote_url(false, None).await?;
        }
        _ => {}
    };

    match onet.runtime() {
        // SupportedRuntime::Polkadot => polkadot::init_and_subscribe_on_chain_events(onet).await,
        SupportedRuntime::Kusama => kusama::init_and_subscribe_on_chain_events(onet).await,
        SupportedRuntime::Paseo => paseo::init_and_subscribe_on_chain_events(onet).await,
        // SupportedRuntime::Westend => westend::init_and_subscribe_on_chain_events(onet).await,
        // SupportedRuntime::WestendNext => {
        //     westend_next::init_and_subscribe_on_chain_events(onet).await
        // }
        _ => todo!(),
    }
}
