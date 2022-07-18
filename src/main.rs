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

mod api;
mod cache;
mod config;
mod errors;
mod matrix;
mod onet;
mod pools;
mod records;
mod report;
mod runtimes;
mod stats;

use crate::api::{routes::routes, ws::server};
use crate::cache::add_pool;
use crate::config::CONFIG;
use crate::onet::Onet;
use actix::*;
use actix_cors::Cors;
use actix_web::{http, middleware, web, App, HttpServer};
use log::info;
use std::env;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // load configuration
    let config = CONFIG.clone();

    if config.is_debug {
        env::set_var(
            "RUST_LOG",
            "onet=debug,subxt=debug,actix_cors=debug,actix_web=debug,actix_server=debug",
        );
    } else {
        env::set_var("RUST_LOG", "onet=info");
    }
    env_logger::try_init().unwrap_or_default();

    info!(
        "{} v{} * {}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_DESCRIPTION")
    );

    // start chain subscription service
    Onet::spawn();

    // start http server with an websocket /ws endpoint
    let addr = format!("{}:{}", config.api_host, config.api_port);
    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin_fn(|origin, _req_head| {
                let allowed_origin =
                    env::var("ONET_API_CORS_ALLOW_ORIGIN").unwrap_or("*".to_string());
                origin.as_bytes().ends_with(allowed_origin.as_bytes())
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
    .run()
    .await
}
