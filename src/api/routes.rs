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

use crate::api::handlers::{
    blocks::{get_best_block, get_block_by_number, get_blocks, get_finalized_block},
    health::get_health,
    info::get_info,
    parachains::get_parachains,
    // pool::{get_pool, get_pool_nomination, get_pool_nominees, get_pools_stats},
    sessions::{get_session_by_index, get_sessions},
    validators::{
        get_peer_by_authority, get_validator_by_stash, get_validator_grade_by_stash,
        get_validator_profile_by_stash, get_validators,
    },
    ws::init,
};
use actix_web::web;

/// All routes are placed here
pub fn routes(cfg: &mut web::ServiceConfig) {
    cfg
        // Index
        .route("/", web::get().to(get_info))
        // Healthcheck
        .route("/health", web::get().to(get_health))
        // /api/v1 routes
        .service(
            web::scope("/api/v1")
                // API info
                .route("", web::get().to(get_info))
                // WEBSOCKET route
                .route("/ws", web::get().to(init))
                // SESSION routes
                .service(
                    web::scope("/sessions")
                        .route("/{index}", web::get().to(get_session_by_index))
                        .route("", web::get().to(get_sessions)),
                )
                // BLOCKS routes
                .service(
                    web::scope("/blocks")
                        .route("/finalized", web::get().to(get_finalized_block))
                        .route("/best", web::get().to(get_best_block))
                        .route("/{block_number}", web::get().to(get_block_by_number))
                        .route("", web::get().to(get_blocks)),
                )
                // VALIDATOR routes
                .service(
                    web::scope("/validators")
                        .route("/{stash}", web::get().to(get_validator_by_stash))
                        .route(
                            "/{stash}/profile",
                            web::get().to(get_validator_profile_by_stash),
                        )
                        .route(
                            "/{stash}/grade",
                            web::get().to(get_validator_grade_by_stash),
                        )
                        .route(
                            "/{stash}/peers/{peer}",
                            web::get().to(get_peer_by_authority),
                        )
                        .route("", web::get().to(get_validators)),
                )
                // PARACHAIN routes
                .service(web::scope("/parachains").route("", web::get().to(get_parachains))), // POOL routes
                                                                                              // .service(
                                                                                              //     web::scope("/pool")
                                                                                              //         .route("/{id}", web::get().to(get_pool))
                                                                                              //         .route("/{id}/nominees", web::get().to(get_pool_nominees))
                                                                                              //         .route("/{id}/nomination", web::get().to(get_pool_nomination))
                                                                                              //         .route("", web::get().to(get_pools_stats)),
                                                                                              // ),
        );
}
