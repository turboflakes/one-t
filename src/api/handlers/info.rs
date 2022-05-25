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

use crate::api::helpers::respond_json;
use crate::config::CONFIG;
use crate::errors::ApiError;
use actix_web::web::Json;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Deserialize, Serialize, PartialEq)]
pub struct InfoResponse {
    pub pkg_name: String,
    pub pkg_version: String,
    pub api_path: String,
    pub chain_name: String,
}

/// Handler to get information about the service
pub async fn get_info() -> Result<Json<InfoResponse>, ApiError> {
    let config = CONFIG.clone();
    respond_json(InfoResponse {
        pkg_name: env!("CARGO_PKG_NAME").into(),
        pkg_version: env!("CARGO_PKG_VERSION").into(),
        api_path: "/api/v1".into(),
        chain_name: config.chain_name.into(),
    })
}
