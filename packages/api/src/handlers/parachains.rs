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

use crate::{
    helpers::respond_json,
    responses::{CacheMap, ParachainsResult},
};
use actix_web::web::{Data, Json, Query};
use log::warn;
use onet_cache::{
    provider::{get_conn, RedisPool},
    types::{CacheKey, Index},
};
use onet_errors::{ApiError, CacheError};
use onet_records::EpochIndex;
use redis::aio::Connection;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Role {
    Authority = 1,
    ParaAuthority = 2,
    Waiting = 3,
    Other = 4,
    NotDefined = 5,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authority => write!(f, "authority"),
            Self::ParaAuthority => write!(f, "para_authority"),
            Self::Waiting => write!(f, "waiting"),
            Self::Other => write!(f, "other"),
            Self::NotDefined => write!(f, "not_defined"),
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Report {
    Validator = 1,
    ValGroups = 2,
    Parachains = 3,
    Other = 4,
    NotDefined = 5,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Params {
    #[serde(default = "default_role")]
    role: Role,
    #[serde(default = "default_report")]
    report: Report,
    #[serde(default = "default_index")]
    session: Index,
    // show_stats indicates wheter parachain details should be retrieved or not, default false
    #[serde(default)]
    show_stats: bool,
    // show_summary indicates wheter parachain summary should be retrieved or not, default false
    #[serde(default)]
    show_summary: bool,
}

fn default_role() -> Role {
    Role::NotDefined
}

fn default_report() -> Report {
    Report::NotDefined
}

fn default_index() -> Index {
    Index::Current
}

/// Get parachains filtered by query params
pub async fn get_parachains(
    params: Query<Params>,
    cache: Data<RedisPool>,
) -> Result<Json<ParachainsResult>, ApiError> {
    let mut conn = get_conn(&cache).await?;

    let session_index: EpochIndex = match &params.session {
        Index::Str(index) => {
            if String::from("current") == *index {
                redis::cmd("GET")
                    .arg(CacheKey::SessionByIndex(Index::Current))
                    .query_async(&mut conn as &mut Connection)
                    .await
                    .map_err(CacheError::RedisCMDError)?
            } else {
                index.parse::<EpochIndex>().unwrap_or_default()
            }
        }
        _ => redis::cmd("GET")
            .arg(CacheKey::SessionByIndex(Index::Current))
            .query_async(&mut conn as &mut Connection)
            .await
            .map_err(CacheError::RedisCMDError)?,
    };

    let mut data: CacheMap = redis::cmd("HGETALL")
        .arg(CacheKey::ParachainsBySession(session_index))
        .query_async(&mut conn as &mut Connection)
        .await
        .map_err(CacheError::RedisCMDError)?;

    if data.is_empty() {
        let msg = format!(
            "At session {} parachains data was not found.",
            session_index
        );
        warn!("{}", msg);
        return Err(ApiError::NotFound(msg));
    }

    data.insert(String::from("session"), session_index.to_string());
    respond_json(data.into())
}
