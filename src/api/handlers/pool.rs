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
use crate::pools::{Pool, PoolNominees, PoolsEra, POOL_FILENAME};
use actix_web::web::{Json, Path};
use std::{fs, path, result::Result};

type PoolResponse = Pool;

pub async fn get_pool(id: Path<u32>) -> Result<Json<PoolResponse>, ApiError> {
    let config = CONFIG.clone();

    if *id != config.pool_id_1 && *id != config.pool_id_2 {
        return Err(ApiError::NotFound(format!(
            "Pool with ID: {} not found.",
            *id
        )));
    }

    let filename = format!(
        "{}{}_{}_{}",
        config.data_path,
        POOL_FILENAME,
        *id,
        config.chain_name.to_lowercase()
    );

    // Try to read from cached file
    if !path::Path::new(&filename).exists() {
        return Err(ApiError::InternalServerError(format!(
            "Cache ({}) is not available.",
            filename
        )));
    }

    let serialized = fs::read_to_string(filename)?;
    let pool: Pool = serde_json::from_str(&serialized).unwrap();
    respond_json(pool.into())
}

type PoolNomineesResponse = PoolNominees;

pub async fn get_pool_nominees(id: Path<u32>) -> Result<Json<PoolNomineesResponse>, ApiError> {
    let config = CONFIG.clone();

    if *id != config.pool_id_1 && *id != config.pool_id_2 {
        return Err(ApiError::NotFound(format!(
            "Pool with ID: {} not found.",
            *id
        )));
    }

    let filename = format!(
        "{}{}_{}_nominees_{}",
        config.data_path,
        POOL_FILENAME,
        *id,
        config.chain_name.to_lowercase()
    );

    // Try to read from cached file
    if !path::Path::new(&filename).exists() {
        return Err(ApiError::InternalServerError(format!(
            "Cache ({}) is not available.",
            filename
        )));
    }

    let serialized = fs::read_to_string(filename)?;
    let pool_nominees: PoolNominees = serde_json::from_str(&serialized).unwrap();
    respond_json(pool_nominees.into())
}

type PoolsStatsResponse = PoolsEra;

pub async fn get_pools_stats() -> Result<Json<PoolsStatsResponse>, ApiError> {
    let config = CONFIG.clone();

    let filename = format!(
        "{}{}_stats_{}",
        config.data_path,
        POOL_FILENAME,
        config.chain_name.to_lowercase()
    );

    // Try to read from cached file
    if !path::Path::new(&filename).exists() {
        return Err(ApiError::InternalServerError(format!(
            "Cache ({}) is not available.",
            filename
        )));
    }

    let serialized = fs::read_to_string(filename)?;
    let pools_stats: PoolsEra = serde_json::from_str(&serialized).unwrap();
    respond_json(pools_stats.into())
}
