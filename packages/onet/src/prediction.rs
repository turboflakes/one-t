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

use log::{error, info, warn};
use onet_cache::{
    cache_nominators_prediction, cache_prediction,
    provider::{create_or_await_pool, get_conn, RedisPool},
};
use onet_chains::SupportedRuntime;
use onet_config::{Config, CONFIG};
use onet_prediction::{
    discard_failed_file, read_pending_files, remove_file, PendingFile, PredictionFile,
};
use redis::aio::Connection;
use std::{path::Path, time::Duration};

/// Files modified more recently than this are assumed to still be written by the producer.
const MIN_FILE_AGE: Duration = Duration::from_secs(2);

/// Polls `prediction_dir` for prediction files, caches each one and deletes it afterwards.
pub fn spawn_prediction_ingest() {
    let config = CONFIG.clone();
    if !config.prediction_enabled {
        return;
    }
    if !config.cache_writer_enabled {
        warn!("Predictions require the cache writer to be enabled, ingest is disabled");
        return;
    }

    let runtime = SupportedRuntime::from(config.chain_name.clone());
    async_std::task::spawn(async move {
        info!(
            "Watching {} for prediction files every {}s",
            config.prediction_dir, config.prediction_poll_interval
        );
        let pool = create_or_await_pool(config.clone());
        loop {
            if let Err(e) = ingest_pending_files(&pool, &config, runtime).await {
                error!("ingest_pending_files error: {}", e);
            }
            async_std::task::sleep(Duration::from_secs(config.prediction_poll_interval)).await;
        }
    });
}

async fn ingest_pending_files(
    pool: &RedisPool,
    config: &Config,
    runtime: SupportedRuntime,
) -> Result<(), String> {
    let dir = Path::new(&config.prediction_dir);
    if !dir.is_dir() {
        return Ok(());
    }
    // oldest first, so the newest file for a given `target_validators` is cached last
    for PendingFile { path, .. } in read_pending_files(dir, MIN_FILE_AGE).map_err(String::from)? {
        let file_path = path.clone();
        let parsed = async_std::task::spawn_blocking(move || {
            PredictionFile::from_path(&file_path, runtime.token_symbol(), runtime.token_decimals())
        })
        .await;

        let prediction = match parsed {
            Ok(prediction) => prediction,
            Err(e) => {
                // keep the file around for inspection but never retry it
                error!("Could not parse prediction file {:?}: {}", path, e);
                if let Err(e) = discard_failed_file(&path) {
                    error!("Could not rename prediction file {:?}: {}", path, e);
                }
                continue;
            }
        };

        let mut conn = get_conn(pool).await.map_err(String::from)?;
        // on cache failure the file is left in place and retried on the next poll
        match prediction {
            PredictionFile::Validators(prediction) => {
                cache_prediction(&mut conn as &mut Connection, config, &prediction)
                    .await
                    .map_err(String::from)?;
                info!(
                    "Prediction cached for target={} round={} validators={}",
                    prediction.metadata.target_validators,
                    prediction.metadata.round,
                    prediction.metadata.validators_count
                );
            }
            PredictionFile::Nominators(prediction) => {
                cache_nominators_prediction(&mut conn as &mut Connection, config, &prediction)
                    .await
                    .map_err(String::from)?;
                info!(
                    "Nominators prediction cached for target={} nominators={}",
                    prediction.target_validators,
                    prediction.entries.len()
                );
            }
        }
        remove_file(&path).map_err(String::from)?;
    }
    Ok(())
}
