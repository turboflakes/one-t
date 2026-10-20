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

use crate::error::CacheError;
use crate::types::CacheKey;
use onet_config::Config;
use onet_prediction::{Prediction, PredictionEntry};
use redis::aio::Connection;
use std::collections::HashSet;
use std::result::Result;
use subxt::utils::AccountId32;

/// Caches a prediction under its `desired_validators` namespace, replacing whatever
/// was cached before for the same `desired_validators` and leaving the others untouched.
///
/// Everything is written in a single MULTI/EXEC so readers never see a half-written round.
/// Accounts present in the previous round but missing from this one are deleted.
pub async fn cache_prediction(
    cache: &mut Connection,
    config: &Config,
    prediction: &Prediction,
) -> Result<(), CacheError> {
    let target = prediction.metadata.target_validators;
    let ttl = config.prediction_cache_ttl;
    let accounts_key = CacheKey::PredictionAccountsByTarget(target);

    let previous: Vec<String> = redis::cmd("SMEMBERS")
        .arg(accounts_key.to_string())
        .query_async(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    let current: HashSet<String> = prediction
        .entries
        .iter()
        .map(|e| e.account_id.to_string())
        .collect();

    let mut pipe = redis::pipe();
    pipe.atomic();

    // drop accounts that are no longer part of the prediction
    for account in previous.iter().filter(|a| !current.contains(*a)) {
        if let Ok(account_id) = account.parse::<AccountId32>() {
            pipe.cmd("DEL")
                .arg(CacheKey::PredictionValidatorByTargetAndAccount(
                    target, account_id,
                ))
                .arg(CacheKey::PredictionNominatorsByTargetAndAccount(
                    target, account_id,
                ))
                .ignore();
        }
    }

    for PredictionEntry {
        account_id,
        validator,
        nominators,
    } in prediction.entries.iter()
    {
        let validator_key = CacheKey::PredictionValidatorByTargetAndAccount(target, *account_id);
        let nominators_key = CacheKey::PredictionNominatorsByTargetAndAccount(target, *account_id);
        pipe.cmd("SET")
            .arg(validator_key.to_string())
            .arg(serde_json::to_string(validator)?)
            .ignore()
            .cmd("EXPIRE")
            .arg(validator_key.to_string())
            .arg(ttl)
            .ignore()
            .cmd("SET")
            .arg(nominators_key.to_string())
            .arg(serde_json::to_string(nominators)?)
            .ignore()
            .cmd("EXPIRE")
            .arg(nominators_key.to_string())
            .arg(ttl)
            .ignore();
    }

    let meta_key = CacheKey::PredictionMetaByTarget(target);
    pipe.cmd("DEL")
        .arg(accounts_key.to_string())
        .ignore()
        .cmd("SET")
        .arg(meta_key.to_string())
        .arg(serde_json::to_string(&prediction.metadata)?)
        .ignore()
        .cmd("EXPIRE")
        .arg(meta_key.to_string())
        .arg(ttl)
        .ignore()
        .cmd("SADD")
        .arg(CacheKey::PredictionIndex)
        .arg(target)
        .ignore()
        .cmd("EXPIRE")
        .arg(CacheKey::PredictionIndex)
        .arg(ttl)
        .ignore();

    if !current.is_empty() {
        pipe.cmd("SADD")
            .arg(accounts_key.to_string())
            .arg(current.iter().collect::<Vec<_>>())
            .ignore()
            .cmd("EXPIRE")
            .arg(accounts_key.to_string())
            .arg(ttl)
            .ignore();
    }

    pipe.query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}
