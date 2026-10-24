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
use onet_prediction::{
    NominatorEntry, NominatorStatus, NominatorsPrediction, Prediction, PredictionEntry,
};
use redis::aio::Connection;
use std::collections::HashSet;
use std::result::Result;
use subxt::utils::AccountId32;

/// Caches a prediction under its `target_validators` namespace, replacing whatever
/// was cached before for the same `target_validators` and leaving the others untouched.
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
    let accounts_key = CacheKey::PredictionValidatorAccountsByTarget(target);

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
                .arg(CacheKey::PredictionValidatorNominatorsByTargetAndAccount(
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
        let nominators_key =
            CacheKey::PredictionValidatorNominatorsByTargetAndAccount(target, *account_id);
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

/// Number of nominators added to the accounts sorted set per ZADD command.
const ZADD_CHUNK_SIZE: usize = 1000;

/// Caches a nominators prediction under its `target_validators` namespace, replacing whatever
/// was cached before for the same `target_validators` and leaving the others untouched.
///
/// Everything is written in a single MULTI/EXEC so readers never see a half-written round.
/// Nominators present in the previous round but missing from this one are deleted.
///
/// The nominators addresses are kept in a sorted set scored by stake, so they can be paginated
/// from the largest to the smallest stake. Besides the sorted set with all the nominators, there
/// is one sorted set per `NominatorStatus` so each group can be paginated on its own.
pub async fn cache_nominators_prediction(
    cache: &mut Connection,
    config: &Config,
    prediction: &NominatorsPrediction,
) -> Result<(), CacheError> {
    let target = prediction.target_validators;
    let ttl = config.prediction_cache_ttl;
    let accounts_key = CacheKey::PredictionNominatorAccountsByTarget(target);

    let previous: Vec<String> = redis::cmd("ZRANGE")
        .arg(accounts_key.to_string())
        .arg(0)
        .arg(-1)
        .query_async(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    // (score, address): the score is only used to sort, so the loss of precision of
    // stakes above 2^53 planck is not a concern
    let current: Vec<(f64, String)> = prediction
        .entries
        .iter()
        .map(|e| (e.nominator.stake.0 as f64, e.account_id.to_string()))
        .collect();
    let current_set: HashSet<&String> = current.iter().map(|(_, a)| a).collect();

    let mut pipe = redis::pipe();
    pipe.atomic();

    // drop nominators that are no longer part of the prediction
    for account in previous.iter().filter(|a| !current_set.contains(*a)) {
        if let Ok(account_id) = account.parse::<AccountId32>() {
            pipe.cmd("DEL")
                .arg(CacheKey::PredictionNominatorByTargetAndAccount(
                    target, account_id,
                ))
                .ignore();
        }
    }

    for NominatorEntry {
        account_id,
        nominator,
    } in prediction.entries.iter()
    {
        pipe.cmd("SET")
            .arg(CacheKey::PredictionNominatorByTargetAndAccount(
                target,
                *account_id,
            ))
            .arg(serde_json::to_string(nominator)?)
            .arg("EX")
            .arg(ttl)
            .ignore();
    }

    pipe.cmd("SET")
        .arg(CacheKey::PredictionNominatorsMetaByTarget(target))
        .arg(serde_json::to_string(&prediction.metadata)?)
        .arg("EX")
        .arg(ttl)
        .ignore();

    // the sorted set with all the nominators followed by one sorted set per status
    let mut by_status: Vec<(NominatorStatus, Vec<(f64, String)>)> = NominatorStatus::ALL
        .iter()
        .map(|status| (*status, Vec::new()))
        .collect();
    for entry in prediction.entries.iter() {
        let status = entry.nominator.status();
        if let Some((_, members)) = by_status.iter_mut().find(|(s, _)| *s == status) {
            members.push((entry.nominator.stake.0 as f64, entry.account_id.to_string()));
        }
    }
    let mut sorted_sets: Vec<(String, &[(f64, String)])> =
        vec![(accounts_key.to_string(), &current)];
    for (status, members) in by_status.iter() {
        sorted_sets.push((
            CacheKey::PredictionNominatorAccountsByTargetAndStatus(target, *status).to_string(),
            members,
        ));
    }
    for (key, members) in sorted_sets {
        pipe.cmd("DEL").arg(&key).ignore();
        for chunk in members.chunks(ZADD_CHUNK_SIZE) {
            pipe.cmd("ZADD").arg(&key).arg(chunk).ignore();
        }
        if !members.is_empty() {
            pipe.cmd("EXPIRE").arg(&key).arg(ttl).ignore();
        }
    }

    pipe.query_async::<_, ()>(cache)
        .await
        .map_err(CacheError::RedisCMDError)?;

    Ok(())
}
