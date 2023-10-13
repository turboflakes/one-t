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

use crate::errors::ApiError;
use crate::mcda::criterias::{CriteriaLimits, CriteriaWeights, DECIMALS, WEIGHTS_CAPACITY};
use crate::records::ValidatorProfileRecord;
use log::{error, warn};
use std::result::Result;

// Maximum normalization value
const NMAX: u64 = 10000000;
// Minimum normalization value
const NMIN: u64 = 0;

fn base_decimals() -> u64 {
    let base = 10_u64;
    base.pow(DECIMALS)
}

/// Normalize value between min and max
fn normalize_value(value: u64, min: u64, max: u64) -> u64 {
    if value == 0 || value < min {
        return NMIN;
    }
    if value > max {
        return NMAX;
    }
    (((value - min) * base_decimals()) as u128 / (max - min) as u128) as u64
}

/// Reverse normalization
fn reverse_normalize_value(value: u64, min: u64, max: u64) -> u64 {
    NMAX - normalize_value(value, min, max)
}

pub type Score = u64;
pub type Scores = Vec<Score>;

pub fn calculate_scores(
    validator: &ValidatorProfileRecord,
    limits: &CriteriaLimits,
    weights: &CriteriaWeights,
    chain_token_decimals: u32,
) -> Result<Scores, ApiError> {
    let mut scores: Scores = Vec::with_capacity(WEIGHTS_CAPACITY);

    scores.push(
        reverse_normalize_value(
            validator.commission as u64,
            limits.commission.min,
            limits.commission.max,
        ) * weights.commission as u64,
    );

    scores.push(
        normalize_value(
            validator.own_stake_trimmed(chain_token_decimals),
            limits.own_stake.min,
            limits.own_stake.max,
        ) * weights.own_stake as u64,
    );

    scores.push(
        normalize_value(
            validator.nominators_stake as u64,
            limits.nominators_stake.min,
            limits.nominators_stake.max,
        ) * weights.nominators_stake as u64,
    );

    scores.push(
        reverse_normalize_value(
            validator.nominators_counter as u64,
            limits.nominators_counter.min,
            limits.nominators_counter.max,
        ) * weights.nominators_counter as u64,
    );

    // scores.push(
    //     normalize_value(
    //         validator.inclusion_rate as f64,
    //         limits.inclusion_rate.min,
    //         limits.inclusion_rate.max,
    //     ) * weights[0] as f64,
    // );
    // scores.push(
    //     reverse_normalize_value(
    //         validator.nominators as f64,
    //         limits.nominators.min,
    //         limits.nominators.max,
    //     ) * weights[2] as f64,
    // );
    // scores.push(
    //     normalize_value(
    //         validator.avg_reward_points,
    //         limits.avg_reward_points.min,
    //         limits.avg_reward_points.max,
    //     ) * weights[3] as f64,
    // );
    // scores.push(normalize_flag(validator.reward_staked) * weights[4] as f64);
    // scores.push(normalize_flag(validator.active) * weights[5] as f64);
    // scores.push(
    //     reverse_normalize_value(
    //         (validator.own_stake + validator.nominators_stake) as f64,
    //         limits.total_stake.min,
    //         limits.total_stake.max,
    //     ) * weights[7] as f64,
    // );
    // scores.push(
    //     normalize_value(
    //         validator.judgements as f64,
    //         limits.judgements.min,
    //         limits.judgements.max,
    //     ) * weights[8] as f64,
    // );
    // scores.push(
    //     reverse_normalize_value(
    //         validator.sub_accounts as f64,
    //         limits.sub_accounts.min,
    //         limits.sub_accounts.max,
    //     ) * weights[9] as f64,
    // );

    Ok(scores)
}

pub fn scores_to_string(scores: Scores) -> String {
    scores
        .iter()
        .enumerate()
        .map(|(i, x)| {
            if i == 0 {
                return x.to_string();
            }
            format!(",{}", x)
        })
        .collect()
}

#[test]
fn test_scores() {
    // normalize 15% value between limits 10% and 20%
    assert_eq!(normalize_value(150000000, 100000000, 200000000), 5000000);
    assert_eq!(normalize_value(150000000, 0, 200000000), 7500000);
    assert_eq!(reverse_normalize_value(150000000, 0, 200000000), 2500000);
}
