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

use crate::api::handlers::boards::{
    limits::Limits,
    params::{Weights, CAPACITY, DECIMALS},
};
use crate::errors::ApiError;
use crate::records::ValidatorProfileRecord;
use log::{error, warn};
use std::result::Result;

// Maximum normalization value
const NMAX: u64 = 10000000;
// Minimum normalization value
const NMIN: u64 = 0;

/// Normalize value between min and max
fn normalize_value(value: u64, min: u64, max: u64) -> u64 {
    if value == 0 || value < min {
        return NMIN;
    }
    if value > max {
        return NMAX;
    }
    let base = 10_u64;
    (((value - min) * base.pow(DECIMALS)) as u128 / (max - min) as u128) as u64
}

/// Reverse normalization
fn reverse_normalize_value(value: u64, min: u64, max: u64) -> u64 {
    NMAX - normalize_value(value, min, max)
}

/// Normalize commission between 0 - 10_000_000
fn normalize_commission(commission: u32) -> u64 {
    commission as u64 / 100_u64
}

/// Reverse Normalize commission between 0 - 10_000_000
/// lower commission the better
fn reverse_normalize_commission(commission: u32, min: u32, max: u32) -> u64 {
    reverse_normalize_value(
        normalize_commission(commission),
        normalize_commission(min),
        normalize_commission(max),
    )
}

pub type Score = u64;
pub type Scores = Vec<Score>;

pub fn calculate_scores(
    validator: &ValidatorProfileRecord,
    limits: &Limits,
    weights: &Weights,
) -> Result<Scores, ApiError> {
    let mut scores: Scores = Vec::with_capacity(CAPACITY);

    scores.push(
        reverse_normalize_commission(
            validator.commission,
            limits.commission.min as u32,
            limits.commission.max as u32,
        ) * weights[0] as u64,
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
    //     normalize_value(
    //         validator.own_stake as f64,
    //         limits.own_stake.min,
    //         limits.own_stake.max,
    //     ) * weights[6] as f64,
    // );
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
