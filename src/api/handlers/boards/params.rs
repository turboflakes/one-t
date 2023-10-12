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

use crate::cache::Index;
use crate::limits::{Interval, Intervals};
use log::{error, warn};
use serde::{de::Deserializer, Deserialize};
use std::result::Result;

/// Weight can be any value in a 10-point scale. Higher the weight more important
/// is the criteria to the user
type Weight = u8;

/// Weights represent an array of points, where the points in each position represents
/// the weight for the respective criteria
/// Position 0 - Lower Commission is preferrable
/// Position 1 - Higher own stake is preferrable
///
///
///
///
/// Position 1 - Higher Inclusion rate is preferrable
/// Position 2 - Lower Nominators is preferrable (limit to 256 -> oversubscribed)
/// Position 3 - Higher Reward Points is preferrable
/// Position 4 - If reward is staked is preferrable
/// Position 5 - If in active set is preferrable
/// Position 7 - Lower total stake is preferrable
/// Position 8 - Higher number of Reasonable or KnownGood judgements is preferrable
/// Position 9 - Lower number of sub-accounts is preferrable
pub type Weights = Vec<Weight>;

/// NOTE: Assumption of the number of decimals in scores or limits
pub const DECIMALS: u32 = 7;

/// Current weighs and limits capacity
pub const CAPACITY: usize = 2;

// Number of elements to return
pub type Quantity = u32;

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Params {
    #[serde(default = "default_index")]
    pub session: Index,
    #[serde(default = "default_weights")]
    #[serde(deserialize_with = "parse_weights")]
    pub w: Weights,
    #[serde(default = "default_intervals")]
    #[serde(deserialize_with = "parse_intervals")]
    pub i: Intervals,
    #[serde(default = "default_quantity")]
    pub n: Quantity,
    #[serde(default = "default_force")]
    pub force: bool,
}

fn default_index() -> Index {
    Index::Current
}

fn default_weights() -> Weights {
    vec![0; CAPACITY]
}

fn default_intervals() -> Intervals {
    vec![]
}

fn default_quantity() -> Quantity {
    16
}

fn default_force() -> bool {
    false
}

fn parse_weights<'de, D>(d: D) -> Result<Weights, D::Error>
where
    D: Deserializer<'de>,
{
    Deserialize::deserialize(d).map(|x: Option<_>| {
        let weights_as_csv = x.unwrap_or("".to_string());

        let mut weights_as_strvec: Vec<&str> = weights_as_csv.split(",").collect();
        weights_as_strvec.resize(CAPACITY, "5");

        let mut weights: Weights = Vec::with_capacity(CAPACITY);
        for i in 0..CAPACITY {
            let weight: u8 = weights_as_strvec.get(i).unwrap_or(&"0").parse().unwrap();
            let weight = if weight > 9 { 9 } else { weight };
            weights.push(weight);
        }
        weights
    })
}

fn parse_intervals<'de, D>(d: D) -> Result<Intervals, D::Error>
where
    D: Deserializer<'de>,
{
    Deserialize::deserialize(d).map(|x: Option<_>| {
        let intervals_as_csv = x.unwrap_or("".to_string());
        let mut intervals_as_strvec: Vec<&str> = intervals_as_csv.split(",").collect();
        intervals_as_strvec.resize(CAPACITY, "0");
        let mut intervals: Intervals = Vec::with_capacity(CAPACITY);
        for i in 0..CAPACITY {
            let interval_as_strvec: Vec<&str> = intervals_as_strvec[i].split(":").collect();
            let interval = Interval {
                min: interval_as_strvec
                    .get(0)
                    .unwrap_or(&"0")
                    .parse::<u64>()
                    .unwrap(),
                max: interval_as_strvec
                    .get(1)
                    .unwrap_or(&"0")
                    .parse::<u64>()
                    .unwrap(),
            };
            intervals.push(interval);
        }
        intervals
    })
}

pub fn get_board_name_from_weights(weights: &Weights, intervals: Option<&Intervals>) -> String {
    match intervals {
        Some(i) => {
            if i.is_empty() {
                return format!("{}", weights_to_string(weights));
            }
            format!("{}|{}", weights_to_string(weights), intervals_to_string(i),)
        }
        None => format!("{}", weights_to_string(weights)),
    }
}

fn weights_to_string(weights: &Weights) -> String {
    weights
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

fn intervals_to_string(intervals: &Intervals) -> String {
    intervals
        .iter()
        .enumerate()
        .map(|(i, x)| {
            if i == 0 {
                return format!("{}", x);
            }
            format!(",{}", x)
        })
        .collect()
}
