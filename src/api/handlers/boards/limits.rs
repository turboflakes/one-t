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

use crate::api::handlers::boards::params::{Intervals, Quantity, Weights, DECIMALS};
use log::{error, warn};
use serde::{de::Deserializer, Deserialize, Serialize};
use std::{collections::BTreeMap, str::FromStr};

// TODO: get this constants from chain
const NOMINATORS_OVERSUBSCRIBED_THRESHOLD: u32 = 256;
const COMMISSION_PLANCK: u32 = 1000000000;

pub type LimitsCache = BTreeMap<String, f64>;

#[derive(Debug, Serialize, PartialEq, Copy, Clone)]
pub struct Interval {
    pub min: u64,
    pub max: u64,
}

impl Default for Interval {
    fn default() -> Interval {
        Interval { min: 0, max: 0 }
    }
}

impl std::fmt::Display for Interval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.min, self.max)
    }
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct Limits {
    pub commission: Interval,
    // pub inclusion_rate: Interval,
    // pub nominators: Interval,
    // pub avg_reward_points: Interval,
    // pub reward_staked: Interval,
    // pub active: Interval,
    // pub own_stake: Interval,
    // pub total_stake: Interval,
    // pub judgements: Interval,
    // pub sub_accounts: Interval,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            commission: Interval::default(),
            // inclusion_rate: Interval::default(),
            // nominators: Interval::default(),
            // avg_reward_points: Interval::default(),
            // reward_staked: Interval::default(),
            // active: Interval::default(),
            // own_stake: Interval::default(),
            // total_stake: Interval::default(),
            // judgements: Interval::default(),
            // sub_accounts: Interval::default(),
        }
    }
}

impl std::fmt::Display for Limits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Note: the position of the traits is important, it should be the same as the position in weights
        write!(
            f,
            // "{},{},{},{},{},{},{},{},{},{}",
            "{}",
            self.commission.to_string(),
            // self.inclusion_rate.to_string(),
            // self.nominators.to_string(),
            // self.avg_reward_points.to_string(),
            // self.reward_staked.to_string(),
            // self.active.to_string(),
            // self.own_stake.to_string(),
            // self.total_stake.to_string(),
            // self.judgements.to_string(),
            // self.sub_accounts.to_string()
        )
    }
}

impl From<&Intervals> for Limits {
    fn from(data: &Intervals) -> Self {
        Limits {
            commission: *data.get(0).unwrap_or(&Interval::default()),
            // inclusion_rate: *data.get(1).unwrap_or(&Interval::default()),
            // nominators: *data.get(2).unwrap_or(&Interval::default()),
            // avg_reward_points: *data.get(3).unwrap_or(&Interval::default()),
            // reward_staked: *data.get(4).unwrap_or(&Interval::default()),
            // active: *data.get(5).unwrap_or(&Interval::default()),
            // own_stake: *data.get(6).unwrap_or(&Interval::default()),
            // total_stake: *data.get(7).unwrap_or(&Interval::default()),
            // judgements: *data.get(8).unwrap_or(&Interval::default()),
            // sub_accounts: *data.get(9).unwrap_or(&Interval::default()),
        }
    }
}

impl From<LimitsCache> for Limits {
    fn from(data: LimitsCache) -> Self {
        let default_min = 0_u64;
        let default_max = 100_u64;
        let base = 10_u64;
        Limits {
            commission: Interval {
                min: 0,
                max: 100 * base.pow(DECIMALS),
            },
            // inclusion_rate: Interval {
            //     min: 0.0_f64,
            //     max: 1.0_f64,
            // },
            // nominators: Interval {
            //     min: 0.0_f64,
            //     max: NOMINATORS_OVERSUBSCRIBED_THRESHOLD as f64,
            // },
            // avg_reward_points: Interval {
            //     min: *data.get("min_avg_reward_points").unwrap_or(&default_min),
            //     max: *data.get("max_avg_reward_points").unwrap_or(&default_max),
            // },
            // reward_staked: Interval {
            //     min: 0.0_f64,
            //     max: 1.0_f64,
            // },
            // active: Interval {
            //     min: 0.0_f64,
            //     max: 1.0_f64,
            // },
            // own_stake: Interval {
            //     min: *data.get("min_own_stake").unwrap_or(&default_min),
            //     max: *data.get("max_own_stake").unwrap_or(&default_max),
            // },
            // total_stake: Interval {
            //     min: *data.get("min_total_stake").unwrap_or(&default_min),
            //     max: *data.get("max_total_stake").unwrap_or(&default_max),
            // },
            // judgements: Interval {
            //     min: *data.get("min_judgements").unwrap_or(&default_min),
            //     max: *data.get("max_judgements").unwrap_or(&default_max),
            // },
            // sub_accounts: Interval {
            //     min: *data.get("min_sub_accounts").unwrap_or(&default_min),
            //     max: *data.get("max_sub_accounts").unwrap_or(&default_max),
            // },
        }
    }
}
