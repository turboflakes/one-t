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
use crate::mcda::criterias::{
    Filters, Interval, Intervals, Weights, FILTERS_CAPACITY, WEIGHTS_CAPACITY,
};
use serde::{de::Deserializer, Deserialize};
use std::result::Result;

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
    #[serde(default = "default_filters")]
    #[serde(deserialize_with = "parse_filters")]
    pub f: Filters,
    #[serde(default = "default_quantity")]
    pub n: Quantity,
    #[serde(default = "default_force")]
    pub force: bool,
}

fn default_index() -> Index {
    Index::Current
}

fn default_weights() -> Weights {
    vec![0; WEIGHTS_CAPACITY]
}

fn default_intervals() -> Intervals {
    vec![]
}

fn default_filters() -> Filters {
    vec![false; FILTERS_CAPACITY]
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
        weights_as_strvec.resize(WEIGHTS_CAPACITY, "5");

        let mut weights: Weights = Vec::with_capacity(WEIGHTS_CAPACITY);
        for i in 0..WEIGHTS_CAPACITY {
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
        intervals_as_strvec.resize(WEIGHTS_CAPACITY, "0");
        let mut intervals: Intervals = Vec::with_capacity(WEIGHTS_CAPACITY);
        for i in 0..WEIGHTS_CAPACITY {
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

fn parse_filters<'de, D>(d: D) -> Result<Filters, D::Error>
where
    D: Deserializer<'de>,
{
    Deserialize::deserialize(d).map(|x: Option<_>| {
        let filters_as_csv = x.unwrap_or("".to_string());

        let mut filters_as_strvec: Vec<&str> = filters_as_csv.split(",").collect();
        filters_as_strvec.resize(FILTERS_CAPACITY, "0");

        let mut filters: Filters = Vec::with_capacity(FILTERS_CAPACITY);
        for i in 0..FILTERS_CAPACITY {
            let filter: u8 = filters_as_strvec.get(i).unwrap_or(&"0").parse().unwrap();
            let filter = if filter >= 1 { true } else { false };
            filters.push(filter);
        }
        filters
    })
}
