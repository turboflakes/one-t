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

use onet_mcda::criterias::{CriteriaFilters, CriteriaLimits, CriteriaWeights};
use onet_records::{BlockNumber, EpochIndex};
use serde::Serialize;
use subxt::ext::sp_core::H256;

#[derive(Debug, Serialize, PartialEq)]
pub struct MetaResult {
    pub limits: String,
}

impl Default for MetaResult {
    fn default() -> MetaResult {
        MetaResult {
            limits: String::default(),
        }
    }
}

#[derive(Debug, Serialize, PartialEq)]
pub struct BoardResult {
    pub hash: H256,
    pub session: EpochIndex,
    pub block_number: BlockNumber,
    pub addresses: Vec<String>,
    pub weights: CriteriaWeights,
    pub limits: CriteriaLimits,
    pub filters: CriteriaFilters,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct BoardsResult {
    pub data: Vec<BoardResult>,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct LimitsResult {
    pub session: EpochIndex,
    pub block_number: BlockNumber,
    pub limits: CriteriaLimits,
}
