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

use onet_cache::Index;
use onet_pools::PoolId;
use onet_records::EpochIndex;
use serde::{de::Deserializer, Deserialize};

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Params {
    #[serde(default = "default_index")]
    pub session: Index,
    #[serde(default)]
    pub pool: PoolId,
    #[serde(default)]
    pub number_last_sessions: u32,
    #[serde(default)]
    #[serde(deserialize_with = "parse_session")]
    pub from: EpochIndex,
    #[serde(default)]
    #[serde(deserialize_with = "parse_session")]
    pub to: EpochIndex,
    // show_metadata indicates whether metadata should be retrieved or not, default false
    #[serde(default)]
    pub show_metadata: bool,
    // show_stats indicates whether session stats should be retrieved or not, default false
    #[serde(default)]
    pub show_stats: bool,
    // show_netstats indicates whether session network stats should be retrieved or not, default false
    #[serde(default)]
    pub show_netstats: bool,
    // show_nominees indicates whether pool nominees should be retrieved or not, default false
    #[serde(default)]
    pub show_nominees: bool,
    // show_nomstats indicates whether pool nominees stats should be retrieved or not, default false
    #[serde(default)]
    pub show_nomstats: bool,
}

fn default_index() -> Index {
    Index::Current
}

fn parse_session<'de, D>(d: D) -> Result<EpochIndex, D::Error>
where
    D: Deserializer<'de>,
{
    Deserialize::deserialize(d).map(|x: Option<_>| {
        x.unwrap_or("".to_string())
            .parse::<EpochIndex>()
            .unwrap_or_default()
    })
}
