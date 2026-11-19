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

use onet_cache::types::{ChainKey, Index};
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
    // metadata indicates whether metadata should be retrieved or not, default false
    // Note: `show_metadata` is deprecated, use `metadata`
    #[serde(default, alias = "show_metadata")]
    pub metadata: bool,
    // stats indicates whether session stats should be retrieved or not, default false
    // Note: `show_stats` is deprecated, use `stats`
    #[serde(default, alias = "show_stats")]
    pub stats: bool,
    // netstats indicates whether session network stats should be retrieved or not, default false
    // Note: `show_netstats` is deprecated, use `netstats`
    #[serde(default, alias = "show_netstats")]
    pub netstats: bool,
    // nominees indicates whether pool nominees should be retrieved or not, default false
    // Note: `show_nominees` is deprecated, use `nominees`
    #[serde(default, alias = "show_nominees")]
    pub nominees: bool,
    // nomstats indicates whether pool nominees stats should be retrieved or not, default false
    // Note: `show_nomstats` is deprecated, use `nomstats`
    #[serde(default, alias = "show_nomstats")]
    pub nomstats: bool,
    // chain_key is the chain of the sessions, default `rc`. For `ah` or `pp` the sessions are the parachain ones
    #[serde(default = "default_chain_key")]
    pub chain_key: ChainKey,
    // slot indicates whether the slot a parachain is in right now should be retrieved or not, default false
    // Note: only for the current session of `ah` or `pp`
    #[serde(default)]
    pub slot: bool,
    // collation_stats indicates whether session collation stats by parachain should be retrieved or not, default false
    #[serde(default)]
    pub collation_stats: bool,
}

fn default_chain_key() -> ChainKey {
    ChainKey::RC
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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::web::Query;

    #[test]
    fn stats_is_accepted_with_its_deprecated_name() {
        let p = Query::<Params>::from_query("stats=true").unwrap();
        assert!(p.stats);
        let p = Query::<Params>::from_query("show_stats=true").unwrap();
        assert!(p.stats);
        let p = Query::<Params>::from_query("from=1&to=2").unwrap();
        assert!(!p.stats);
        let p = Query::<Params>::from_query("show_netstats=true&nominees=true").unwrap();
        assert!(p.netstats && p.nominees && !p.nomstats && !p.metadata);
    }
}
