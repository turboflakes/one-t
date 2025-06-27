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

use onet_cache::types::ChainKey;
use onet_pools::{Pool, PoolCounter, PoolNominees, PoolNomineesStats, PoolState, PoolStats, Roles};
use onet_records::{
    AuthorityIndex, AuthorityRecord, BlockNumber, DiscoveryRecord, EpochIndex, EraIndex,
    NetworkSessionStats, ParaId, ParaStats, ParachainRecord, SessionStats, ValidatorProfileRecord,
    Validity,
};
use serde::{
    de::{Deserializer, MapAccess, Visitor},
    Deserialize, Serialize,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub type AuthorityKeyCache = BTreeMap<String, String>;
pub type CacheMap = BTreeMap<String, String>;

#[derive(Debug, Serialize, PartialEq, Clone)]
pub struct AuthorityKey {
    pub era_index: EraIndex,
    pub epoch_index: EpochIndex,
    pub authority_index: AuthorityIndex,
}

impl From<String> for AuthorityKey {
    fn from(data: String) -> Self {
        // example authority_key = e:{era}:s:{session}:a:{authority}
        // let key = String::from("e:1:s:123:a:555");
        let era_index: u32 = if let Some(a) = data.strip_prefix("e:") {
            if let Some(i) = a.find(":s") {
                let s = &a[..i];
                s.parse().unwrap_or_default()
            } else {
                0
            }
        } else {
            0
        };

        let prefix = format!("e:{era_index}:s:");
        let epoch_index: u32 = if let Some(a) = data.strip_prefix(&prefix) {
            if let Some(i) = a.find(":a") {
                let s = &a[..i];
                s.parse().unwrap_or_default()
            } else {
                0
            }
        } else {
            0
        };

        let prefix = format!("e:{era_index}:s:{epoch_index}:a:");
        let authority_index: u32 = if let Some(a) = data.strip_prefix(&prefix) {
            a.parse().unwrap_or_default()
        } else {
            0
        };

        AuthorityKey {
            era_index,
            epoch_index,
            authority_index,
        }
    }
}

impl From<AuthorityKeyCache> for AuthorityKey {
    fn from(data: AuthorityKeyCache) -> Self {
        let zero = "0".to_string();
        AuthorityKey {
            era_index: data
                .get("era")
                .unwrap_or(&zero)
                .parse::<EraIndex>()
                .unwrap_or_default(),
            epoch_index: data
                .get("session")
                .unwrap_or(&zero)
                .parse::<EpochIndex>()
                .unwrap_or_default(),
            authority_index: data
                .get("authority")
                .unwrap_or(&zero)
                .parse::<AuthorityIndex>()
                .unwrap_or_default(),
        }
    }
}

impl std::fmt::Display for AuthorityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "e:{}:s:{}:a:{}",
            self.era_index, self.epoch_index, self.authority_index
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BlockResult {
    // chain_key
    chain_key: ChainKey,
    // block_number
    block_number: BlockNumber,
    // is_finalized
    #[serde(skip_serializing_if = "default")]
    is_finalized: bool,
    // session stats
    #[serde(skip_serializing_if = "SessionStats::is_empty")]
    stats: SessionStats,
}

impl From<CacheMap> for BlockResult {
    fn from(data: CacheMap) -> Self {
        let zero = "0".to_string();
        let serialized = data.get("stats").unwrap_or(&"{}".to_string()).to_string();
        let stats: SessionStats = serde_json::from_str(&serialized).unwrap_or_default();
        BlockResult {
            chain_key: data
                .get("chain_key")
                .unwrap_or(&"{}".to_string())
                .parse::<ChainKey>()
                .unwrap_or_default(),
            block_number: data
                .get("block_number")
                .unwrap_or(&zero)
                .parse::<BlockNumber>()
                .unwrap_or_default(),
            is_finalized: data
                .get("is_finalized")
                .unwrap_or(&zero)
                .parse::<bool>()
                .unwrap_or_default(),
            stats,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BlocksResult {
    pub data: Vec<BlockResult>,
}

impl From<Vec<BlockResult>> for BlocksResult {
    fn from(data: Vec<BlockResult>) -> Self {
        BlocksResult { data }
    }
}

#[derive(Serialize, Debug)]
pub struct SessionResult {
    six: EpochIndex,
    eix: EraIndex,
    sbix: BlockNumber,
    ebix: BlockNumber,
    esix: u8,
    #[serde(skip_serializing_if = "default")]
    is_current: bool,
    #[serde(skip_serializing_if = "SessionStats::is_empty")]
    stats: SessionStats,
    #[serde(skip_serializing_if = "NetworkSessionStats::is_empty")]
    netstats: NetworkSessionStats,
    is_syncing: bool,
}

fn default<T: Default + PartialEq>(t: &T) -> bool {
    *t == Default::default()
}

impl From<CacheMap> for SessionResult {
    fn from(data: CacheMap) -> Self {
        let zero = "0".to_string();
        // stats
        let stats_serialized = data.get("stats").unwrap_or(&"{}".to_string()).to_string();
        let stats: SessionStats = serde_json::from_str(&stats_serialized).unwrap_or_default();
        // netstats
        let netstats_serialized = data
            .get("netstats")
            .unwrap_or(&"{}".to_string())
            .to_string();
        let netstats: NetworkSessionStats =
            serde_json::from_str(&netstats_serialized).unwrap_or_default();

        SessionResult {
            eix: data
                .get("era")
                .unwrap_or(&zero)
                .parse::<EraIndex>()
                .unwrap_or_default(),
            six: data
                .get("session")
                .unwrap_or(&zero)
                .parse::<EpochIndex>()
                .unwrap_or_default(),
            sbix: data
                .get("start_block")
                .unwrap_or(&zero)
                .parse::<BlockNumber>()
                .unwrap_or_default(),
            ebix: data
                .get("current_block")
                .unwrap_or(&zero)
                .parse::<BlockNumber>()
                .unwrap_or_default(),
            esix: data
                .get("era_session_index")
                .unwrap_or(&zero)
                .parse::<u8>()
                .unwrap_or_default(),
            is_current: data
                .get("is_current")
                .unwrap_or(&zero)
                .parse::<bool>()
                .unwrap_or_default(),
            is_syncing: data
                .get("is_syncing")
                .unwrap_or(&zero)
                .parse::<bool>()
                .unwrap_or_default(),
            stats,
            netstats,
        }
    }
}

// https://serde.rs/deserialize-struct.html
// NOTE: SessionResult is manually deserialized because some of the fields might not exist
// and rather than rasing error just set default values
//
impl<'de> Deserialize<'de> for SessionResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Six,
            Eix,
            Sbix,
            Ebix,
            Esix,
            IsCurrent,
            Stats,
            Netstats,
            IsSyncing,
        }

        struct SessionResultVisitor;

        impl<'de> Visitor<'de> for SessionResultVisitor {
            type Value = SessionResult;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct SessionResult")
            }

            fn visit_map<V>(self, mut map: V) -> Result<SessionResult, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut six: Option<EpochIndex> = None;
                let mut eix: Option<EraIndex> = None;
                let mut sbix: Option<BlockNumber> = None;
                let mut ebix: Option<BlockNumber> = None;
                let mut esix: Option<u8> = None;
                let mut is_current: Option<bool> = None;
                let mut stats: Option<SessionStats> = None;
                let mut netstats: Option<NetworkSessionStats> = None;
                let mut is_syncing: Option<bool> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Six => {
                            if six.is_some() {
                                return Err(serde::de::Error::duplicate_field("six"));
                            }
                            six = Some(map.next_value()?);
                        }
                        Field::Eix => {
                            if eix.is_some() {
                                return Err(serde::de::Error::duplicate_field("eix"));
                            }
                            eix = Some(map.next_value()?);
                        }
                        Field::Sbix => {
                            if sbix.is_some() {
                                return Err(serde::de::Error::duplicate_field("sbix"));
                            }
                            sbix = Some(map.next_value()?);
                        }
                        Field::Ebix => {
                            if ebix.is_some() {
                                return Err(serde::de::Error::duplicate_field("ebix"));
                            }
                            ebix = Some(map.next_value()?);
                        }
                        Field::Esix => {
                            if esix.is_some() {
                                return Err(serde::de::Error::duplicate_field("esix"));
                            }
                            esix = Some(map.next_value()?);
                        }
                        Field::IsCurrent => {
                            if is_current.is_some() {
                                return Err(serde::de::Error::duplicate_field("is_current"));
                            }
                            is_current = Some(map.next_value()?);
                        }
                        Field::Stats => {
                            if stats.is_some() {
                                return Err(serde::de::Error::duplicate_field("stats"));
                            }
                            stats = Some(map.next_value()?);
                        }
                        Field::Netstats => {
                            if netstats.is_some() {
                                return Err(serde::de::Error::duplicate_field("netstats"));
                            }
                            netstats = Some(map.next_value()?);
                        }
                        Field::IsSyncing => {
                            if is_syncing.is_some() {
                                return Err(serde::de::Error::duplicate_field("is_syncing"));
                            }
                            is_syncing = Some(map.next_value()?);
                        }
                    }
                }
                let six = six.unwrap_or_default();
                let eix = eix.unwrap_or_default();
                let sbix = sbix.unwrap_or_default();
                let ebix = ebix.unwrap_or_default();
                let esix = esix.unwrap_or_default();
                let is_current = is_current.unwrap_or_default();
                let stats = stats.unwrap_or_default();
                let netstats = netstats.unwrap_or_default();
                let is_syncing = is_syncing.unwrap_or_default();
                Ok(SessionResult::new(
                    six, eix, sbix, ebix, esix, is_current, stats, netstats, is_syncing,
                ))
            }
        }

        const FIELDS: &'static [&'static str] = &[
            "six",
            "eix",
            "sbix",
            "ebix",
            "esix",
            "is_current",
            "stats",
            "netstats",
            "is_syncing",
        ];
        deserializer.deserialize_struct("SessionResult", FIELDS, SessionResultVisitor)
    }
}

impl SessionResult {
    pub fn new(
        six: EpochIndex,
        eix: EraIndex,
        sbix: BlockNumber,
        ebix: BlockNumber,
        esix: u8,
        is_current: bool,
        stats: SessionStats,
        netstats: NetworkSessionStats,
        is_syncing: bool,
    ) -> Self {
        Self {
            six,
            eix,
            sbix,
            ebix,
            esix,
            is_current,
            stats,
            netstats,
            is_syncing,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SessionsResult {
    pub data: Vec<SessionResult>,
}

impl From<Vec<SessionResult>> for SessionsResult {
    fn from(data: Vec<SessionResult>) -> Self {
        SessionsResult { data }
    }
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ValidatorResult {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub address: String,
    #[serde(skip_serializing_if = "ValidatorProfileResult::is_empty")]
    pub profile: ValidatorProfileResult,
    #[serde(skip_serializing_if = "EpochIndex::is_empty")]
    pub session: EpochIndex,
    pub is_auth: bool,
    pub is_para: bool,
    #[serde(skip_serializing_if = "AuthorityRecord::is_empty")]
    pub auth: AuthorityRecord,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub para: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "ParaStats::is_empty")]
    pub para_summary: ParaStats,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub para_stats: BTreeMap<ParaId, ParaStats>,
    // P2P data
    #[serde(skip_serializing_if = "DiscoveryRecord::is_empty")]
    pub discovery: DiscoveryRecord,
    //
    #[serde(skip_serializing_if = "PoolCounter::is_empty")]
    pub pool_counter: PoolCounter,
    //
    #[serde(skip_serializing_if = "RankingStats::is_empty")]
    pub ranking: RankingStats,
}

// https://serde.rs/deserialize-struct.html
// NOTE: ValidatorResult is manually deserialized because some of the fields might not exist
// and rather than rasing error just set default values
//
impl<'de> Deserialize<'de> for ValidatorResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Address,
            Profile,
            Session,
            IsAuth,
            IsPara,
            Auth,
            Para,
            ParaSummary,
            ParaStats,
            Discovery,
            PoolCounter,
            Ranking,
        }

        struct ValidatorResultVisitor;

        impl<'de> Visitor<'de> for ValidatorResultVisitor {
            type Value = ValidatorResult;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct ValidatorResult")
            }

            fn visit_map<V>(self, mut map: V) -> Result<ValidatorResult, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut address: Option<String> = None;
                let mut profile: Option<ValidatorProfileResult> = None;
                let mut session: Option<EpochIndex> = None;
                let mut is_auth: Option<bool> = None;
                let mut is_para: Option<bool> = None;
                let mut auth: Option<AuthorityRecord> = None;
                let mut para: Option<BTreeMap<String, Value>> = None;
                let mut para_summary: Option<ParaStats> = None;
                let mut para_stats: Option<BTreeMap<ParaId, ParaStats>> = None;
                let mut discovery: Option<DiscoveryRecord> = None;
                let mut pool_counter: Option<PoolCounter> = None;
                let mut ranking: Option<RankingStats> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Address => {
                            if address.is_some() {
                                return Err(serde::de::Error::duplicate_field("address"));
                            }
                            address = Some(map.next_value()?);
                        }
                        Field::Profile => {
                            if profile.is_some() {
                                return Err(serde::de::Error::duplicate_field("profile"));
                            }
                            profile = Some(map.next_value()?);
                        }
                        Field::Session => {
                            if session.is_some() {
                                return Err(serde::de::Error::duplicate_field("session"));
                            }
                            session = Some(map.next_value()?);
                        }
                        Field::IsAuth => {
                            if is_auth.is_some() {
                                return Err(serde::de::Error::duplicate_field("is_auth"));
                            }
                            is_auth = Some(map.next_value()?);
                        }
                        Field::IsPara => {
                            if is_para.is_some() {
                                return Err(serde::de::Error::duplicate_field("is_para"));
                            }
                            is_para = Some(map.next_value()?);
                        }
                        Field::Auth => {
                            if auth.is_some() {
                                return Err(serde::de::Error::duplicate_field("auth"));
                            }
                            auth = Some(map.next_value()?);
                        }
                        Field::Para => {
                            if para.is_some() {
                                return Err(serde::de::Error::duplicate_field("para"));
                            }
                            para = Some(map.next_value()?);
                        }
                        Field::ParaSummary => {
                            if para_summary.is_some() {
                                return Err(serde::de::Error::duplicate_field("para_summary"));
                            }
                            para_summary = Some(map.next_value()?);
                        }
                        Field::ParaStats => {
                            if para_stats.is_some() {
                                return Err(serde::de::Error::duplicate_field("para_stats"));
                            }
                            para_stats = Some(map.next_value()?);
                        }
                        Field::Discovery => {
                            if discovery.is_some() {
                                return Err(serde::de::Error::duplicate_field("discovery"));
                            }
                            discovery = Some(map.next_value()?);
                        }
                        Field::PoolCounter => {
                            if pool_counter.is_some() {
                                return Err(serde::de::Error::duplicate_field("pool_counter"));
                            }
                            pool_counter = Some(map.next_value()?);
                        }
                        Field::Ranking => {
                            if ranking.is_some() {
                                return Err(serde::de::Error::duplicate_field("ranking"));
                            }
                            ranking = Some(map.next_value()?);
                        }
                    }
                }
                let address = address.unwrap_or_default();
                let profile = profile.unwrap_or_default();
                let session = session.unwrap_or_default();
                let is_auth = is_auth.unwrap_or_default();
                let is_para = is_para.unwrap_or_default();
                let auth = auth.unwrap_or_default();
                let para = para.unwrap_or_default();
                let para_summary = para_summary.unwrap_or_default();
                let para_stats = para_stats.unwrap_or_default();
                let discovery = discovery.unwrap_or_default();
                let pool_counter = pool_counter.unwrap_or_default();
                let ranking = ranking.unwrap_or_default();
                Ok(ValidatorResult::new(
                    address,
                    profile,
                    session,
                    is_auth,
                    is_para,
                    auth,
                    para,
                    para_summary,
                    para_stats,
                    discovery,
                    pool_counter,
                    ranking,
                ))
            }
        }

        const FIELDS: &'static [&'static str] = &[
            "address",
            "profile",
            "session",
            "is_auth",
            "is_para",
            "auth",
            "para",
            "para_summary",
            "para_stats",
            "discovery",
            "pool_counter",
            "ranking",
        ];
        deserializer.deserialize_struct("ValidatorResult", FIELDS, ValidatorResultVisitor)
    }
}

impl ValidatorResult {
    pub fn new(
        address: String,
        profile: ValidatorProfileResult,
        session: EpochIndex,
        is_auth: bool,
        is_para: bool,
        auth: AuthorityRecord,
        para: BTreeMap<String, Value>,
        para_summary: ParaStats,
        para_stats: BTreeMap<ParaId, ParaStats>,
        discovery: DiscoveryRecord,
        pool_counter: PoolCounter,
        ranking: RankingStats,
    ) -> Self {
        Self {
            address,
            profile,
            session,
            is_auth,
            is_para,
            auth,
            para,
            para_summary,
            para_stats,
            discovery,
            pool_counter,
            ranking,
        }
    }

    pub fn with_address(address: String) -> Self {
        Self {
            address,
            ..Default::default()
        }
    }
}

impl From<CacheMap> for ValidatorResult {
    fn from(data: CacheMap) -> Self {
        let zero = "0".to_string();

        let serialized = data.get("auth").unwrap_or(&"{}".to_string()).to_string();
        let auth: AuthorityRecord = serde_json::from_str(&serialized).unwrap_or_default();

        let serialized = data.get("para").unwrap_or(&"{}".to_string()).to_string();
        let mut para: BTreeMap<String, Value> = serde_json::from_str(&serialized).unwrap();
        // NOTE: bitfields.uat is not being currently used on the frontend, so let's skip it for now as the response size increases a lot
        if let Some(bitfields) = para.get_mut("bitfields") {
            if let Some(obj) = bitfields.as_object_mut() {
                obj.remove("uat");
            }
        }

        // para_summary
        let serialized = data
            .get("para_summary")
            .unwrap_or(&"{}".to_string())
            .to_string();
        let para_summary: ParaStats = serde_json::from_str(&serialized).unwrap_or_default();

        // para_stats
        let serialized = data
            .get("para_stats")
            .unwrap_or(&"{}".to_string())
            .to_string();
        let para_stats: BTreeMap<ParaId, ParaStats> =
            serde_json::from_str(&serialized).unwrap_or_default();

        // discovery
        let serialized = data
            .get("discovery")
            .unwrap_or(&"{}".to_string())
            .to_string();
        let discovery: DiscoveryRecord = serde_json::from_str(&serialized).unwrap_or_default();

        // profile
        let serialized = data.get("profile").unwrap_or(&"{}".to_string()).to_string();
        let profile: ValidatorProfileResult = serialized.into();

        ValidatorResult {
            is_auth: !auth.is_empty(),
            is_para: !para.is_empty(),
            address: data.get("address").unwrap_or(&"".to_string()).to_string(),
            profile,
            session: data
                .get("session")
                .unwrap_or(&zero)
                .parse::<EpochIndex>()
                .unwrap_or_default(),
            auth,
            para,
            para_summary,
            para_stats,
            discovery,
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize, Default)]
pub struct ValidatorsResult {
    #[serde(skip_serializing_if = "EpochIndex::is_empty")]
    pub session: EpochIndex,
    pub data: Vec<ValidatorResult>,
}

// Validator RankingStats
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct RankingStats {
    pub score: u32,
    pub mvr: f64,
    pub avg_para_points: u32,
    pub para_epochs: u32,
}

impl RankingStats {
    pub fn with(score: u32, mvr: f64, avg_para_points: u32, para_epochs: u32) -> Self {
        Self {
            score,
            mvr,
            avg_para_points,
            para_epochs,
        }
    }
}

impl Validity for RankingStats {
    fn is_empty(&self) -> bool {
        self.score == 0 && self.mvr == 0.0 && self.avg_para_points == 0 && self.para_epochs == 0
    }
}

// Parachains
pub type ParachainResult = ParachainRecord;

#[derive(Debug, Serialize)]
pub struct ParachainsResult {
    #[serde(skip_serializing_if = "EpochIndex::is_empty")]
    pub session: EpochIndex,
    pub data: Vec<ParachainResult>,
}

impl From<CacheMap> for ParachainsResult {
    fn from(data: CacheMap) -> Self {
        let zero = "0".to_string();

        let mut out: Vec<ParachainResult> = Vec::new();
        for (para_id, serialized) in data.iter() {
            if para_id == "session" {
                continue;
            }
            out.push(serialized.into());
        }

        ParachainsResult {
            session: data
                .get("session")
                .unwrap_or(&zero)
                .parse::<EpochIndex>()
                .unwrap_or_default(),
            data: out,
        }
    }
}

pub type ValidatorProfileResult = ValidatorProfileRecord;

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ValidatorGradeResult {
    pub address: String,
    pub grade: String,
    pub authority_inclusion: f64,
    pub para_authority_inclusion: f64,
    pub explicit_votes_total: u32,
    pub implicit_votes_total: u32,
    pub missed_votes_total: u32,
    pub bitfields_availability_total: u32,
    pub bitfields_unavailability_total: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sessions: Vec<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sessions_data: Vec<ValidatorResult>,
}

pub type NetworkStatResult = NetworkSessionStats;

#[derive(Debug, Serialize, Default)]
pub struct NetworkStatsResult {
    pub data: Vec<NetworkStatResult>,
}

impl From<Vec<NetworkStatResult>> for NetworkStatsResult {
    fn from(data: Vec<NetworkStatResult>) -> Self {
        NetworkStatsResult { data }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct PoolResult {
    id: u32,
    #[serde(skip_serializing_if = "String::is_empty")]
    metadata: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    roles: Option<Roles>,
    #[serde(skip_serializing_if = "PoolState::is_not_defined")]
    state: PoolState,
    #[serde(skip_serializing_if = "EpochIndex::is_empty")]
    pub session: EpochIndex,
    #[serde(skip_serializing_if = "BlockNumber::is_empty")]
    block_number: BlockNumber,
    #[serde(skip_serializing_if = "PoolStats::is_empty")]
    pub stats: PoolStats,
    #[serde(skip_serializing_if = "PoolNominees::is_empty")]
    pub nominees: PoolNominees,
    #[serde(skip_serializing_if = "PoolNomineesStats::is_empty")]
    pub nomstats: PoolNomineesStats,
}

impl From<Pool> for PoolResult {
    fn from(data: Pool) -> Self {
        PoolResult {
            id: data.id,
            metadata: data.metadata,
            roles: data.roles,
            state: data.state,
            block_number: data.block_number,
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PoolsResult {
    pub data: Vec<PoolResult>,
}

impl From<Vec<PoolResult>> for PoolsResult {
    fn from(data: Vec<PoolResult>) -> Self {
        PoolsResult { data }
    }
}

// Cohorts
#[derive(Debug, Serialize, Default)]
pub struct CohortsResult {
    pub data: Vec<u32>,
}

#[derive(Debug, Serialize, Default)]
pub struct CohortValidatorsGradesResult {
    pub cohort: u32,
    pub data: Vec<ValidatorGradeResult>,
}

// Eras
#[derive(Debug, Serialize, Default)]
pub struct ErasResult {
    pub data: Vec<u32>,
}

#[derive(Debug, Serialize, Default)]
pub struct EraValidatorsGradesResult {
    pub era: u32,
    pub sessions: Vec<u32>,
    pub data: Vec<ValidatorGradeResult>,
}
