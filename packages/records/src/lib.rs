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

pub mod collators;

use collators::{CollatorRecord, ParaSlots};
use log::info;
use onet_config::CONFIG;
use serde::{Deserialize, Serialize};

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    convert::TryInto,
    hash::Hash,
    net::IpAddr,
};
use subxt::utils::AccountId32;

/// NOTE: Assumption of the number of decimals in scores or limits
pub const DECIMALS: u32 = 7;

pub type UserID = String;
pub type BlockNumber = u64;
pub type Param = String;
pub type EraIndex = u32;
pub type EpochIndex = u32;
pub type GroupIndex = u32;
pub type CoreIndex = u32;
pub type AuthorityIndex = u32;
pub type ParaIndex = u32;
pub type ParaId = u32;
pub type Points = u32;
pub type AuthoredBlocks = u32;
pub type TotalActiveEpochs = u32;
pub type TotalParaEpochs = u32;
pub type TotalFlaggedEpochs = u32;
pub type TotalExceptionalEpochs = u32;
pub type Votes = u32;
pub type ExplicitVotes = u32;
pub type ImplicitVotes = u32;
pub type MissedVotes = u32;
pub type CoreAssignments = u32;
pub type BitfieldsAvailability = u32;
pub type BitfieldsUnavailability = u32;
pub type Ratio = f64;
pub type ParaEpochs = Vec<EpochIndex>;
pub type Pattern = Vec<Glyph>;
pub type FlaggedEpochs = Vec<EpochIndex>;
// pub type RecordKey = String;
pub type SS58 = String;
pub type DisputeKind = String;
pub type AuthorityDiscoveryKey = [u8; 32];
pub type PreviousEpochsData = (
    bool,
    Option<(
        TotalParaEpochs,
        TotalExceptionalEpochs,
        TotalFlaggedEpochs,
        Ratio,
    )>,
);
pub type FullEpochsData = (
    (TotalActiveEpochs, AuthoredBlocks, Pattern),
    Option<(
        TotalParaEpochs,
        Points,
        ExplicitVotes,
        ImplicitVotes,
        MissedVotes,
        CoreAssignments,
        BitfieldsAvailability,
        BitfieldsUnavailability,
    )>,
);
pub type BlockNumberTuple = (BlockNumber, BlockNumber);

// Keys to be easily used in BTreeMap
// DEPRECATE as EpochKey(pub EraIndex, pub EpochIndex)
// #[derive(Debug, Clone, Hash, Eq, PartialEq)]
// pub struct EpochKey(pub EraIndex, pub EpochIndex);
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct EpochKey(pub EpochIndex);
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct RecordKey(EpochKey, AuthorityIndex);
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct AddressKey(EpochKey, SS58);
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct CollatorKey(ParaId, EpochKey, SS58);
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct BlockKey(EpochKey, BlockKind);
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct PublicKey(EpochKey, String);

pub trait Validity {
    fn is_empty(&self) -> bool;
}

impl Validity for BlockNumber {
    fn is_empty(&self) -> bool {
        *self == 0
    }
}

impl Validity for EpochIndex {
    fn is_empty(&self) -> bool {
        *self == 0
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
enum BlockKind {
    Start,
    End,
    Best,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, PartialOrd)]
pub enum Glyph {
    Waiting,
    Active,
    ActivePVL0,
    ActivePVL1,
    ActivePVL2,
    ActivePVL3,
    ActivePVL4,
    ActivePVidle,
    NA,
}

impl Glyph {
    pub fn from_mvr(ratio: Ratio) -> Self {
        let config = CONFIG.clone();
        let rounded: Option<u32> = Some((ratio * 10000.0).round() as u32);
        match rounded {
            Some(r) if r > config.mvr_level_4 => Glyph::ActivePVL4,
            Some(r) if r > config.mvr_level_3 => Glyph::ActivePVL3,
            Some(r) if r > config.mvr_level_2 => Glyph::ActivePVL2,
            Some(r) if r > config.mvr_level_1 => Glyph::ActivePVL1,
            _ => Glyph::ActivePVL0,
        }
    }

    pub fn level(&self) -> String {
        match self {
            Self::ActivePVL0 => "Excellent".to_string(),
            Self::ActivePVL1 => "Very Good".to_string(),
            Self::ActivePVL2 => "Good".to_string(),
            Self::ActivePVL3 => "Low".to_string(),
            Self::ActivePVL4 => "Very Low".to_string(),
            _ => "NA".to_string(),
        }
    }
}

impl std::fmt::Display for Glyph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Waiting => write!(f, "_"),
            Self::Active => write!(f, "•"),
            Self::ActivePVL0 => write!(f, "❚"),
            Self::ActivePVL1 => write!(f, "❙"),
            Self::ActivePVL2 => write!(f, "❘"),
            Self::ActivePVL3 => write!(f, "!"),
            Self::ActivePVL4 => write!(f, "¿"),
            Self::ActivePVidle => write!(f, "?"),
            Self::NA => write!(f, ""),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Eq, PartialEq, PartialOrd, Default)]
pub enum Grade {
    Ap,
    A,
    Bp,
    B,
    Cp,
    C,
    Dp,
    D,
    F,
    #[default]
    NA,
}

impl Grade {
    pub fn leading_spaces(&self, leading_spaces: usize) -> String {
        match self {
            Self::Ap => format!("{:width$}A+", "", width = leading_spaces),
            Self::A => format!("{:width$}A", "", width = leading_spaces + 1),
            Self::Bp => format!("{:width$}B+", "", width = leading_spaces),
            Self::B => format!("{:width$}B", "", width = leading_spaces + 1),
            Self::Cp => format!("{:width$}C+", "", width = leading_spaces),
            Self::C => format!("{:width$}C", "", width = leading_spaces + 1),
            Self::Dp => format!("{:width$}D+", "", width = leading_spaces),
            Self::D => format!("{:width$}D", "", width = leading_spaces + 1),
            Self::F => format!("{:width$}F", "", width = leading_spaces + 1),
            Self::NA => format!("{:width$}-", "", width = leading_spaces + 1),
        }
    }
}

impl std::fmt::Display for Grade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ap => write!(f, "A+"),
            Self::A => write!(f, "A"),
            Self::Bp => write!(f, "B+"),
            Self::B => write!(f, "B"),
            Self::Cp => write!(f, "C+"),
            Self::C => write!(f, "C"),
            Self::Dp => write!(f, "D+"),
            Self::D => write!(f, "D"),
            Self::F => write!(f, "F"),
            Self::NA => write!(f, "-"),
        }
    }
}

/// Grade of a validator based on the missed votes ratio (`mvr`), the bitfields unavailability
/// ratio (`bur`) and, if the validator also collated, the missed collation ratio (`mcr`).
pub fn grade(mvr: f64, bur: f64, mcr: Option<f64>) -> Grade {
    let ratio = match mcr {
        Some(mcr) => 1.0_f64 - (mvr * 0.6 + bur * 0.15 + mcr * 0.25),
        None => 1.0_f64 - (mvr * 0.75 + bur * 0.25),
    };
    grade_from_ratio(ratio)
}

/// Grade of a validator that only collated, based on the missed collation ratio (`mcr`).
pub fn collation_grade(mcr: f64) -> Grade {
    grade_from_ratio(1.0_f64 - mcr)
}

fn grade_from_ratio(ratio: f64) -> Grade {
    let p = (ratio * 10000.0).round() as u32;
    match p {
        9901..=10000 => Grade::Ap,
        9501..=9900 => Grade::A,
        9001..=9500 => Grade::Bp,
        8001..=9000 => Grade::B,
        7001..=8000 => Grade::Cp,
        6001..=7000 => Grade::C,
        5001..=6000 => Grade::Dp,
        4001..=5000 => Grade::D,
        _ => Grade::F,
    }
}

#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Subset {
    TVP,
    #[default]
    NONTVP,
    C100,
    NotDefined,
}

impl std::fmt::Display for Subset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TVP => write!(f, "TVP"),
            Self::NONTVP => write!(f, "OTH"),
            Self::C100 => write!(f, "100C"),
            Self::NotDefined => write!(f, "NotDefined"),
        }
    }
}

/// What is pending to be cached, and what is already cached, of the collators of a parachain
#[derive(Debug, Clone, Default)]
struct ParaCacheState {
    // collator records changed since the last time they were cached:
    // (parachain session, relay session, address)
    dirty: BTreeSet<(EpochIndex, EpochIndex, SS58)>,
    // parachain session and relay session for which the collators already have a record
    seeded: Option<(EpochIndex, EpochIndex)>,
    // draw of validators last cached: (parachain session, relay session, authorities)
    draw: Option<(EpochIndex, EpochIndex, BTreeSet<AuthorityIndex>)>,
}

#[derive(Debug, Clone)]
pub struct Records {
    current_era: EraIndex,
    current_epoch: EpochIndex,
    first_epoch: EpochIndex,
    eras: HashMap<EpochIndex, EraIndex>,
    blocks: HashMap<BlockKey, BlockNumber>,
    ah_blocks: HashMap<BlockKey, BlockNumberTuple>,
    authorities: HashMap<EpochKey, HashSet<AuthorityIndex>>,
    addresses: HashMap<AddressKey, AuthorityIndex>,
    authority_records: HashMap<RecordKey, AuthorityRecord>,
    para_authorities: HashMap<EpochKey, HashSet<AuthorityIndex>>,
    para_records: HashMap<RecordKey, ParaRecord>,
    discovery_records: HashMap<RecordKey, DiscoveryRecord>,
    // Note: we use the following maps to easily manage missed votes and para_id assignment changes and core assignments
    core_para: HashMap<CoreIndex, Option<ParaId>>,
    para_group: HashMap<ParaId, GroupIndex>,
    groups: HashMap<GroupIndex, Vec<AuthorityIndex>>,
    authority_discovery_keys: HashMap<PublicKey, AuthorityIndex>,
    // Note: collator records are keyed by parachain, parachain session and collator address
    collator_records: HashMap<CollatorKey, CollatorRecord>,
    // Note: same counters keyed by the relay chain session in which the slots closed,
    // to be easily served alongside the relay chain authorities
    collator_epoch_records: HashMap<CollatorKey, CollatorRecord>,
    // first and last parachain block tracked by parachain session
    para_session_blocks: HashMap<(ParaId, EpochIndex), (BlockNumber, BlockNumber)>,
    // era of the parachain sessions
    para_session_era: HashMap<(ParaId, EpochIndex), EraIndex>,
    // first parachain session known of an era, to tell the position of a session in its era
    para_era_first_session: HashMap<(ParaId, EraIndex), EpochIndex>,
    // first and last parachain block tracked by relay session
    para_epoch_blocks: HashMap<(ParaId, EpochIndex), (BlockNumber, BlockNumber)>,
    para_slots: HashMap<ParaId, ParaSlots>,
    // collator data pending to be cached, and already cached, by parachain
    para_cache: HashMap<ParaId, ParaCacheState>,
}

impl Records {
    pub fn with_era_epoch_and_block(
        current_era: EraIndex,
        current_epoch: EpochIndex,
        start_block: BlockNumber,
    ) -> Self {
        let mut blocks = HashMap::new();
        blocks.insert(
            BlockKey(EpochKey(current_epoch), BlockKind::Start),
            start_block,
        );
        let mut eras = HashMap::new();
        eras.insert(current_epoch, current_era);
        Self {
            current_era,
            current_epoch,
            first_epoch: current_epoch,
            eras: HashMap::new(),
            blocks,
            ah_blocks: HashMap::new(),
            authorities: HashMap::new(),
            addresses: HashMap::new(),
            authority_records: HashMap::new(),
            para_authorities: HashMap::new(),
            para_records: HashMap::new(),
            discovery_records: HashMap::new(),
            core_para: HashMap::new(),
            para_group: HashMap::new(),
            groups: HashMap::new(),
            authority_discovery_keys: HashMap::new(),
            collator_records: HashMap::new(),
            collator_epoch_records: HashMap::new(),
            para_session_blocks: HashMap::new(),
            para_session_era: HashMap::new(),
            para_era_first_session: HashMap::new(),
            para_epoch_blocks: HashMap::new(),
            para_slots: HashMap::new(),
            para_cache: HashMap::new(),
        }
    }

    pub fn para_slots(&self, para_id: ParaId) -> Option<&ParaSlots> {
        self.para_slots.get(&para_id)
    }

    pub fn para_slots_mut(&mut self, para_id: ParaId) -> &mut ParaSlots {
        self.para_slots.entry(para_id).or_default()
    }

    /// Track a parachain block and add the slots it closes to the collator records
    pub fn track_para_block(
        &mut self,
        para_id: ParaId,
        number: BlockNumber,
        slot: collators::Slot,
    ) {
        let epoch = self.current_epoch;
        let closed_slots = self.para_slots_mut(para_id).on_block(number, slot);
        self.seed_collators(para_id);
        // Note: the session is set before the block of a new session is tracked
        if let Some(session) = self.para_slots(para_id).and_then(|t| t.session()) {
            Self::extend_blocks(
                &mut self.para_session_blocks,
                (para_id, session),
                number,
                number,
            );
        }
        Self::extend_blocks(
            &mut self.para_epoch_blocks,
            (para_id, epoch),
            number,
            number,
        );
        for closed in closed_slots {
            let Some((account, kind)) = closed.owner else {
                continue;
            };
            let address = account.to_string();
            for (records, index) in [
                (&mut self.collator_records, closed.session),
                (&mut self.collator_epoch_records, epoch),
            ] {
                let record = records
                    .entry(CollatorKey(para_id, EpochKey(index), address.clone()))
                    .or_insert_with(|| CollatorRecord::new(address.clone(), kind));
                record.add_slot(
                    closed.slot,
                    &closed.blocks,
                    closed.expected_blocks,
                    closed.points_per_block,
                );
                record.set_cix(closed.owner_index);
            }
            self.para_cache.entry(para_id).or_default().dirty.insert((
                closed.session,
                epoch,
                address,
            ));
        }
    }

    /// Give every collator of the session a record, even before it owns a slot, so they are all
    /// known (and their position) from the start. Records already there are kept.
    /// Note: it is done once by parachain session and relay session
    fn seed_collators(&mut self, para_id: ParaId) {
        let epoch = self.current_epoch;
        let Some(slots) = self.para_slots.get(&para_id) else {
            return;
        };
        let Some(session) = slots.session() else {
            return;
        };
        let cache = self.para_cache.entry(para_id).or_default();
        if cache.seeded == Some((session, epoch)) {
            return;
        }
        let collators: Vec<(SS58, collators::CollatorKind)> = slots
            .collators()
            .iter()
            .map(|(account, kind)| (account.to_string(), *kind))
            .collect();
        for (cix, (address, kind)) in collators.into_iter().enumerate() {
            for (records, index) in [
                (&mut self.collator_records, session),
                (&mut self.collator_epoch_records, epoch),
            ] {
                records
                    .entry(CollatorKey(para_id, EpochKey(index), address.clone()))
                    .or_insert_with(|| CollatorRecord::new(address.clone(), kind))
                    .set_cix(Some(cix as u32));
            }
            self.para_cache
                .entry(para_id)
                .or_default()
                .dirty
                .insert((session, epoch, address));
        }
        self.para_cache.entry(para_id).or_default().seeded = Some((session, epoch));
    }

    fn extend_blocks(
        blocks: &mut HashMap<(ParaId, EpochIndex), (BlockNumber, BlockNumber)>,
        key: (ParaId, EpochIndex),
        start: BlockNumber,
        end: BlockNumber,
    ) {
        let range = blocks.entry(key).or_insert((start, end));
        range.0 = range.0.min(start);
        range.1 = range.1.max(end);
    }

    /// Set the era of a parachain session, kept if it was already set.
    /// Note: the session is the first of its era only if the session before is known to be in another era,
    /// otherwise, e.g. after a restart in the middle of an era, its position in the era is not known.
    pub fn set_para_session_era(&mut self, para_id: ParaId, session: EpochIndex, era: EraIndex) {
        self.para_session_era
            .entry((para_id, session))
            .or_insert(era);
        let previous_era = session
            .checked_sub(1)
            .and_then(|s| self.para_session_era.get(&(para_id, s)));
        if previous_era.is_some_and(|previous| *previous != era) {
            self.para_era_first_session
                .entry((para_id, era))
                .or_insert(session);
        }
    }

    /// Resume the era of a parachain session read from the cache, and its position in the era if it was known
    pub fn seed_para_session_era(
        &mut self,
        para_id: ParaId,
        session: EpochIndex,
        era: EraIndex,
        esix: Option<u32>,
    ) {
        self.para_session_era
            .entry((para_id, session))
            .or_insert(era);
        if let Some(first) = esix.and_then(|e| session.checked_sub(e)) {
            self.para_era_first_session
                .entry((para_id, era))
                .or_insert(first);
        }
    }

    /// Resume the block range of a parachain session read from the cache
    pub fn seed_para_session_blocks(
        &mut self,
        para_id: ParaId,
        session: EpochIndex,
        start: BlockNumber,
        end: BlockNumber,
    ) {
        Self::extend_blocks(
            &mut self.para_session_blocks,
            (para_id, session),
            start,
            end,
        );
    }

    /// Resume the block range of a parachain in a relay session read from the cache
    pub fn seed_para_epoch_blocks(
        &mut self,
        para_id: ParaId,
        epoch: EpochIndex,
        start: BlockNumber,
        end: BlockNumber,
    ) {
        Self::extend_blocks(&mut self.para_epoch_blocks, (para_id, epoch), start, end);
    }

    /// Validators drawn as collators of a parachain that are authorities of the current relay
    /// session, with their position in the parachain collators (authority index, collation index)
    pub fn collator_draw(&self, para_id: ParaId) -> Vec<(AuthorityIndex, u32)> {
        let Some(slots) = self.para_slots(para_id) else {
            return Vec::new();
        };
        slots
            .collators()
            .iter()
            .enumerate()
            .filter(|(_, (_, kind))| *kind == collators::CollatorKind::Validator)
            .filter_map(|(cix, (account, _))| {
                self.get_authority_index_by_address(&account.to_string(), self.current_epoch)
                    .map(|authority_index| (authority_index, cix as u32))
            })
            .collect()
    }

    /// Whether the authorities of the current relay session were already inserted
    pub fn has_authorities(&self) -> bool {
        self.authorities
            .get(&EpochKey(self.current_epoch))
            .is_some_and(|a| !a.is_empty())
    }

    /// Draw of a parachain last cached: (parachain session, relay session, authorities)
    pub fn cached_collator_draw(
        &self,
        para_id: ParaId,
    ) -> Option<&(EpochIndex, EpochIndex, BTreeSet<AuthorityIndex>)> {
        self.para_cache.get(&para_id).and_then(|c| c.draw.as_ref())
    }

    pub fn set_cached_collator_draw(
        &mut self,
        para_id: ParaId,
        session: EpochIndex,
        epoch: EpochIndex,
        authorities: BTreeSet<AuthorityIndex>,
    ) {
        self.para_cache.entry(para_id).or_default().draw = Some((session, epoch, authorities));
    }

    /// Collator records (parachain session, relay session, address) changed since last cleared
    pub fn dirty_collators(&self, para_id: ParaId) -> Vec<(EpochIndex, EpochIndex, SS58)> {
        self.para_cache
            .get(&para_id)
            .map(|c| c.dirty.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn clear_dirty_collators(&mut self, para_id: ParaId) {
        if let Some(cache) = self.para_cache.get_mut(&para_id) {
            cache.dirty.clear();
        }
    }

    /// Insert a collator record read from the cache, used to resume after a restart
    pub fn insert_collator_record(
        &mut self,
        para_id: ParaId,
        session: EpochIndex,
        record: CollatorRecord,
    ) {
        self.collator_records.insert(
            CollatorKey(para_id, EpochKey(session), record.address().clone()),
            record,
        );
    }

    /// Insert a collator record per relay session read from the cache
    pub fn insert_collator_epoch_record(
        &mut self,
        para_id: ParaId,
        epoch: EpochIndex,
        record: CollatorRecord,
    ) {
        self.collator_epoch_records.insert(
            CollatorKey(para_id, EpochKey(epoch), record.address().clone()),
            record,
        );
    }

    /// Counters of the collators of a parachain session
    pub fn collator_session_stats(
        &self,
        para_id: ParaId,
        session: EpochIndex,
    ) -> collators::CollatorSessionStats {
        let mut stats = collators::CollatorSessionStats::default();
        for (key, record) in self.collator_records.iter() {
            if key.0 == para_id && key.1 == EpochKey(session) {
                stats.add(record);
            }
        }
        if let Some((start, end)) = self.para_session_blocks.get(&(para_id, session)) {
            stats.sbix = *start;
            stats.ebix = *end;
        }
        stats.eix = self.para_session_era.get(&(para_id, session)).copied();
        stats.esix = stats.eix.and_then(|era| {
            let first = self.para_era_first_session.get(&(para_id, era))?;
            session.checked_sub(*first)
        });
        stats
    }

    /// Counters of the collators of a parachain in a relay chain session
    pub fn collator_epoch_stats(
        &self,
        para_id: ParaId,
        epoch: EpochIndex,
    ) -> collators::CollatorSessionStats {
        let mut stats = collators::CollatorSessionStats::default();
        for (key, record) in self.collator_epoch_records.iter() {
            if key.0 == para_id && key.1 == EpochKey(epoch) {
                stats.add(record);
            }
        }
        if let Some((start, end)) = self.para_epoch_blocks.get(&(para_id, epoch)) {
            stats.sbix = *start;
            stats.ebix = *end;
        }
        stats
    }

    pub fn get_collator_epoch_record(
        &self,
        para_id: ParaId,
        epoch: EpochIndex,
        address: &str,
    ) -> Option<&CollatorRecord> {
        self.collator_epoch_records
            .get(&CollatorKey(para_id, EpochKey(epoch), address.to_string()))
    }

    /// Relay chain authority index of an address, if active in the relay session
    pub fn get_authority_index_by_address(
        &self,
        address: &str,
        epoch: EpochIndex,
    ) -> Option<AuthorityIndex> {
        self.addresses
            .get(&AddressKey(EpochKey(epoch), address.to_string()))
            .copied()
    }

    pub fn get_collator_record(
        &self,
        para_id: ParaId,
        session: EpochIndex,
        address: &str,
    ) -> Option<&CollatorRecord> {
        self.collator_records.get(&CollatorKey(
            para_id,
            EpochKey(session),
            address.to_string(),
        ))
    }

    pub fn get_collator_records(
        &self,
        para_id: ParaId,
        session: EpochIndex,
    ) -> impl Iterator<Item = &CollatorRecord> {
        self.collator_records
            .iter()
            .filter(move |(k, _)| k.0 == para_id && k.1 == EpochKey(session))
            .map(|(_, r)| r)
    }

    pub fn current_era(&self) -> EraIndex {
        self.current_era
    }

    pub fn is_first_epoch(&self, index: EpochIndex) -> bool {
        self.first_epoch == index
    }

    pub fn total_full_epochs(&self) -> u32 {
        // NOTE: first_epoch and current_epoch should not count as a full recorded sessions
        if self.current_epoch - self.first_epoch <= 1 {
            return 0;
        }
        let epochs = self.current_epoch - self.first_epoch - 1;
        let config = CONFIG.clone();
        if epochs > config.maximum_history_eras * 6 {
            config.maximum_history_eras * 6
        } else {
            epochs
        }
    }

    pub fn total_full_eras(&self) -> u32 {
        self.total_full_epochs() / 6
    }

    pub fn current_epoch(&self) -> EpochIndex {
        self.current_epoch
    }

    pub fn start_block(&self, epoch_key: Option<EpochKey>) -> Option<&BlockNumber> {
        if let Some(epoch_key) = epoch_key {
            self.blocks.get(&BlockKey(epoch_key, BlockKind::Start))
        } else {
            let epoch_key = EpochKey(self.current_epoch);
            self.blocks.get(&BlockKey(epoch_key, BlockKind::Start))
        }
    }

    pub fn end_block(&self, epoch_key: Option<EpochKey>) -> Option<&BlockNumber> {
        if let Some(epoch_key) = epoch_key {
            self.blocks.get(&BlockKey(epoch_key, BlockKind::End))
        } else {
            let epoch_key = EpochKey(self.current_epoch);
            self.blocks.get(&BlockKey(epoch_key, BlockKind::End))
        }
    }

    // deprecated: use finalized_block
    pub fn _current_block(&self) -> Option<&BlockNumber> {
        let block = self.end_block(Some(EpochKey(self.current_epoch)));
        if block.is_none() {
            return self.start_block(Some(EpochKey(self.current_epoch)));
        }
        block
    }

    pub fn finalized_block(&self) -> Option<&BlockNumber> {
        let block = self.end_block(Some(EpochKey(self.current_epoch)));
        if block.is_none() {
            return self.start_block(Some(EpochKey(self.current_epoch)));
        }
        block
    }

    pub fn best_block(&self) -> Option<&BlockNumber> {
        let epoch_key = EpochKey(self.current_epoch);
        self.blocks.get(&BlockKey(epoch_key, BlockKind::Best))
    }

    pub fn set_new_epoch(&mut self, epoch: EpochIndex) {
        self.current_epoch = epoch;
        info!("New RC epoch {} started.", epoch);
    }

    pub fn start_new_epoch(&mut self, era: EraIndex, epoch: EpochIndex) {
        self.current_era = era;
        self.current_epoch = epoch;
        self.eras.insert(epoch, era);
        info!("New AH session {} at era {} started.", epoch, era);
    }

    pub fn set_relay_chain_block_number(&mut self, block_number: BlockNumber) {
        // insert start block only if it doesn't already exist
        self.blocks
            .entry(BlockKey(EpochKey(self.current_epoch), BlockKind::Start))
            .or_insert(block_number);
        // update end block
        self.blocks.insert(
            BlockKey(EpochKey(self.current_epoch), BlockKind::End),
            block_number,
        );
    }

    pub fn set_relay_chain_best_block_number(&mut self, block_number: BlockNumber) {
        self.blocks.insert(
            BlockKey(EpochKey(self.current_epoch), BlockKind::Best),
            block_number,
        );
    }

    pub fn set_asset_hub_block_number(
        &mut self,
        ah_block_number: BlockNumber,
        rc_block_number: BlockNumber,
    ) {
        // insert start block only if it doesn't already exist
        self.ah_blocks
            .entry(BlockKey(EpochKey(self.current_epoch), BlockKind::Start))
            .or_insert((ah_block_number, rc_block_number));
        // update end block
        self.ah_blocks.insert(
            BlockKey(EpochKey(self.current_epoch), BlockKind::End),
            (ah_block_number, rc_block_number),
        );
    }

    pub fn set_asset_hub_best_block_number(&mut self, ah_block_number: BlockNumber) {
        self.ah_blocks.insert(
            BlockKey(EpochKey(self.current_epoch), BlockKind::Best),
            (ah_block_number, 0),
        );
    }

    pub fn get_era_index(&self, epoch_index: Option<EpochIndex>) -> Option<&EraIndex> {
        let ei = if let Some(epoch_index) = epoch_index {
            epoch_index
        } else {
            self.current_epoch()
        };
        self.eras.get(&ei)
    }

    pub fn get_data_from_previous_epochs(
        &self,
        address: &AccountId32,
        number_of_epochs: u32,
    ) -> Option<PreviousEpochsData> {
        if self.total_full_epochs() == 0 {
            return None;
        }
        let mut is_active = false;
        let mut para_epochs: TotalParaEpochs = 0;
        let mut flagged_epochs: TotalFlaggedEpochs = 0;
        let mut exceptional_epochs: TotalExceptionalEpochs = 0;
        let mut total_votes: Votes = 0;
        let mut missed_votes: Votes = 0;

        let mut epoch_index = self.current_epoch() - number_of_epochs;
        while epoch_index < self.current_epoch() {
            let key = EpochKey(epoch_index);
            if let Some(auth_idx) = self
                .addresses
                .get(&AddressKey(key.clone(), address.to_string()))
            {
                is_active = true;
                if let Some(para_record) = self.para_records.get(&RecordKey(key.clone(), *auth_idx))
                {
                    para_epochs += 1;
                    let tv = para_record.total_votes();
                    let mv = para_record.total_missed_votes();
                    let mvr = mv as f64 / (tv + mv) as f64;
                    let ta = para_record.total_availability();
                    let tu = para_record.total_unavailability();
                    let bur = tu as f64 / (ta + tu) as f64;
                    // Identify failed and exceptional epochs
                    let grade = grade(mvr, bur, None);
                    if grade == Grade::F {
                        flagged_epochs += 1;
                    } else if grade == Grade::Ap {
                        exceptional_epochs += 1;
                    }
                    total_votes += tv;
                    missed_votes += mv;
                }
            }
            epoch_index += 1;
        }
        if para_epochs > 0 && total_votes + missed_votes > 0 {
            let mvr = missed_votes as f64 / (total_votes + missed_votes) as f64;
            Some((
                is_active,
                Some((para_epochs, exceptional_epochs, flagged_epochs, mvr)),
            ))
        } else {
            Some((is_active, None))
        }
    }

    pub fn get_data_from_all_full_epochs(&self, address: &AccountId32) -> Option<FullEpochsData> {
        if self.total_full_epochs() == 0 {
            return None;
        }
        let mut pattern: Pattern = Vec::new();
        let mut active_epochs: TotalActiveEpochs = 0;
        let mut para_epochs: TotalParaEpochs = 0;
        let mut para_points: Points = 0;
        let mut authored_blocks: AuthoredBlocks = 0;
        let mut explicit_votes: Votes = 0;
        let mut implicit_votes: Votes = 0;
        let mut missed_votes: Votes = 0;
        let mut bitfields_availability: BitfieldsAvailability = 0;
        let mut bitfields_unavailability: BitfieldsUnavailability = 0;
        let mut core_assignments: CoreAssignments = 0;

        let mut epoch_index = self.current_epoch() - self.total_full_epochs();
        while epoch_index < self.current_epoch() {
            let key = EpochKey(epoch_index);
            if let Some(auth_idx) = self
                .addresses
                .get(&AddressKey(key.clone(), address.to_string()))
            {
                active_epochs += 1;
                if let Some(authority_record) = self
                    .authority_records
                    .get(&RecordKey(key.clone(), *auth_idx))
                {
                    authored_blocks += authority_record.total_authored_blocks();
                    para_points += authority_record.para_points();
                    // Get para data
                    if let Some(para_record) =
                        self.para_records.get(&RecordKey(key.clone(), *auth_idx))
                    {
                        para_epochs += 1;
                        explicit_votes += para_record.total_explicit_votes();
                        implicit_votes += para_record.total_implicit_votes();
                        missed_votes += para_record.total_missed_votes();
                        bitfields_availability += para_record.total_availability();
                        bitfields_unavailability += para_record.total_unavailability();
                        core_assignments += para_record.total_core_assignments();

                        if let Some(ratio) = para_record.missed_votes_ratio() {
                            pattern.push(Glyph::from_mvr(ratio));
                        } else {
                            pattern.push(Glyph::ActivePVidle);
                        }
                    } else {
                        pattern.push(Glyph::Active);
                    }
                }
            } else {
                pattern.push(Glyph::Waiting);
            }
            epoch_index += 1;
        }

        if para_epochs > 0 && explicit_votes + implicit_votes + missed_votes > 0 {
            Some((
                (active_epochs, authored_blocks, pattern),
                Some((
                    para_epochs,
                    para_points,
                    explicit_votes,
                    implicit_votes,
                    missed_votes,
                    core_assignments,
                    bitfields_availability,
                    bitfields_unavailability,
                )),
            ))
        } else {
            Some(((active_epochs, authored_blocks, pattern), None))
        }
    }

    pub fn is_active_at(&self, address: &AccountId32, epoch_index: EpochIndex) -> bool {
        let key = EpochKey(epoch_index);
        self.addresses
            .contains_key(&AddressKey(key.clone(), address.to_string()))
    }

    pub fn insert_group(&mut self, group_idx: GroupIndex, authorities: Vec<AuthorityIndex>) {
        self.groups.insert(group_idx, authorities);
    }

    pub fn get_authorities_from_group(&self, index: GroupIndex) -> Option<Vec<AuthorityIndex>> {
        self.groups
            .get(&index)
            .map(|authorities| authorities.to_vec())
    }

    pub fn update_para_group(
        &mut self,
        para_id: ParaId,
        core: CoreIndex,
        group_idx: GroupIndex,
        epoch_idx: Option<EpochIndex>,
    ) {
        if let Some(previous_group_idx) = self.para_group.insert(para_id, group_idx) {
            if previous_group_idx == group_idx {
                return;
            }
            // remove assignement from authorities assigned to the current group
            if let Some(authorities) = self.get_authorities_from_group(previous_group_idx) {
                for authority_idx in authorities.iter() {
                    if let Some(para_record) = self.get_mut_para_record(*authority_idx, epoch_idx) {
                        para_record.remove_scheduled_core(para_id);
                    }
                }
            }
        }
        // update scheduled core and para_id to the authorities assigned to the group_idx
        if let Some(authorities) = self.get_authorities_from_group(group_idx) {
            for authority_idx in authorities.iter() {
                if let Some(para_record) = self.get_mut_para_record(*authority_idx, epoch_idx) {
                    para_record.update_scheduled_core(para_id, core);
                }
            }
        }
    }

    pub fn update_core_by_para_id(
        &mut self,
        para_id: ParaId,
        core: CoreIndex,
        epoch_idx: Option<EpochIndex>,
    ) {
        // update core_para map
        self.core_para.insert(core, Some(para_id));

        // set core assignment for all authorities in the group
        if let Some(group_idx) = self.para_group.get(&para_id) {
            if let Some(authorities) = self.get_authorities_from_group(*group_idx) {
                for authority_idx in authorities.iter() {
                    if let Some(para_record) = self.get_mut_para_record(*authority_idx, epoch_idx) {
                        para_record.set_core_assignment(para_id, core);
                    }
                }
            }
        }
    }

    pub fn update_core_free(&mut self, core: CoreIndex, epoch_idx: Option<EpochIndex>) {
        // update core_para map
        if let Some(Some(para_id)) = self.core_para.insert(core, None) {
            if let Some(group_idx) = self.para_group.get(&para_id) {
                if let Some(authorities) = self.get_authorities_from_group(*group_idx) {
                    for authority_idx in authorities.iter() {
                        if let Some(para_record) =
                            self.get_mut_para_record(*authority_idx, epoch_idx)
                        {
                            para_record.set_core_free();
                        }
                    }
                }
            }
        }
    }

    pub fn update_para_id_by_group(
        &mut self,
        para_id: ParaId,
        group_idx: GroupIndex,
        epoch_idx: Option<EpochIndex>,
    ) {
        if let Some(previous_group_idx) = self.para_group.insert(para_id, group_idx) {
            if previous_group_idx == group_idx {
                return;
            }
            // remove assignement from authorities assigned to the current group
            if let Some(authorities) = self.get_authorities_from_group(previous_group_idx) {
                for authority_idx in authorities.iter() {
                    if let Some(para_record) = self.get_mut_para_record(*authority_idx, epoch_idx) {
                        para_record.unset_para_id(para_id);
                    }
                }
            }
        }
        // update scheduled core and para_id to the authorities assigned to the group_idx
        if let Some(authorities) = self.get_authorities_from_group(group_idx) {
            for authority_idx in authorities.iter() {
                if let Some(para_record) = self.get_mut_para_record(*authority_idx, epoch_idx) {
                    para_record.set_para_id(para_id);
                }
            }
        }
    }

    pub fn inc_missing_vote_for_the_missing_authorities(
        &mut self,
        authorities_present: Vec<AuthorityIndex>,
        para_id: ParaId,
        group_idx: GroupIndex,
        epoch_idx: Option<EpochIndex>,
    ) {
        if let Some(authorities) = self.get_authorities_from_group(group_idx) {
            // find the ones missing
            let a: HashSet<AuthorityIndex> = authorities_present.into_iter().collect();
            let b: HashSet<AuthorityIndex> = authorities.into_iter().collect();
            let missing: Vec<&AuthorityIndex> = b.difference(&a).collect();

            for authority_idx in missing {
                if let Some(para_record) = self.get_mut_para_record(*authority_idx, epoch_idx) {
                    para_record.inc_missed_votes(para_id);
                }
            }
        }
    }

    pub fn insert(
        &mut self,
        address: &AccountId32,
        authority_index: AuthorityIndex,
        authority_record: AuthorityRecord,
        para_record: Option<ParaRecord>,
    ) {
        // Insert authority_index to the set of authorities for the current epoch
        if let Some(authorities) = self.get_mut_authorities(None) {
            authorities.insert(authority_index);
        } else {
            self.authorities.insert(
                EpochKey(self.current_epoch),
                HashSet::from([authority_index]),
            );
        }

        // Map address to the authority_index for the current epoch
        let address_key = AddressKey(EpochKey(self.current_epoch), address.to_string());
        self.addresses.entry(address_key).or_insert(authority_index);

        // Map authority_index to the AuthorityRecord for the current epoch
        let record_key = RecordKey(EpochKey(self.current_epoch), authority_index);
        self.authority_records
            .entry(record_key.clone())
            .or_insert(authority_record);

        // Map authority_index to the ParaRecord for the current epoch
        if let Some(para_record) = para_record {
            // Insert authority_index to the set of para_authorities for the current epoch
            if let Some(para_authorities) = self.get_mut_para_authorities(None) {
                para_authorities.insert(authority_index);
            } else {
                self.para_authorities.insert(
                    EpochKey(self.current_epoch),
                    HashSet::from([authority_index]),
                );
            }
            self.para_records
                .entry(record_key.clone())
                .or_insert(para_record);
        }
    }

    pub fn set_discovery_record(
        &mut self,
        authority_index: AuthorityIndex,
        discovery_record: DiscoveryRecord,
    ) {
        // Map authority_discovery_keys to the record_key
        let public_key = PublicKey(
            EpochKey(self.current_epoch),
            discovery_record.authority_discovery_key(),
        );
        self.authority_discovery_keys
            .entry(public_key)
            .or_insert(authority_index);

        // Map authority_index to the PeerToPeerRecord for the current epoch
        let record_key = RecordKey(EpochKey(self.current_epoch), authority_index);
        self.discovery_records
            .entry(record_key.clone())
            .or_insert(discovery_record);
    }

    pub fn get_authorities(&self, key: Option<EpochKey>) -> Option<Vec<AuthorityIndex>> {
        let key = if let Some(key) = key {
            key
        } else {
            EpochKey(self.current_epoch)
        };
        self.authorities
            .get(&key)
            .map(|authorities| authorities.iter().copied().collect())
    }

    pub fn get_para_authorities(&self, key: Option<EpochKey>) -> Option<Vec<AuthorityIndex>> {
        let key = if let Some(key) = key {
            key
        } else {
            EpochKey(self.current_epoch)
        };
        self.para_authorities
            .get(&key)
            .map(|para_authorities| para_authorities.iter().copied().collect())
    }

    pub fn get_mut_authorities(
        &mut self,
        key: Option<EpochKey>,
    ) -> Option<&mut HashSet<AuthorityIndex>> {
        if let Some(key) = key {
            self.authorities.get_mut(&key)
        } else {
            let key = EpochKey(self.current_epoch);
            self.authorities.get_mut(&key)
        }
    }

    pub fn get_mut_authority_record(
        &mut self,
        index: AuthorityIndex,
        epoch_index: Option<EpochIndex>,
    ) -> Option<&mut AuthorityRecord> {
        let epoch_key = if let Some(epoch_idx) = epoch_index {
            EpochKey(epoch_idx)
        } else {
            EpochKey(self.current_epoch)
        };
        self.authority_records.get_mut(&RecordKey(epoch_key, index))
    }

    pub fn get_mut_para_authorities(
        &mut self,
        key: Option<EpochKey>,
    ) -> Option<&mut HashSet<AuthorityIndex>> {
        if let Some(key) = key {
            self.para_authorities.get_mut(&key)
        } else {
            let key = EpochKey(self.current_epoch);
            self.para_authorities.get_mut(&key)
        }
    }

    pub fn get_mut_para_record(
        &mut self,
        index: AuthorityIndex,
        epoch_index: Option<EpochIndex>,
    ) -> Option<&mut ParaRecord> {
        let epoch_key = if let Some(epoch_idx) = epoch_index {
            EpochKey(epoch_idx)
        } else {
            EpochKey(self.current_epoch)
        };

        self.para_records.get_mut(&RecordKey(epoch_key, index))
    }

    pub fn get_authority_record(
        &self,
        index: AuthorityIndex,
        key: Option<EpochKey>,
    ) -> Option<&AuthorityRecord> {
        let epoch_key = if let Some(key) = key {
            key
        } else {
            EpochKey(self.current_epoch)
        };

        self.authority_records.get(&RecordKey(epoch_key, index))
    }

    pub fn get_para_record(
        &self,
        index: AuthorityIndex,
        key: Option<EpochKey>,
    ) -> Option<&ParaRecord> {
        let epoch_key = if let Some(key) = key {
            key
        } else {
            EpochKey(self.current_epoch)
        };

        self.para_records.get(&RecordKey(epoch_key, index))
    }

    pub fn get_authority_record_with_address(
        &self,
        address: &AccountId32,
        key: Option<EpochKey>,
    ) -> Option<&AuthorityRecord> {
        let epoch_key = if let Some(key) = key {
            key
        } else {
            EpochKey(self.current_epoch)
        };

        if let Some(authority_index) = self
            .addresses
            .get(&AddressKey(epoch_key.clone(), address.to_string()))
        {
            self.authority_records
                .get(&RecordKey(epoch_key, *authority_index))
        } else {
            None
        }
    }

    pub fn get_mut_authority_record_with_address(
        &mut self,
        address: &AccountId32,
        key: Option<EpochKey>,
    ) -> Option<&mut AuthorityRecord> {
        let epoch_key = if let Some(key) = key {
            key
        } else {
            EpochKey(self.current_epoch)
        };

        if let Some(authority_index) = self
            .addresses
            .get(&AddressKey(epoch_key.clone(), address.to_string()))
        {
            self.authority_records
                .get_mut(&RecordKey(epoch_key, *authority_index))
        } else {
            None
        }
    }

    pub fn get_discovery_record(
        &self,
        index: AuthorityIndex,
        key: Option<EpochKey>,
    ) -> Option<&DiscoveryRecord> {
        let epoch_key = if let Some(key) = key {
            key
        } else {
            EpochKey(self.current_epoch)
        };

        self.discovery_records.get(&RecordKey(epoch_key, index))
    }

    pub fn get_discovery_record_with_authority_discovery_key(
        &self,
        authority_discovery_key: &AuthorityDiscoveryKey,
        key: Option<EpochKey>,
    ) -> Option<&DiscoveryRecord> {
        let epoch_key = if let Some(key) = key {
            key
        } else {
            EpochKey(self.current_epoch)
        };

        if let Some(authority_index) = self.authority_discovery_keys.get(&PublicKey(
            epoch_key.clone(),
            hex::encode(authority_discovery_key),
        )) {
            self.discovery_records
                .get(&RecordKey(epoch_key, *authority_index))
        } else {
            None
        }
    }

    pub fn get_para_record_with_address(
        &self,
        address: &AccountId32,
        key: Option<EpochKey>,
    ) -> Option<&ParaRecord> {
        let epoch_key = if let Some(key) = key {
            key
        } else {
            EpochKey(self.current_epoch)
        };

        if let Some(authority_index) = self
            .addresses
            .get(&AddressKey(epoch_key.clone(), address.to_string()))
        {
            self.para_records
                .get(&RecordKey(epoch_key, *authority_index))
        } else {
            None
        }
    }

    pub fn remove(&mut self, epoch_key: EpochKey) {
        // Maps that need to be cleaned up
        // blocks: HashMap<BlockKey, BlockNumber>,
        // ah_blocks: HashMap<BlockKey, BlockNumberTupple>,
        // authorities: HashMap<EpochKey, HashSet<AuthorityIndex>>,
        // addresses: HashMap<AddressKey, AuthorityIndex>,
        // authority_records: HashMap<RecordKey, AuthorityRecord>,
        // para_authorities: HashMap<EpochKey, HashSet<AuthorityIndex>>,
        // para_records: HashMap<RecordKey, ParaRecord>,
        // authorithy_discovery_keys: HashMap<PublicKey, AuthorityIndex>,
        // discovery_records: HashMap<RecordKey, DiscoveryRecord>,

        let mut counter = 0;
        // Remove RC blocks
        if self
            .blocks
            .remove(&BlockKey(epoch_key.clone(), BlockKind::Start))
            .is_some()
        {
            counter += 1;
        }
        if self
            .blocks
            .remove(&BlockKey(epoch_key.clone(), BlockKind::End))
            .is_some()
        {
            counter += 1;
        }
        // Remove AH blocks
        if self
            .ah_blocks
            .remove(&BlockKey(epoch_key.clone(), BlockKind::Start))
            .is_some()
        {
            counter += 1;
        }
        if self
            .ah_blocks
            .remove(&BlockKey(epoch_key.clone(), BlockKind::End))
            .is_some()
        {
            counter += 1;
        }

        if let Some(authority_indexes) = self.authorities.get(&epoch_key.clone()) {
            for auth_idx in authority_indexes.iter() {
                // get authority address first
                if let Some(authority_record) = self
                    .authority_records
                    .get(&RecordKey(epoch_key.clone(), *auth_idx))
                {
                    if let Some(stash) = authority_record.address() {
                        // remove authority address from addresses map
                        if self
                            .addresses
                            .remove(&AddressKey(epoch_key.clone(), stash.to_string()))
                            .is_some()
                        {
                            counter += 1;
                        }
                        // remove para record
                        if self
                            .para_records
                            .remove(&RecordKey(epoch_key.clone(), *auth_idx))
                            .is_some()
                        {
                            counter += 1;
                        }
                    }
                }
                // remove authority records
                if self
                    .authority_records
                    .remove(&RecordKey(epoch_key.clone(), *auth_idx))
                    .is_some()
                {
                    counter += 1;
                }
                // remove authorithy_discovery_keys records
                if let Some(discovery_record) = self
                    .discovery_records
                    .get(&RecordKey(epoch_key.clone(), *auth_idx))
                {
                    // remove public key address from authority_discovery_keys map
                    if self
                        .authority_discovery_keys
                        .remove(&PublicKey(
                            epoch_key.clone(),
                            hex::encode(discovery_record.authority_discovery_key()),
                        ))
                        .is_some()
                    {
                        counter += 1;
                    }
                }
                // remove discovery records
                if self
                    .discovery_records
                    .remove(&RecordKey(epoch_key.clone(), *auth_idx))
                    .is_some()
                {
                    counter += 1;
                }
            }
        }
        // remove authorities
        if self.authorities.remove(&epoch_key.clone()).is_some() {
            counter += 1;
        }
        // remove para_authorities
        if self.para_authorities.remove(&epoch_key.clone()).is_some() {
            counter += 1;
        }
        info!("Removed {} keys from records for {:?}", counter, epoch_key);
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AuthorityRecord {
    // index is the position of the stash in session().validators(None)
    #[serde(rename = "aix")]
    #[serde(default)]
    index: Option<AuthorityIndex>,
    #[serde(default)]
    #[serde(skip_serializing)]
    address: Option<AccountId32>,
    #[serde(rename = "sp")]
    start_points: Points,
    #[serde(rename = "ep")]
    end_points: Option<Points>,
    #[serde(default)]
    #[serde(skip)]
    old_points: Points,
    #[serde(rename = "ab")]
    authored_blocks: Vec<BlockNumber>,
    // last block ever authored, it is not part of the records but set when served
    #[serde(rename = "lab", default, skip_serializing_if = "Option::is_none")]
    last_authored_block: Option<BlockNumber>,
    #[serde(default)]
    #[serde(skip_serializing)]
    is_flagged: bool,
}

impl AuthorityRecord {
    // NOTE: The start_points should be the value earned up to the last session.
    // If is the first session of an Era than should be zero
    pub fn with_index_address_and_points(
        index: AuthorityIndex,
        address: AccountId32,
        start_points: Points,
    ) -> Self {
        Self {
            index: Some(index),
            address: Some(address),
            start_points,
            old_points: start_points,
            end_points: Some(start_points),
            ..Default::default()
        }
    }

    pub fn authority_index(&self) -> Option<AuthorityIndex> {
        self.index
    }

    pub fn set_last_authored_block(&mut self, block_number: Option<BlockNumber>) {
        self.last_authored_block = block_number;
    }

    pub fn address(&self) -> Option<&AccountId32> {
        self.address.as_ref()
    }

    pub fn start_points(&self) -> Points {
        self.start_points
    }

    pub fn end_points(&self) -> Option<Points> {
        self.end_points
    }

    pub fn points(&self) -> Points {
        if let Some(end_points) = self.end_points {
            end_points.saturating_sub(self.start_points)
        } else {
            self.start_points
        }
    }

    pub fn era_points(&self) -> Points {
        if let Some(end_points) = self.end_points {
            end_points
        } else {
            self.start_points
        }
    }

    pub fn para_points(&self) -> Points {
        if self.points() < (self.total_authored_blocks() * 20) {
            return 0;
        }
        self.points() - (self.total_authored_blocks() * 20)
    }

    pub fn authored_blocks(&self) -> Vec<BlockNumber> {
        self.authored_blocks.to_vec()
    }

    pub fn total_authored_blocks(&self) -> u32 {
        self.authored_blocks.len().try_into().unwrap()
    }

    pub fn push_authored_block(&mut self, block_number: BlockNumber) {
        self.authored_blocks.push(block_number);
    }

    pub fn flag(&mut self) {
        self.is_flagged = true;
    }

    pub fn is_flagged(&self) -> bool {
        self.is_flagged
    }

    // NOTE: With async RC <-> AH the current_points expected to be recieved in this function
    // are the points earned within the current session. Before AHM the current_points expected
    // was the aggregated points for the active era.
    //
    // To keep the same behavior as before AHM, we need to update end_points with the
    // difference between the points collected in previous block (old_points)
    // and the ones collected in the current block (current_points).
    pub fn update_current_points(&mut self, current_points: Points) -> Points {
        fn diff(current: Points, last: Points) -> Points {
            current.saturating_sub(last)
        }
        if let Some(end_points) = self.end_points {
            let aditional_points = diff(current_points, self.old_points);
            self.old_points = current_points;
            self.end_points = Some(aditional_points + end_points);
            aditional_points
        } else {
            self.old_points = current_points;
            self.end_points = Some(current_points);
            diff(current_points, 0)
        }
    }

    // pub fn DEPRECATED_update_current_points(&mut self, current_points: Points) -> Points {
    //     fn diff(current: Points, last: Points) -> Points {
    //         if current > last {
    //             current - last
    //         } else {
    //             0
    //         }
    //     }
    //     if let Some(end_points) = self.end_points {
    //         // Note: only update end_points if current_points > end_points
    //         if current_points > end_points {
    //             self.end_points = Some(current_points);
    //         }
    //         // calculate diff and return
    //         return diff(current_points, end_points);
    //     } else {
    //         // update end_points if None with current_points value
    //         self.end_points = Some(current_points);
    //         // calculate diff and return
    //         return diff(current_points, self.start_points);
    //     };
    // }
}

impl Validity for AuthorityRecord {
    fn is_empty(&self) -> bool {
        self.index.is_none()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct DiscoveryRecord {
    #[serde(rename = "adk")]
    authority_discovery_key: String,
    ips: Vec<IpAddr>,
    #[serde(rename = "nv")]
    node_version: String,
    #[serde(rename = "nn")]
    node_name: String,
    #[serde(rename = "bn", default)]
    block_number: Option<BlockNumber>,
}

impl DiscoveryRecord {
    pub fn with_authority_discovery_key(authority_discovery_key: AuthorityDiscoveryKey) -> Self {
        Self {
            authority_discovery_key: hex::encode(authority_discovery_key),
            ips: Vec::new(),
            ..Default::default()
        }
    }

    pub fn authority_discovery_key(&self) -> String {
        self.authority_discovery_key.clone()
    }

    pub fn set_ips(&mut self, ips: Vec<IpAddr>) {
        self.ips = ips;
    }

    pub fn set_node_version(&mut self, version: String) {
        self.node_version = version;
    }

    pub fn set_node_name(&mut self, name: String) {
        self.node_name = name;
    }

    pub fn set_block_number(&mut self, block_number: BlockNumber) {
        self.block_number = Some(block_number);
    }

    pub fn is_version_available(&self) -> bool {
        !self.node_version.is_empty()
    }
}

impl Validity for DiscoveryRecord {
    fn is_empty(&self) -> bool {
        self.authority_discovery_key().is_empty()
    }
}

#[derive(Serialize, Debug, Clone, Default)]
pub struct BitfieldsRecord {
    #[serde(rename = "ba")]
    availability: u32,
    #[serde(rename = "bu")]
    unavailability: u32,
    #[serde(rename = "uat")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unavailable_at: Vec<BlockNumber>,
}

impl BitfieldsRecord {
    pub fn new() -> Self {
        Self {
            availability: 0,
            unavailability: 0,
            unavailable_at: Vec::new(),
        }
    }

    pub fn availability(&self) -> u32 {
        self.availability
    }

    pub fn set_availability(&mut self, availability: u32) {
        self.availability = availability;
    }

    pub fn unavailability(&self) -> u32 {
        self.unavailability
    }

    pub fn set_unavailability(&mut self, unavailability: u32) {
        self.unavailability = unavailability;
    }

    pub fn unavailable(&self) -> Vec<BlockNumber> {
        self.unavailable_at.to_vec()
    }

    pub fn inc_availability(&mut self) {
        self.availability += 1;
    }

    pub fn push_unavailable_at(&mut self, block_number: BlockNumber) {
        self.unavailability += 1;
        self.unavailable_at.push(block_number);
    }
}

impl<'de> Deserialize<'de> for BitfieldsRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // First, try to deserialize as a regular struct
        let result = serde_json::Value::deserialize(deserializer)?;

        // Create a default BitfieldsRecord
        let mut bitfields = BitfieldsRecord::new();

        if let Some(obj) = result.as_object() {
            // Handle "ba" (availability) field
            if let Some(ba) = obj.get("ba") {
                if let Some(num) = ba.as_u64() {
                    bitfields.set_availability(num as u32);
                } else if let Some(num) = ba.as_i64() {
                    if num >= 0 {
                        bitfields.set_availability(num as u32);
                    }
                } else if let Some(num) = ba.as_f64() {
                    if num >= 0.0 {
                        bitfields.set_availability(num as u32);
                    }
                }
            }

            // Handle "bu" (unavailability) field
            if let Some(bu) = obj.get("bu") {
                if let Some(num) = bu.as_u64() {
                    bitfields.set_unavailability(num as u32);
                } else if let Some(num) = bu.as_i64() {
                    if num >= 0 {
                        bitfields.set_unavailability(num as u32);
                    }
                } else if let Some(num) = bu.as_f64() {
                    if num >= 0.0 {
                        bitfields.set_unavailability(num as u32);
                    }
                }
            }

            // Handle "uat" (unavailable_at) field
            if let Some(uat) = obj.get("uat") {
                if let Some(array) = uat.as_array() {
                    let mut unavailable_at = Vec::new();
                    for item in array {
                        if let Some(num) = item.as_u64() {
                            unavailable_at.push(num);
                        }
                    }
                    bitfields.unavailable_at = unavailable_at;
                }
            }
        }

        Ok(bitfields)
    }
}

impl Validity for BitfieldsRecord {
    fn is_empty(&self) -> bool {
        self.availability() == 0 && self.unavailability() == 0 && self.unavailable_at.is_empty()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ParaRecord {
    // index is the position of the authority in paras_shared().active_validator_indices(None)
    #[serde(rename = "pix")]
    index: ParaIndex,
    group: Option<GroupIndex>,
    core: Option<CoreIndex>,
    #[serde(rename = "pid")]
    para_id: Option<ParaId>,
    peers: Vec<AuthorityIndex>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    disputes: Vec<(BlockNumber, DisputeKind)>,
    #[serde(skip)]
    para_stats: BTreeMap<ParaId, ParaStats>,
    bitfields: Option<BitfieldsRecord>,
}

impl ParaRecord {
    pub fn with_index_group_and_peers(
        index: ParaIndex,
        group_index: GroupIndex,
        peers: Vec<AuthorityIndex>,
    ) -> Self {
        Self {
            index,
            group: Some(group_index),
            core: None,
            para_id: None,
            peers,
            para_stats: BTreeMap::new(),
            bitfields: Some(BitfieldsRecord::default()),
            ..Default::default()
        }
    }

    pub fn para_index(&self) -> &ParaIndex {
        &self.index
    }

    pub fn group(&self) -> Option<GroupIndex> {
        self.group
    }

    pub fn core(&self) -> Option<CoreIndex> {
        self.core
    }

    pub fn para_id(&self) -> Option<ParaId> {
        self.para_id
    }

    pub fn is_para_id_assigned(&self, id: ParaId) -> bool {
        if let Some(para_id) = self.para_id {
            return para_id == id;
        }
        false
    }

    pub fn peers(&self) -> Vec<AuthorityIndex> {
        self.peers.to_vec()
    }

    pub fn disputes(&self) -> Vec<(BlockNumber, DisputeKind)> {
        self.disputes.to_vec()
    }

    pub fn push_dispute(&mut self, block_number: BlockNumber, msg: String) {
        self.disputes.push((block_number, msg));
    }

    pub fn inc_availability(&mut self) {
        self.bitfields.as_mut().unwrap().inc_availability();
    }

    pub fn push_unavailable_at(&mut self, block_number: BlockNumber) {
        self.bitfields
            .as_mut()
            .unwrap()
            .push_unavailable_at(block_number);
    }

    pub fn update_scheduled_core(&mut self, para_id: ParaId, core: CoreIndex) {
        // Assign current scheduled para_id
        self.para_id = Some(para_id);
        // Verify if a different core has been assigned
        let is_different_core = if let Some(previous_core) = self.core {
            previous_core != core
        } else {
            true
        };
        self.core = Some(core);
        // if different core increment assignments
        if is_different_core {
            let stats = self.para_stats.entry(para_id).or_default();
            stats.core_assignments += 1;
        }
    }

    pub fn remove_scheduled_core(&mut self, para_id: ParaId) {
        if let Some(pid) = self.para_id {
            if pid == para_id {
                self.para_id = None;
                self.core = None;
            }
        }
    }

    pub fn set_core_assignment(&mut self, para_id: ParaId, core: CoreIndex) {
        self.core = Some(core);

        let stats = self.para_stats.entry(para_id).or_default();
        stats.core_assignments += 1;
    }

    pub fn set_core_free(&mut self) {
        self.core = None;
    }

    pub fn set_para_id(&mut self, para_id: ParaId) {
        self.para_id = Some(para_id);
    }

    pub fn unset_para_id(&mut self, para_id: ParaId) {
        if let Some(pid) = self.para_id {
            if pid == para_id {
                self.para_id = None;
            }
        }
    }

    pub fn update_points(&mut self, points: Points, is_block_author: bool) {
        if let Some(para_id) = self.para_id {
            // increment current points and authored blocks if the author of the current finalized block
            let stats = self.para_stats.entry(para_id).or_default();
            stats.points += points;
            stats.authored_blocks += is_block_author as u32;
        }
    }

    pub fn inc_explicit_votes(&mut self, para_id: ParaId) {
        // increment current explicit_votes
        let stats = self.para_stats.entry(para_id).or_default();
        stats.explicit_votes += 1;
    }

    pub fn inc_implicit_votes(&mut self, para_id: ParaId) {
        // increment current explicit_votes
        let stats = self.para_stats.entry(para_id).or_default();
        stats.implicit_votes += 1;
    }

    pub fn inc_missed_votes(&mut self, para_id: ParaId) {
        // increment current missed_votes
        let stats = self.para_stats.entry(para_id).or_default();
        stats.missed_votes += 1;
    }

    pub fn total_points(&self) -> Points {
        self.para_stats.values().map(|stats| stats.points).sum()
    }

    pub fn total_authored_blocks(&self) -> AuthoredBlocks {
        self.para_stats
            .values()
            .map(|stats| stats.authored_blocks)
            .sum()
    }

    pub fn total_missed_votes(&self) -> Votes {
        self.para_stats
            .values()
            .map(|stats| stats.missed_votes)
            .sum()
    }

    pub fn total_implicit_votes(&self) -> Votes {
        self.para_stats
            .values()
            .map(|stats| stats.implicit_votes)
            .sum()
    }

    pub fn total_explicit_votes(&self) -> Votes {
        self.para_stats
            .values()
            .map(|stats| stats.explicit_votes)
            .sum()
    }

    pub fn total_votes(&self) -> Votes {
        self.total_implicit_votes() + self.total_explicit_votes()
    }

    pub fn missed_votes_ratio(&self) -> Option<Ratio> {
        let total_missed_votes = self.total_missed_votes();
        let total_votes =
            total_missed_votes + self.total_implicit_votes() + self.total_explicit_votes();
        if total_votes == 0 {
            None
        } else {
            // calculate ratio
            let ratio = total_missed_votes as f64
                / (total_missed_votes + self.total_implicit_votes() + self.total_explicit_votes())
                    as f64;

            Some(ratio)
        }
    }

    pub fn total_core_assignments(&self) -> CoreAssignments {
        self.para_stats
            .values()
            .map(|stats| stats.core_assignments)
            .sum()
    }

    pub fn total_disputes(&self) -> u32 {
        self.disputes.len().try_into().unwrap()
    }

    pub fn total_availability(&self) -> u32 {
        if let Some(bitfields) = &self.bitfields {
            bitfields.availability()
        } else {
            0
        }
    }

    pub fn total_unavailability(&self) -> u32 {
        if let Some(bitfields) = &self.bitfields {
            bitfields.unavailability()
        } else {
            0
        }
    }

    pub fn bitfields_unavailability_ratio(&self) -> Option<Ratio> {
        let total_votes = self.total_availability() + self.total_unavailability();
        if total_votes == 0 {
            None
        } else {
            let ratio = self.total_unavailability() as f64 / total_votes as f64;
            Some(ratio)
        }
    }

    pub fn bitfields_availability_ratio(&self) -> Option<Ratio> {
        let total_votes = self.total_availability() + self.total_unavailability();
        if total_votes == 0 {
            None
        } else {
            let ratio = self.total_availability() as f64 / total_votes as f64;
            Some(ratio)
        }
    }

    pub fn get_para_id_stats(&self, para_id: ParaId) -> Option<&ParaStats> {
        self.para_stats.get(&para_id)
    }

    pub fn para_stats(&self) -> &BTreeMap<ParaId, ParaStats> {
        &self.para_stats
    }

    pub fn clone_without_stats(&self) -> ParaRecord {
        ParaRecord {
            index: self.index,
            group: self.group,
            core: self.core,
            para_id: self.para_id,
            peers: self.peers.clone(),
            disputes: self.disputes.clone(),
            para_stats: BTreeMap::new(),
            bitfields: self.bitfields.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ParaStats {
    #[serde(rename = "pt")]
    pub points: Points,
    #[serde(rename = "ca")]
    pub core_assignments: u32,
    #[serde(rename = "ab")]
    pub authored_blocks: AuthoredBlocks,
    #[serde(rename = "ev")]
    pub explicit_votes: u32,
    #[serde(rename = "iv")]
    pub implicit_votes: u32,
    #[serde(rename = "mv")]
    pub missed_votes: u32,
}

impl ParaStats {
    pub fn points(&self) -> Points {
        self.points
    }

    pub fn para_points(&self) -> Points {
        self.points - (self.authored_blocks * 20)
    }

    pub fn core_assignments(&self) -> u32 {
        self.core_assignments
    }

    pub fn authored_blocks(&self) -> AuthoredBlocks {
        self.authored_blocks
    }

    pub fn explicit_votes(&self) -> Votes {
        self.explicit_votes
    }

    pub fn implicit_votes(&self) -> Votes {
        self.implicit_votes
    }

    pub fn total_votes(&self) -> Votes {
        self.explicit_votes + self.implicit_votes
    }

    pub fn missed_votes(&self) -> Votes {
        self.missed_votes
    }

    pub fn votes_points(&self) -> Points {
        self.total_votes() * 20
    }
}

impl Validity for ParaStats {
    fn is_empty(&self) -> bool {
        self.missed_votes() == 0
            && self.total_votes() == 0
            && self.authored_blocks() == 0
            && self.core_assignments() == 0
            && self.points() == 0
    }
}

#[derive(Debug, Clone)]
pub struct Subscribers {
    current_era: EraIndex,
    current_epoch: EpochIndex,
    subscribers: HashMap<EpochKey, Vec<(AccountId32, UserID, Option<Param>)>>,
}

impl Subscribers {
    pub fn with_era_and_epoch(current_era: EraIndex, current_epoch: EpochIndex) -> Self {
        Self {
            current_era,
            current_epoch,
            subscribers: HashMap::new(),
        }
    }

    pub fn start_new_epoch(&mut self, era: EraIndex, epoch: EpochIndex) {
        self.current_era = era;
        self.current_epoch = epoch;
    }

    pub fn current_era(&self) -> EraIndex {
        self.current_era
    }

    pub fn current_epoch(&self) -> EpochIndex {
        self.current_epoch
    }

    pub fn subscribe(&mut self, account: AccountId32, user_id: UserID, param: Option<Param>) {
        let key = EpochKey(self.current_epoch);
        if let Some(s) = self.subscribers.get_mut(&key) {
            s.push((account, user_id.to_string(), param.clone()));
        } else {
            self.subscribers
                .insert(key, vec![(account, user_id.to_string(), param.clone())]);
        }
        info!(
            "{} subscribed ({}) report for epoch {} era {}",
            user_id,
            account,
            self.current_epoch(),
            self.current_era(),
        );
    }

    pub fn get(&self, key: Option<EpochKey>) -> Option<&Vec<(AccountId32, UserID, Option<Param>)>> {
        if let Some(key) = key {
            self.subscribers.get(&key)
        } else {
            let key = EpochKey(self.current_epoch);
            self.subscribers.get(&key)
        }
    }

    pub fn remove(&mut self, epoch_key: EpochKey) {
        // Maps that need to be cleaned up
        // subscribers: HashMap<EpochKey, Vec<(AccountId32, UserID)>>,

        let mut counter = 0;
        // remove subscribers
        if self.subscribers.remove(&epoch_key.clone()).is_some() {
            counter += 1;
        }
        info!(
            "Removed {} keys from subscribers for {:?}",
            counter, epoch_key
        );
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ParachainRecord {
    #[serde(rename = "pid")]
    pub para_id: ParaId,
    #[serde(rename = "group")]
    pub current_group: Option<GroupIndex>,
    #[serde(rename = "auths")]
    pub current_authorities: Vec<AuthorityIndex>,
    pub stats: ParaStats,
}

impl From<&std::string::String> for ParachainRecord {
    fn from(serialized: &std::string::String) -> Self {
        serde_json::from_str(serialized).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Identity {
    #[serde(default)]
    name: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
}

impl Identity {
    pub fn with_name(name: String) -> Self {
        Self { name, sub: None }
    }
    pub fn with_name_and_sub(name: String, sub: String) -> Self {
        Self {
            name,
            sub: Some(sub),
        }
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(sub) = &self.sub {
            write!(f, "{}/{}", self.name, sub)
        } else {
            write!(f, "{}", self.name)
        }
    }
}

// Note: the following structs are useful for api/cache support
/// Predicted outcome for a validator, one per number of target validators (`id`)
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct ProfilePrediction {
    #[serde(rename = "p")]
    pub target: u32,
    #[serde(rename = "tts")]
    pub total_stake: u128,
    #[serde(rename = "nc")]
    pub nominators_counter: u32,
    #[serde(rename = "ts")]
    pub ts: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ValidatorProfileRecord {
    pub stash: Option<AccountId32>,
    pub controller: Option<AccountId32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
    // Note: commission max value = Perbill(1000000000) => 100%
    pub commission: u32,
    pub own_stake: u128,
    // Note: nominators_stake is the sum of all nominators stake
    pub nominators_stake: u128,
    // Note: nominators_raw_stake is the sum of all nominators stake divided by the number of nominees
    pub nominators_raw_stake: u128,
    pub nominators_counter: u128,
    pub points: u32,
    pub subset: Subset,
    // mvr is calculated based on the mvr from previous sessions and the latest obtained
    pub mvr: Option<u64>,
    // mvr_session contains the session from where the mvr was last updated
    pub mvr_session: Option<EpochIndex>,
    // mcr is the missed collation ratio averaged with the previous sessions,
    // none if the validator never collated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcr: Option<u64>,
    // mcr_session contains the session from where the mcr was last updated
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcr_session: Option<EpochIndex>,
    // TODO: DEPRECATE is_oversubscribed, after runtime v1.2 no longer needed
    pub is_oversubscribed: bool,
    pub is_active: bool,
    pub is_chilled: bool,
    pub is_blocked: bool,
}

impl ValidatorProfileRecord {
    pub fn new(stash: AccountId32) -> Self {
        Self {
            stash: Some(stash),
            controller: None,
            identity: None,
            commission: 0,
            own_stake: 0,
            nominators_stake: 0,
            nominators_raw_stake: 0,
            nominators_counter: 0,
            points: 0,
            subset: Subset::NONTVP,
            mvr: None,
            mvr_session: None,
            mcr: None,
            mcr_session: None,
            is_oversubscribed: false,
            is_active: false,
            is_chilled: false,
            is_blocked: false,
        }
    }

    pub fn own_stake_trimmed(&self, chain_token_decimals: u32) -> u64 {
        let base: u128 = 10_u128;
        (self.own_stake / base.pow(chain_token_decimals - DECIMALS)) as u64
    }

    pub fn nominators_stake_trimmed(&self, chain_token_decimals: u32) -> u64 {
        let base: u128 = 10_u128;
        (self.nominators_stake / base.pow(chain_token_decimals - DECIMALS)) as u64
    }

    pub fn nominators_raw_stake_trimmed(&self, chain_token_decimals: u32) -> u64 {
        let base: u128 = 10_u128;
        (self.nominators_raw_stake / base.pow(chain_token_decimals - DECIMALS)) as u64
    }

    pub fn is_tvp(&self) -> bool {
        self.subset == Subset::TVP
    }

    pub fn is_identified(&self) -> bool {
        self.identity.is_some()
    }
}

impl Validity for ValidatorProfileRecord {
    fn is_empty(&self) -> bool {
        self.stash.is_none()
    }
}

impl From<String> for ValidatorProfileRecord {
    fn from(serialized_data: String) -> Self {
        serde_json::from_str(&serialized_data).unwrap_or_default()
    }
}

// // Note: the following structs are useful for api/cache support
// #[derive(Serialize, Deserialize, Debug, Clone, Default)]
// pub struct ValidatorP2PRecord {
//     pub stash: Option<AccountId32>,
//     pub ipv4s: u32,
//     pub own_stake: u128,
//     // Note: nominators_stake is the sum of all nominators stake
//     pub nominators_stake: u128,
//     // Note: nominators_raw_stake is the sum of all nominators stake divided by the number of nominees
//     pub nominators_raw_stake: u128,
//     pub nominators_counter: u128,
//     pub points: u32,
//     pub subset: Subset,
//     // mvr is calculated based on the mvr from previous sessions and the latest obtained
//     pub mvr: Option<u64>,
//     // mvr_session contains the session from where the mvr was last updated
//     pub mvr_session: Option<EpochIndex>,
//     // TODO: DEPRECATE is_oversubscribed, after runtime v1.2 no longer needed
//     pub is_oversubscribed: bool,
//     pub is_active: bool,
//     pub is_chilled: bool,
//     pub is_blocked: bool,
// }

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SessionStats {
    #[serde(rename = "na")]
    pub authorities: u32,
    #[serde(rename = "npa")]
    pub para_authorities: u32,
    #[serde(rename = "pt")]
    pub points: Points,
    #[serde(rename = "ab")]
    pub authored_blocks: u32,
    #[serde(rename = "ca")]
    pub core_assignments: u32,
    #[serde(rename = "ev")]
    pub explicit_votes: u32,
    #[serde(rename = "iv")]
    pub implicit_votes: u32,
    #[serde(rename = "mv")]
    pub missed_votes: u32,
    #[serde(rename = "di")]
    pub disputes: u32,
    #[serde(rename = "ba")]
    pub bitfields_availability: u32,
    #[serde(rename = "bu")]
    pub bitfields_unavailability: u32,
}

impl Validity for SessionStats {
    fn is_empty(&self) -> bool {
        self.authorities == 0
    }
}

#[derive(Default, Serialize, Deserialize, Clone, Eq, Hash, PartialEq, Debug)]
pub enum SyncStatus {
    #[default]
    Syncing,
    Finished,
}

impl std::fmt::Display for SyncStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Syncing => write!(f, "syncing"),
            Self::Finished => write!(f, "finished"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct NetworkSessionStats {
    pub session: EpochIndex,
    pub block_number: BlockNumber,
    pub subsets: Vec<SubsetStats>,
    pub total_issuance: u128,
    pub total_reward_points: u32,
    pub total_staked: u128,
    pub last_rewarded: u128,
    pub total_vals_chilled: u32,
}

impl Validity for NetworkSessionStats {
    fn is_empty(&self) -> bool {
        self.session == 0
    }
}

impl NetworkSessionStats {
    pub fn new(session: EpochIndex, block_number: BlockNumber) -> Self {
        Self {
            session,
            block_number,
            subsets: Vec::new(),
            total_issuance: 0,
            total_reward_points: 0,
            total_staked: 0,
            last_rewarded: 0,
            total_vals_chilled: 0,
        }
    }
}

impl From<String> for NetworkSessionStats {
    fn from(serialized_data: String) -> Self {
        serde_json::from_str(&serialized_data).unwrap_or_default()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SubsetStats {
    pub subset: Subset,
    pub vals_total: u32,
    pub vals_active: u32,
    pub vals_own_stake_total: u128,
    pub vals_own_stake_avg: u128,
    pub vals_own_stake_min: u128,
    pub vals_own_stake_max: u128,
    pub vals_oversubscribed: u32,
    pub vals_points_total: u32,
    pub vals_points_avg: u32,
    pub vals_points_min: u32,
    pub vals_points_max: u32,
}

impl Validity for SubsetStats {
    fn is_empty(&self) -> bool {
        self.vals_total == 0
    }
}

impl SubsetStats {
    pub fn new(subset: Subset) -> Self {
        Self {
            subset,
            vals_total: 0,
            vals_active: 0,
            vals_own_stake_total: 0,
            vals_own_stake_avg: 0,
            vals_own_stake_min: 0,
            vals_own_stake_max: 0,
            vals_oversubscribed: 0,
            vals_points_total: 0,
            vals_points_avg: 0,
            vals_points_min: 0,
            vals_points_max: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn grade_with_and_without_collation() {
        // without collation: 75% votes, 25% bitfields
        assert_eq!(grade(0.0, 0.0, None), Grade::Ap);
        assert_eq!(grade(0.04, 0.0, None), Grade::A);
        // with collation: 60% votes, 15% bitfields, 25% collation
        assert_eq!(grade(0.0, 0.0, Some(0.0)), Grade::Ap);
        assert_eq!(grade(0.0, 0.0, Some(0.02)), Grade::Ap);
        assert_eq!(grade(0.0, 0.0, Some(0.03)), Grade::Ap);
        assert_eq!(grade(0.0, 0.0, Some(0.04)), Grade::A);
        assert_eq!(grade(0.0, 0.0, Some(0.2)), Grade::Bp);
        assert_eq!(grade(0.05, 0.0, Some(0.0)), Grade::A);
        assert_eq!(grade(0.1, 0.0, Some(0.0)), Grade::Bp);
        assert_eq!(grade(0.0, 0.1, Some(0.0)), Grade::A);
        // a validator that missed all its collation blocks loses 25 points
        assert_eq!(grade(0.0, 0.0, Some(1.0)), Grade::Cp);
        // a perfect collation does not change a grade without it, if votes are perfect
        assert_eq!(grade(0.0, 0.0, None), grade(0.0, 0.0, Some(0.0)));
    }

    #[test]
    fn grade_of_a_validator_that_only_collated() {
        assert_eq!(collation_grade(0.0), Grade::Ap);
        assert_eq!(collation_grade(0.02), Grade::A);
        assert_eq!(collation_grade(0.25), Grade::Cp);
        assert_eq!(collation_grade(1.0), Grade::F);
    }

    #[test]
    fn collator_records_are_tracked_by_para_session_and_epoch() {
        use collators::CollatorKind;
        let para_id = 1000;
        let a = AccountId32([1; 32]);
        let mut records = Records::with_era_epoch_and_block(10, 100, 1);
        let slots = records.para_slots_mut(para_id);
        slots.set_blocks_per_slot(2);
        slots.set_points_per_block(20);
        slots.set_session(7);
        slots.set_collators(vec![(a, CollatorKind::Validator)]);

        // slot 1 is partial, slot 2 has 2 blocks, slot 3 closes slot 2
        records.track_para_block(para_id, 1, 1);
        // the collators of the session have a record before any slot is closed
        let address = a.to_string();
        assert_eq!(
            records.dirty_collators(para_id),
            vec![(7, 100, address.clone())]
        );
        let seeded = records.get_collator_record(para_id, 7, &address).unwrap();
        assert_eq!((seeded.owned_slots(), seeded.cix()), (0, Some(0)));
        assert_eq!(records.collator_session_stats(para_id, 7).nc, 1);
        records.clear_dirty_collators(para_id);
        records.track_para_block(para_id, 2, 2);
        records.track_para_block(para_id, 3, 2);
        assert!(records.dirty_collators(para_id).is_empty());
        records.track_para_block(para_id, 4, 3);

        assert_eq!(
            records.dirty_collators(para_id),
            vec![(7, 100, address.clone())]
        );
        let by_session = records.get_collator_record(para_id, 7, &address).unwrap();
        let by_epoch = records
            .get_collator_epoch_record(para_id, 100, &address)
            .unwrap();
        assert_eq!(by_session, by_epoch);
        assert_eq!(by_session.produced_blocks(), 2);
        assert_eq!(by_session.msr(), Some(0.0));
        assert_eq!(by_session.summary().pt, 40);
        assert_eq!(by_session.cix(), Some(0));
        let stats = records.collator_session_stats(para_id, 7);
        assert_eq!((stats.nc, stats.pb, stats.pt), (1, 2, 40));
        assert_eq!((stats.sbix, stats.ebix), (1, 4));
        assert_eq!(stats, records.collator_epoch_stats(para_id, 100));
        assert!(records.collator_session_stats(para_id, 8).is_empty());

        // resume the range after a restart, the earliest start and the latest end are kept
        records.seed_para_session_blocks(para_id, 7, 0, 3);
        let stats = records.collator_session_stats(para_id, 7);
        assert_eq!((stats.sbix, stats.ebix), (0, 4));
        assert!(records
            .get_collator_record(para_id + 1, 7, &address)
            .is_none());

        records.clear_dirty_collators(para_id);
        assert!(records.dirty_collators(para_id).is_empty());
    }

    #[test]
    fn para_session_has_the_era_it_started_in() {
        let para_id = 1000;
        let mut records = Records::with_era_epoch_and_block(10, 100, 1);
        assert_eq!(records.collator_session_stats(para_id, 7).eix, None);
        records.set_para_session_era(para_id, 7, 11303);
        // the era does not change once set
        records.set_para_session_era(para_id, 7, 11304);
        assert_eq!(records.collator_session_stats(para_id, 7).eix, Some(11303));
        assert_eq!(records.collator_session_stats(para_id, 8).eix, None);
        // not shown for relay sessions
        assert_eq!(records.collator_epoch_stats(para_id, 7).eix, None);
    }

    #[test]
    fn para_session_knows_its_position_in_the_era_only_after_an_era_change() {
        let para_id = 1000;
        let mut records = Records::with_era_epoch_and_block(10, 100, 1);
        // tracker started in the middle of an era, position not known
        records.set_para_session_era(para_id, 7, 5);
        records.set_para_session_era(para_id, 8, 5);
        assert_eq!(records.collator_session_stats(para_id, 8).esix, None);
        // the session after an era change is the first of the new era
        records.set_para_session_era(para_id, 9, 6);
        records.set_para_session_era(para_id, 10, 6);
        records.set_para_session_era(para_id, 11, 6);
        let esix = |s| records.collator_session_stats(para_id, s).esix;
        assert_eq!((esix(9), esix(10), esix(11)), (Some(0), Some(1), Some(2)));
        assert_eq!(esix(8), None);

        // resumed after a restart from the stats of the running session
        let mut records = Records::with_era_epoch_and_block(10, 100, 1);
        records.seed_para_session_era(para_id, 11, 6, Some(2));
        records.set_para_session_era(para_id, 12, 6);
        assert_eq!(records.collator_session_stats(para_id, 12).esix, Some(3));
        // resumed without the position
        let mut records = Records::with_era_epoch_and_block(10, 100, 1);
        records.seed_para_session_era(para_id, 11, 6, None);
        records.set_para_session_era(para_id, 12, 6);
        assert_eq!(records.collator_session_stats(para_id, 12).esix, None);
    }

    #[test]
    fn collator_draw_has_the_validators_that_are_authorities() {
        use collators::CollatorKind;
        let para_id = 1000;
        let (a, b, c) = (
            AccountId32([1; 32]),
            AccountId32([2; 32]),
            AccountId32([3; 32]),
        );
        let mut records = Records::with_era_epoch_and_block(10, 100, 1);
        let slots = records.para_slots_mut(para_id);
        slots.set_session(7);
        slots.set_collators(vec![
            (a, CollatorKind::Invulnerable),
            (b, CollatorKind::Validator),
            (c, CollatorKind::Validator),
        ]);
        assert!(records.collator_draw(para_id).is_empty());

        // only `b` is an authority of the relay session, `a` is not a validator
        records.insert(
            &b,
            5,
            AuthorityRecord::with_index_address_and_points(5, b, 0),
            None,
        );
        assert_eq!(records.collator_draw(para_id), vec![(5, 1)]);
        assert!(records.collator_draw(para_id + 1).is_empty());

        assert!(records.cached_collator_draw(para_id).is_none());
        records.set_cached_collator_draw(para_id, 7, 100, BTreeSet::from([5]));
        assert_eq!(
            records.cached_collator_draw(para_id),
            Some(&(7, 100, BTreeSet::from([5])))
        );
    }

    #[test]
    fn test_subscribers() {
        let era: EraIndex = 100;
        let epoch: EpochIndex = 20;

        // Define Subscribers
        let mut subscribers = Subscribers::with_era_and_epoch(era, epoch);
        assert_eq!(subscribers.current_era(), 100);
        assert_eq!(subscribers.current_epoch(), 20);

        // Subscribe
        let account =
            AccountId32::from_str("DSov56qpKEc32ZjhCN1qTPmTYW3tM65wmsXVkrrtXV3ywpV").unwrap();
        subscribers.subscribe(account, "@subscriber:matrix.org".to_string(), None);
        assert!(subscribers.get(None).is_some());
        assert!(subscribers.get(Some(EpochKey(epoch))).is_some());
        assert!(subscribers.get(Some(EpochKey(30))).is_none());
        assert_eq!(
            subscribers.get(Some(EpochKey(epoch))),
            Some(&vec![(
                AccountId32::from_str("DSov56qpKEc32ZjhCN1qTPmTYW3tM65wmsXVkrrtXV3ywpV").unwrap(),
                "@subscriber:matrix.org".to_string(),
                None
            )])
        );

        subscribers.start_new_epoch(era, epoch + 1);
        assert_eq!(subscribers.current_era(), 100);
        assert_eq!(subscribers.current_epoch(), 21);
    }

    #[test]
    fn test_records() {
        let era: EraIndex = 100;
        let epoch: EpochIndex = 20;
        let account =
            AccountId32::from_str("DSov56qpKEc32ZjhCN1qTPmTYW3tM65wmsXVkrrtXV3ywpV").unwrap();
        let authority_idx: AuthorityIndex = 123;

        // Define some records
        let mut records = Records::with_era_epoch_and_block(era, epoch, 45000);
        assert_eq!(records.current_era(), 100);
        assert_eq!(records.current_epoch(), 20);

        // TODO
        // assert_eq!(records.current_block(), 45000);
        // assert_eq!(records.start_block(), 45000);
        // assert_eq!(records.end_block(), None);

        //
        let ar = AuthorityRecord::with_index_address_and_points(authority_idx, account, 300);
        assert_eq!(ar.authority_index(), Some(authority_idx));
        assert_eq!(ar.address(), Some(&account));
        assert_eq!(ar.start_points(), 300);
        assert_eq!(ar.end_points(), Some(300));

        let pr = ParaRecord::with_index_group_and_peers(1, 2, vec![456, 789]);
        assert_eq!(pr.para_index(), &1);
        assert_eq!(pr.group(), Some(2));
        assert_eq!(pr.peers(), vec![456, 789]);

        records.insert(&account, authority_idx, ar, Some(pr));

        assert!(records.get_authorities(None).is_some());
        assert!(records.get_authorities(Some(EpochKey(epoch))).is_some());
        assert!(records.get_authorities(Some(EpochKey(0))).is_none());

        if let Some(authorities) = records.get_authorities(None) {
            assert_eq!(*authorities, vec![authority_idx]);
        }

        // Increment authored blocks and current points
        if let Some(ar) = records.get_mut_authority_record(authority_idx, None) {
            let diff = ar.update_current_points(1900);
            assert_eq!(diff, 1600);
            assert_eq!(ar.start_points(), 300);
            assert!(ar.end_points().is_some());
            assert_eq!(ar.end_points().unwrap(), 1900);
            assert_eq!(ar.points(), 1600);
            assert_eq!(ar.era_points(), 1900);
        }

        // Increment authored blocks and current points
        if let Some(pr) = records.get_mut_para_record(authority_idx, None) {
            pr.update_scheduled_core(1001, 3);
            pr.update_points(1600, true);
            assert!(pr.get_para_id_stats(1001).is_some());
            assert!(pr.get_para_id_stats(1002).is_none());
            if let Some(stats) = pr.get_para_id_stats(1001) {
                assert_eq!(stats.points(), 1600);
                assert_eq!(stats.authored_blocks(), 1);
            }
            pr.update_scheduled_core(1001, 4);
            if let Some(stats) = pr.get_para_id_stats(1001) {
                assert_eq!(stats.points(), 1600);
                assert_eq!(stats.core_assignments(), 2);
            }
        }

        let dr: DiscoveryRecord = DiscoveryRecord::with_authority_discovery_key([0; 32]);
        assert_eq!(
            dr.authority_discovery_key(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        records.set_discovery_record(authority_idx, dr);
        assert!(records.get_authority_record(authority_idx, None).is_some());
    }
}
