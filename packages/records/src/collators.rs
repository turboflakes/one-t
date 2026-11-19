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

use crate::{BlockNumber, EpochIndex, ParaId, SS58};
use log::warn;
use serde::{Deserialize, Serialize};
use subxt::utils::AccountId32;

pub type Slot = u64;

/// Maximum number of consecutive empty slots we are willing to attribute to their
/// owners. Anything above is considered downtime of the indexer or the chain.
const MAX_SLOT_GAP: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CollatorKind {
    #[serde(rename = "I")]
    Invulnerable,
    #[serde(rename = "P")]
    Permissionless,
    #[serde(rename = "V")]
    Validator,
    // session validator not found in invulnerables, candidates or drawn collators
    #[serde(rename = "U")]
    Unknown,
}

/// Position of a validator in the collators of a parachain, once it is part of the draw
/// Note: the slots owned by the collator are the ones where `slot % collators == cix`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollationIndex {
    // Note: alias to read the values cached before the rename
    #[serde(rename = "pid", alias = "para_id")]
    pub para_id: ParaId,
    // position of the validator in the parachain session validators (aura authorities)
    pub cix: u32,
    // slot the validator is collating right now and the blocks produced so far in it,
    // these are not cached with the draw, they are set by the api from `LiveSlot`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<Slot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pb: Option<u32>,
    // era points earned so far in that slot
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pt: Option<u32>,
}

/// Slot a parachain is currently in, as of the last block followed
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LiveSlot {
    // slot index, Note: alias to read the values cached before the rename
    #[serde(rename = "ix", alias = "slot")]
    pub slot: Slot,
    // position of the slot owner in the collators of the session and its address
    pub cix: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<SS58>,
    // blocks produced in the slot so far
    pub pb: u32,
    // era points earned in the slot so far
    #[serde(default)]
    pub pt: u32,
    // last parachain block followed, the one that is in the slot
    #[serde(default)]
    pub bix: BlockNumber,
}

impl CollationIndex {
    pub fn new(para_id: ParaId, cix: u32) -> Self {
        Self {
            para_id,
            cix,
            slot: None,
            pb: None,
            pt: None,
        }
    }

    /// Whether the validator owns the slot a parachain is currently in
    pub fn set_live(&mut self, live: &LiveSlot) {
        if live.cix == Some(self.cix) {
            self.slot = Some(live.slot);
            self.pb = Some(live.pb);
            self.pt = Some(live.pt);
        }
    }

    /// Set, or remove with `None`, the index of a parachain keeping the list ordered by parachain
    pub fn set(list: &mut Vec<CollationIndex>, para_id: ParaId, cix: Option<u32>) {
        list.retain(|c| c.para_id != para_id);
        if let Some(cix) = cix {
            list.push(CollationIndex::new(para_id, cix));
        }
        list.sort_by_key(|c| c.para_id);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CollatorRecord {
    // collator address and kind
    address: SS58,
    kind: Option<CollatorKind>,
    // position of the collator in the parachain session collators (aura authorities)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cix: Option<u32>,
    // slots owned by the collator and closed in the session
    #[serde(rename = "os")]
    owned_slots: u32,
    // blocks that were possible to be produced in the owned slots
    #[serde(rename = "eb")]
    expected_blocks: u32,
    // blocks actually produced in the owned slots
    #[serde(rename = "pb")]
    produced_blocks: u32,
    // era points earned by the produced blocks
    #[serde(rename = "pt", default)]
    points: u32,
    // block numbers produced
    #[serde(rename = "pbn")]
    produced_block_numbers: Vec<BlockNumber>,
    // slots owned where no block was produced at all
    #[serde(rename = "msl")]
    missed_slots: Vec<Slot>,
}

/// Counters of a collator, serialized to the validators response
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CollatorSummary {
    // Note: kind is skipped when not set, e.g. in the validators response where collators are always validators
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<CollatorKind>,
    // owned slots
    pub os: u32,
    // expected blocks
    pub eb: u32,
    // produced blocks
    pub pb: u32,
    // era points
    #[serde(default)]
    pub pt: u32,
    // missed slots
    pub ms: u32,
}

impl CollatorSummary {
    pub fn is_empty(&self) -> bool {
        self.os == 0
    }

    /// Missed collation ratio: 1 - produced blocks / expected blocks, clamped to [0, 1],
    /// none if there were no blocks expected
    pub fn mcr(&self) -> Option<f64> {
        if self.eb == 0 {
            return None;
        }
        Some((1.0 - self.pb as f64 / self.eb as f64).clamp(0.0, 1.0))
    }

    /// Add the counters of another summary, kind is not aggregated
    pub fn add(&mut self, other: &CollatorSummary) {
        self.os += other.os;
        self.eb += other.eb;
        self.pb += other.pb;
        self.pt += other.pt;
        self.ms += other.ms;
    }
}

/// Number of collators of a parachain session by kind
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollatorInfra {
    // invulnerables
    pub ni: u32,
    // permissionless
    pub np: u32,
    // validators
    pub nv: u32,
}

impl CollatorInfra {
    /// Count a collator, kinds that are not known are not counted
    pub fn add(&mut self, kind: Option<CollatorKind>) {
        match kind {
            Some(CollatorKind::Invulnerable) => self.ni += 1,
            Some(CollatorKind::Permissionless) => self.np += 1,
            Some(CollatorKind::Validator) => self.nv += 1,
            _ => {}
        }
    }
}

/// Counters of the collators of a parachain in a session
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CollatorSessionStats {
    // first and last parachain block tracked in the session
    #[serde(default)]
    pub sbix: BlockNumber,
    #[serde(default)]
    pub ebix: BlockNumber,
    // number of collators with slots closed in the session
    pub nc: u32,
    // owned slots
    pub os: u32,
    // expected blocks
    pub eb: u32,
    // produced blocks
    pub pb: u32,
    // era points
    #[serde(default)]
    pub pt: u32,
    // missed slots
    pub ms: u32,
    // slot the parachain is in right now, only set by the api for the current session
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<LiveSlot>,
}

impl CollatorSessionStats {
    pub fn is_empty(&self) -> bool {
        self.nc == 0 && self.sbix == 0
    }

    /// Add the counters of a collator record
    pub fn add(&mut self, record: &CollatorRecord) {
        let summary = record.summary();
        self.nc += 1;
        self.os += summary.os;
        self.eb += summary.eb;
        self.pb += summary.pb;
        self.pt += summary.pt;
        self.ms += summary.ms;
    }
}

impl CollatorRecord {
    pub fn summary(&self) -> CollatorSummary {
        CollatorSummary {
            kind: self.kind,
            os: self.owned_slots,
            eb: self.expected_blocks,
            pb: self.produced_blocks,
            pt: self.points,
            ms: self.missed_slots.len() as u32,
        }
    }

    /// Summary without the collator kind
    pub fn summary_without_kind(&self) -> CollatorSummary {
        CollatorSummary {
            kind: None,
            ..self.summary()
        }
    }

    pub fn new(address: SS58, kind: CollatorKind) -> Self {
        Self {
            address,
            kind: Some(kind),
            ..Default::default()
        }
    }

    pub fn address(&self) -> &SS58 {
        &self.address
    }

    pub fn kind(&self) -> Option<CollatorKind> {
        self.kind
    }

    pub fn cix(&self) -> Option<u32> {
        self.cix
    }

    /// Set the position of the collator in the session, it is the one of the last slot added
    pub fn set_cix(&mut self, cix: Option<u32>) {
        self.cix = cix;
    }

    /// Add a closed slot to the record
    pub fn add_slot(
        &mut self,
        slot: Slot,
        blocks: &[BlockNumber],
        expected_blocks: u32,
        points_per_block: u32,
    ) {
        self.owned_slots += 1;
        self.expected_blocks += expected_blocks;
        self.produced_blocks += blocks.len() as u32;
        self.points += blocks.len() as u32 * points_per_block;
        self.produced_block_numbers.extend_from_slice(blocks);
        if blocks.is_empty() {
            self.missed_slots.push(slot);
        }
    }

    pub fn owned_slots(&self) -> u32 {
        self.owned_slots
    }

    pub fn expected_blocks(&self) -> u32 {
        self.expected_blocks
    }

    pub fn produced_blocks(&self) -> u32 {
        self.produced_blocks
    }

    pub fn produced_block_numbers(&self) -> &[BlockNumber] {
        &self.produced_block_numbers
    }

    pub fn missed_slots(&self) -> &[Slot] {
        &self.missed_slots
    }

    /// Missed slot ratio: 1 - produced / expected, clamped to [0, 1]
    pub fn msr(&self) -> Option<f64> {
        if self.expected_blocks == 0 {
            return None;
        }
        let ratio = 1.0 - self.produced_blocks as f64 / self.expected_blocks as f64;
        Some(ratio.clamp(0.0, 1.0))
    }
}

/// A slot that was closed in a parachain session
#[derive(Debug, Clone, PartialEq)]
pub struct ClosedSlot {
    pub session: EpochIndex,
    pub slot: Slot,
    pub owner: Option<(AccountId32, CollatorKind)>,
    // position of the owner in the collators of the session
    pub owner_index: Option<u32>,
    pub blocks: Vec<BlockNumber>,
    pub expected_blocks: u32,
    // era points per block in force when the slot was closed
    pub points_per_block: u32,
}

#[derive(Debug, Clone)]
struct OpenSlot {
    slot: Slot,
    owner: Option<AccountId32>,
    blocks: Vec<BlockNumber>,
    // first slot observed after (re)start, the slot start is unknown
    partial: bool,
}

/// Follows the parachain block by block and closes slots, attributing them to their owners.
/// Note: closed slots are returned to be added to the collator records.
#[derive(Debug, Clone, Default)]
pub struct ParaSlots {
    blocks_per_slot: u64,
    points_per_block: u32,
    last_block: Option<BlockNumber>,
    session: Option<EpochIndex>,
    // collators ordered as the aura authorities
    collators: Vec<(AccountId32, CollatorKind)>,
    // collators before the last rotation, kept to compare slot owners right after a rotation
    previous_collators: Option<Vec<(AccountId32, CollatorKind)>>,
    open_slot: Option<OpenSlot>,
}

impl ParaSlots {
    pub fn is_initialized(&self) -> bool {
        self.blocks_per_slot > 0 && self.session.is_some() && !self.collators.is_empty()
    }

    pub fn last_block(&self) -> Option<BlockNumber> {
        self.last_block
    }

    pub fn session(&self) -> Option<EpochIndex> {
        self.session
    }

    pub fn collators(&self) -> &[(AccountId32, CollatorKind)] {
        &self.collators
    }

    pub fn set_blocks_per_slot(&mut self, blocks_per_slot: u64) {
        self.blocks_per_slot = blocks_per_slot;
    }

    pub fn points_per_block(&self) -> u32 {
        self.points_per_block
    }

    /// Set the era points a validator earns for each block collated
    pub fn set_points_per_block(&mut self, points_per_block: u32) {
        self.points_per_block = points_per_block;
    }

    /// Resume from a block already counted, blocks up to it are ignored.
    pub fn set_last_block(&mut self, number: BlockNumber) {
        self.last_block = Some(number);
    }

    /// Set the parachain session and the collators ordered as the aura authorities.
    pub fn set_session(&mut self, session: EpochIndex) {
        self.session = Some(session);
    }

    pub fn set_collators(&mut self, collators: Vec<(AccountId32, CollatorKind)>) {
        let previous = std::mem::replace(&mut self.collators, collators);
        if !previous.is_empty() {
            self.previous_collators = Some(previous);
        }
    }

    /// Collators before the last rotation, available once until the next block is processed.
    pub fn take_previous_collators(&mut self) -> Option<Vec<(AccountId32, CollatorKind)>> {
        self.previous_collators.take()
    }

    /// Forget the open slot, used when blocks could not be followed continuously.
    pub fn break_continuity(&mut self) {
        self.open_slot = None;
    }

    /// Slot the parachain is currently in, the one of the last block followed
    pub fn live_slot(&self) -> Option<LiveSlot> {
        let open = self.open_slot.as_ref()?;
        let cix = open.owner.and_then(|owner| {
            self.collators
                .iter()
                .position(|(c, _)| *c == owner)
                .map(|i| i as u32)
        });
        Some(LiveSlot {
            slot: open.slot,
            cix,
            owner: open.owner.map(|owner| owner.to_string()),
            pb: open.blocks.len() as u32,
            pt: open.blocks.len() as u32 * self.points_per_block,
            bix: self.last_block.unwrap_or_default(),
        })
    }

    /// Owner of a slot according to the current set of collators.
    pub fn slot_owner(&self, slot: Slot) -> Option<&(AccountId32, CollatorKind)> {
        if self.collators.is_empty() {
            return None;
        }
        self.collators
            .get((slot % self.collators.len() as u64) as usize)
    }

    /// Process a block authored in `slot`. Blocks must be given in ascending order.
    /// Returns the slots closed by this block.
    pub fn on_block(&mut self, number: BlockNumber, slot: Slot) -> Vec<ClosedSlot> {
        let mut closed_slots = Vec::new();
        if let Some(last) = self.last_block {
            if number <= last {
                warn!("Para: block {number} already processed (last {last}), skipping");
                return closed_slots;
            }
        }
        self.last_block = Some(number);

        match self.open_slot.take() {
            Some(mut open) if open.slot == slot => {
                open.blocks.push(number);
                self.open_slot = Some(open);
            }
            Some(open) if open.slot < slot => {
                let closed = open.slot;
                closed_slots.extend(self.close_slot(open));
                // slots without blocks between the closed and the new one
                if slot - closed - 1 > MAX_SLOT_GAP {
                    warn!(
                        "Para: gap of {} slots before block {number}, not attributed",
                        slot - closed - 1
                    );
                } else {
                    for missed in closed + 1..slot {
                        closed_slots.extend(self.closed_slot(
                            missed,
                            self.slot_owner(missed).copied(),
                            Vec::new(),
                        ));
                    }
                }
                self.open_slot = Some(self.new_open_slot(slot, number, false));
            }
            Some(open) => {
                warn!(
                    "Para: block {number} has slot {slot} before open slot {}, skipping",
                    open.slot
                );
                self.open_slot = Some(open);
            }
            None => {
                self.open_slot = Some(self.new_open_slot(slot, number, true));
            }
        }
        closed_slots
    }

    fn new_open_slot(&self, slot: Slot, number: BlockNumber, partial: bool) -> OpenSlot {
        OpenSlot {
            slot,
            owner: self.slot_owner(slot).map(|(a, _)| *a),
            blocks: vec![number],
            partial,
        }
    }

    fn close_slot(&self, open: OpenSlot) -> Option<ClosedSlot> {
        if open.partial {
            return None;
        }
        let owner = open.owner.and_then(|a| {
            self.collators
                .iter()
                .find(|(c, _)| *c == a)
                .map(|(c, k)| (*c, *k))
        });
        self.closed_slot(open.slot, owner, open.blocks)
    }

    // ASSUMPTION: a slot is credited to the parachain session in which it closes.
    fn closed_slot(
        &self,
        slot: Slot,
        owner: Option<(AccountId32, CollatorKind)>,
        blocks: Vec<BlockNumber>,
    ) -> Option<ClosedSlot> {
        let owner_index = owner.as_ref().and_then(|(account, _)| {
            self.collators
                .iter()
                .position(|(c, _)| c == account)
                .map(|i| i as u32)
        });
        Some(ClosedSlot {
            session: self.session?,
            slot,
            owner,
            owner_index,
            blocks,
            expected_blocks: self.blocks_per_slot as u32,
            points_per_block: self.points_per_block,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acc(n: u8) -> AccountId32 {
        AccountId32([n; 32])
    }

    fn tracker() -> ParaSlots {
        let mut t = ParaSlots::default();
        t.set_blocks_per_slot(3);
        t.set_points_per_block(20);
        t.set_session(10);
        t.set_collators(vec![
            (acc(0), CollatorKind::Invulnerable),
            (acc(1), CollatorKind::Validator),
            (acc(2), CollatorKind::Validator),
        ]);
        t
    }

    #[test]
    fn first_slot_is_dropped_and_full_slot_is_closed() {
        let mut t = tracker();
        // slot 3 (owner idx 0) partial, slot 4 (owner idx 1) full, slot 5 starts
        assert!(t.on_block(1, 3).is_empty());
        assert!(t.on_block(2, 4).is_empty());
        assert!(t.on_block(3, 4).is_empty());
        assert!(t.on_block(4, 4).is_empty());
        let closed = t.on_block(5, 5);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].slot, 4);
        assert_eq!(closed[0].session, 10);
        assert_eq!(closed[0].owner, Some((acc(1), CollatorKind::Validator)));
        assert_eq!(closed[0].blocks, vec![2, 3, 4]);
        assert_eq!(closed[0].expected_blocks, 3);
    }

    #[test]
    fn skipped_slots_are_closed_without_blocks() {
        let mut t = tracker();
        t.on_block(1, 3);
        t.on_block(2, 4);
        t.on_block(3, 4);
        // slots 5 (idx 2) and 6 (idx 0) have no blocks, slot 7 (idx 1) starts
        let closed = t.on_block(4, 7);
        assert_eq!(closed.len(), 3);
        assert_eq!(closed[0].blocks, vec![2, 3]);
        assert_eq!(closed[1].owner_index, Some(2));
        assert_eq!(closed[1].slot, 5);
        assert_eq!(closed[1].owner, Some((acc(2), CollatorKind::Validator)));
        assert!(closed[1].blocks.is_empty());
        assert_eq!(closed[2].slot, 6);
        assert_eq!(closed[2].owner, Some((acc(0), CollatorKind::Invulnerable)));
    }

    #[test]
    fn collation_index_is_set_by_para_id() {
        let mut list = Vec::new();
        CollationIndex::set(&mut list, 1004, Some(3));
        CollationIndex::set(&mut list, 1000, Some(7));
        assert_eq!(
            serde_json::to_string(&list).unwrap(),
            r#"[{"pid":1000,"cix":7},{"pid":1004,"cix":3}]"#
        );
        // the index changes after a reshuffle
        CollationIndex::set(&mut list, 1000, Some(1));
        assert_eq!(list[0], CollationIndex::new(1000, 1));
        // values cached before the rename are still read
        let old: Vec<CollationIndex> =
            serde_json::from_str(r#"[{"para_id":1000,"cix":2}]"#).unwrap();
        assert_eq!(old, vec![CollationIndex::new(1000, 2)]);
        // and is removed when the validator leaves the draw
        CollationIndex::set(&mut list, 1004, None);
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn live_slot_is_the_open_slot_and_its_owner() {
        let mut t = tracker();
        assert_eq!(t.live_slot(), None);
        t.on_block(1, 4);
        // slot 4 belongs to the collator at index 1
        assert_eq!(
            t.live_slot(),
            Some(LiveSlot {
                slot: 4,
                cix: Some(1),
                owner: Some(acc(1).to_string()),
                pb: 1,
                pt: 20,
                bix: 1
            })
        );
        t.on_block(2, 4);
        assert_eq!(t.live_slot().unwrap().pb, 2);
        assert_eq!(t.live_slot().unwrap().bix, 2);
        t.on_block(3, 5);
        assert_eq!(
            t.live_slot(),
            Some(LiveSlot {
                slot: 5,
                cix: Some(2),
                owner: Some(acc(2).to_string()),
                pb: 1,
                pt: 20,
                bix: 3
            })
        );

        // only the validator that owns the slot gets it
        let live = t.live_slot().unwrap();
        let mut owner = CollationIndex::new(1000, 2);
        let mut other = CollationIndex::new(1000, 1);
        owner.set_live(&live);
        other.set_live(&live);
        assert_eq!(
            (owner.slot, owner.pb, owner.pt),
            (Some(5), Some(1), Some(20))
        );
        assert_eq!((other.slot, other.pb, other.pt), (None, None, None));
    }

    #[test]
    fn already_processed_blocks_are_ignored() {
        let mut t = tracker();
        t.on_block(5, 3);
        t.on_block(5, 4);
        t.on_block(4, 4);
        assert_eq!(t.last_block(), Some(5));
    }

    #[test]
    fn summary_uses_abbreviations() {
        let mut r = CollatorRecord::new("a".to_string(), CollatorKind::Validator);
        r.add_slot(4, &[1, 2], 2, 20);
        r.add_slot(5, &[], 2, 20);
        assert_eq!(
            serde_json::to_string(&r.summary()).unwrap(),
            r#"{"kind":"V","os":2,"eb":4,"pb":2,"pt":40,"ms":1}"#
        );
    }

    #[test]
    fn summary_without_kind_omits_kind() {
        let mut r = CollatorRecord::new("a".to_string(), CollatorKind::Validator);
        r.add_slot(4, &[1, 2], 2, 20);
        assert_eq!(
            serde_json::to_string(&r.summary_without_kind()).unwrap(),
            r#"{"os":1,"eb":2,"pb":2,"pt":40,"ms":0}"#
        );
        assert!(r.summary().kind.is_some());
    }

    #[test]
    fn mcr_is_the_ratio_of_missed_blocks() {
        let mut summary = CollatorSummary::default();
        assert_eq!(summary.mcr(), None);
        summary.eb = 24;
        summary.pb = 24;
        assert_eq!(summary.mcr(), Some(0.0));
        summary.pb = 18;
        assert_eq!(summary.mcr(), Some(0.25));
        summary.pb = 30;
        assert_eq!(summary.mcr(), Some(0.0));
    }

    #[test]
    fn summaries_are_added_without_kind() {
        let mut a = CollatorRecord::new("a".to_string(), CollatorKind::Validator);
        a.add_slot(4, &[1, 2], 2, 20);
        let mut b = CollatorRecord::new("a".to_string(), CollatorKind::Validator);
        b.add_slot(5, &[], 2, 10);
        let mut total = CollatorSummary::default();
        assert!(total.is_empty());
        total.add(&a.summary_without_kind());
        total.add(&b.summary_without_kind());
        assert_eq!(
            serde_json::to_string(&total).unwrap(),
            r#"{"os":2,"eb":4,"pb":2,"pt":40,"ms":1}"#
        );
    }

    #[test]
    fn session_stats_sum_collators() {
        let mut a = CollatorRecord::new("a".to_string(), CollatorKind::Validator);
        a.add_slot(4, &[1, 2], 2, 20);
        let mut b = CollatorRecord::new("b".to_string(), CollatorKind::Invulnerable);
        b.add_slot(5, &[], 2, 20);
        let mut stats = CollatorSessionStats::default();
        assert!(stats.is_empty());
        stats.add(&a);
        stats.add(&b);
        assert_eq!(
            stats,
            CollatorSessionStats {
                nc: 2,
                os: 2,
                eb: 4,
                pb: 2,
                pt: 40,
                ms: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn record_msr() {
        let mut r = CollatorRecord::new("a".to_string(), CollatorKind::Validator);
        assert_eq!(r.msr(), None);
        r.add_slot(4, &[1, 2, 3], 3, 0);
        r.add_slot(5, &[], 3, 0);
        assert_eq!(r.owned_slots(), 2);
        assert_eq!(r.produced_blocks(), 3);
        assert_eq!(r.missed_slots(), &[5]);
        assert_eq!(r.msr(), Some(0.5));
    }
}
