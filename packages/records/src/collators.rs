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

use crate::{BlockNumber, EpochIndex, SS58};
use log::warn;
use serde::{Deserialize, Serialize};
use subxt::utils::AccountId32;

pub type Slot = u64;

/// Maximum number of consecutive empty slots we are willing to attribute to their
/// owners. Anything above is considered downtime of the indexer or the chain.
const MAX_SLOT_GAP: u64 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CollatorKind {
    Invulnerable,
    Permissionless,
    Validator,
    // session validator not found in invulnerables, candidates or drawn collators
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CollatorRecord {
    // collator address and kind
    address: SS58,
    kind: Option<CollatorKind>,
    // slots owned by the collator and closed in the session
    owned_slots: u32,
    // blocks that were possible to be produced in the owned slots
    expected_blocks: u32,
    // blocks actually produced in the owned slots
    produced_blocks: u32,
    // block numbers produced
    produced_block_numbers: Vec<BlockNumber>,
    // slots owned where no block was produced at all
    missed_slots: Vec<Slot>,
}

impl CollatorRecord {
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

    /// Add a closed slot to the record
    pub fn add_slot(&mut self, slot: Slot, blocks: &[BlockNumber], expected_blocks: u32) {
        self.owned_slots += 1;
        self.expected_blocks += expected_blocks;
        self.produced_blocks += blocks.len() as u32;
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
    pub blocks: Vec<BlockNumber>,
    pub expected_blocks: u32,
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
        Some(ClosedSlot {
            session: self.session?,
            slot,
            owner,
            blocks,
            expected_blocks: self.blocks_per_slot as u32,
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
        assert_eq!(closed[1].slot, 5);
        assert_eq!(closed[1].owner, Some((acc(2), CollatorKind::Validator)));
        assert!(closed[1].blocks.is_empty());
        assert_eq!(closed[2].slot, 6);
        assert_eq!(closed[2].owner, Some((acc(0), CollatorKind::Invulnerable)));
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
    fn record_msr() {
        let mut r = CollatorRecord::new("a".to_string(), CollatorKind::Validator);
        assert_eq!(r.msr(), None);
        r.add_slot(4, &[1, 2, 3], 3);
        r.add_slot(5, &[], 3);
        assert_eq!(r.owned_slots(), 2);
        assert_eq!(r.produced_blocks(), 3);
        assert_eq!(r.missed_slots(), &[5]);
        assert_eq!(r.msr(), Some(0.5));
    }
}
