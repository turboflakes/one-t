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
use crate::stats::mean;
use codec::Decode;
use log::info;
use sp_consensus_babe::digests::PreDigest;
use std::{
    collections::BTreeMap, collections::HashMap, collections::HashSet, hash::Hash,
    iter::FromIterator, str::FromStr,
};
use subxt::{
    rpc::ChainBlock,
    sp_runtime::{traits::Header as HeaderT, AccountId32, Digest, DigestItem},
    DefaultConfig,
};

pub type BlockNumber = u64;
pub type EraIndex = u32;
pub type EpochIndex = u32;
pub type GroupIndex = u32;
pub type CoreIndex = u32;
pub type ValidatorIndex = u32;
pub type ParaId = u32;
pub type Points = u32;
pub type AuthoredBlocks = u32;
// pub type RecordKey = String;
pub type SS58 = String;
pub type AuthorityIndex = u32;

// Keys to be easily used in BTreeMap
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct EpochKey(pub EraIndex, pub EpochIndex);
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct RecordKey(EpochKey, AuthorityIndex);
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct AddressKey(EpochKey, SS58);
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct BlockKey(EpochKey, BlockKind);

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
enum BlockKind {
    Start,
    End,
}

pub fn decode_authority_index(chain_block: &ChainBlock<DefaultConfig>) -> Option<AuthorityIndex> {
    match chain_block.block.header.digest() {
        Digest { logs } => {
            for digests in logs.iter() {
                match digests {
                    DigestItem::PreRuntime(_, data) => {
                        if let Some(pre) = PreDigest::decode(&mut &data[..]).ok() {
                            return Some(pre.authority_index());
                        } else {
                            return None;
                        }
                    }
                    _ => (),
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct Records {
    current_era: EraIndex,
    current_epoch: EpochIndex,
    blocks: HashMap<BlockKey, BlockNumber>,
    authorities: HashMap<EpochKey, HashSet<AuthorityIndex>>,
    addresses: HashMap<AddressKey, AuthorityIndex>,
    authority_records: HashMap<RecordKey, AuthorityRecord>,
    para_records: HashMap<RecordKey, ParaRecord>,
}

impl Records {
    pub fn with_era_epoch_and_block(
        current_era: EraIndex,
        current_epoch: EpochIndex,
        start_block: BlockNumber,
    ) -> Self {
        let mut blocks = HashMap::new();
        blocks.insert(
            BlockKey(EpochKey(current_era, current_epoch), BlockKind::Start),
            start_block,
        );
        Self {
            current_era,
            current_epoch,
            blocks,
            authorities: HashMap::new(),
            addresses: HashMap::new(),
            authority_records: HashMap::new(),
            para_records: HashMap::new(),
        }
    }

    pub fn current_era(&self) -> EraIndex {
        self.current_era
    }

    pub fn current_epoch(&self) -> EpochIndex {
        self.current_epoch
    }

    pub fn start_block(&self, epoch_key: EpochKey) -> Option<&BlockNumber> {
        self.blocks.get(&BlockKey(epoch_key, BlockKind::Start))
    }

    pub fn end_block(&self, epoch_key: EpochKey) -> Option<&BlockNumber> {
        self.blocks.get(&BlockKey(epoch_key, BlockKind::End))
    }

    pub fn current_block(&self) -> Option<&BlockNumber> {
        self.blocks.get(&BlockKey(
            EpochKey(self.current_era, self.current_epoch),
            BlockKind::End,
        ))
    }

    pub fn start_new_epoch(&mut self, era: EraIndex, epoch: EpochIndex) {
        self.current_era = era;
        self.current_epoch = epoch;
        info!("New epoch {} at era {} started", epoch, era);
    }

    pub fn set_current_block_number(&mut self, block_number: BlockNumber) {
        // insert start block only if it doesn't already exist
        self.blocks
            .entry(BlockKey(
                EpochKey(self.current_era, self.current_epoch),
                BlockKind::Start,
            ))
            .or_insert(block_number);
        // update end block
        self.blocks.insert(
            BlockKey(
                EpochKey(self.current_era, self.current_epoch),
                BlockKind::End,
            ),
            block_number,
        );
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
                EpochKey(self.current_era, self.current_epoch),
                HashSet::from([authority_index]),
            );
        }

        // Map address to the authority_index for the current epoch
        let address_key = AddressKey(
            EpochKey(self.current_era, self.current_epoch),
            address.to_string(),
        );
        self.addresses.entry(address_key).or_insert(authority_index);

        // Map authority_index to the AuthorityRecord for the current epoch
        let record_key = RecordKey(
            EpochKey(self.current_era, self.current_epoch),
            authority_index,
        );
        self.authority_records
            .entry(record_key.clone())
            .or_insert(authority_record);

        // Map authority_index to the ParaRecord for the current epoch
        if let Some(para_record) = para_record {
            self.para_records.entry(record_key).or_insert(para_record);
        }
    }

    pub fn get_authorities(&self, key: Option<EpochKey>) -> Option<Vec<AuthorityIndex>> {
        let key = if let Some(key) = key {
            key
        } else {
            EpochKey(self.current_era, self.current_epoch)
        };
        if let Some(authorities) = self.authorities.get(&key) {
            Some(authorities.iter().map(|a| *a).collect())
        } else {
            None
        }
    }

    pub fn get_mut_authorities(
        &mut self,
        key: Option<EpochKey>,
    ) -> Option<&mut HashSet<AuthorityIndex>> {
        if let Some(key) = key {
            self.authorities.get_mut(&key)
        } else {
            let key = EpochKey(self.current_era, self.current_epoch);
            self.authorities.get_mut(&key)
        }
    }

    pub fn get_mut_authority_record(
        &mut self,
        index: AuthorityIndex,
    ) -> Option<&mut AuthorityRecord> {
        let record_key = RecordKey(EpochKey(self.current_era, self.current_epoch), index);
        self.authority_records.get_mut(&record_key)
    }

    pub fn get_mut_para_record(&mut self, index: AuthorityIndex) -> Option<&mut ParaRecord> {
        let record_key = RecordKey(EpochKey(self.current_era, self.current_epoch), index);
        self.para_records.get_mut(&record_key)
    }

    pub fn get_authority_record(
        &self,
        index: AuthorityIndex,
        key: Option<EpochKey>,
    ) -> Option<&AuthorityRecord> {
        let epoch_key = if let Some(key) = key {
            key
        } else {
            EpochKey(self.current_era, self.current_epoch)
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
            EpochKey(self.current_era, self.current_epoch)
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
            EpochKey(self.current_era, self.current_epoch)
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

    pub fn get_para_record_with_address(
        &self,
        address: &AccountId32,
        key: Option<EpochKey>,
    ) -> Option<&ParaRecord> {
        let epoch_key = if let Some(key) = key {
            key
        } else {
            EpochKey(self.current_era, self.current_epoch)
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
}

#[derive(Debug, Clone)]
pub struct AuthorityRecord {
    index: AuthorityIndex,
    address: AccountId32,
    start_points: Points,
    end_points: Option<Points>,
    authored_blocks: AuthoredBlocks,
}

impl AuthorityRecord {
    pub fn with_index_address_points_and_blocks(
        index: AuthorityIndex,
        address: AccountId32,
        start_points: Points,
        authored_blocks: AuthoredBlocks,
    ) -> Self {
        Self {
            index,
            address,
            start_points,
            end_points: None,
            authored_blocks,
        }
    }

    pub fn authority_index(&self) -> &AuthorityIndex {
        &self.index
    }

    pub fn address(&self) -> &AccountId32 {
        &self.address
    }

    pub fn start_points(&self) -> Points {
        self.start_points
    }

    pub fn end_points(&self) -> Option<Points> {
        self.end_points
    }

    pub fn points(&self) -> Points {
        if let Some(end_points) = self.end_points {
            end_points - self.start_points
        } else {
            self.start_points
        }
    }

    pub fn authored_blocks(&self) -> AuthoredBlocks {
        self.authored_blocks
    }

    pub fn inc_authored_blocks(&mut self) {
        self.authored_blocks += 1;
    }

    pub fn update_current_points(&mut self, current_points: Points) -> Points {
        fn diff(current: Points, last: Points) -> Points {
            if current > last {
                current - last
            } else {
                0
            }
        }
        let diff_points = if let Some(end_points) = self.end_points {
            diff(current_points, end_points)
        } else {
            diff(current_points, self.start_points)
        };
        self.end_points = Some(current_points);
        diff_points
    }
}

#[derive(Debug, Clone, Default)]
pub struct ParaRecord {
    group: Option<GroupIndex>,
    core: Option<CoreIndex>,
    peers: Vec<AuthorityIndex>,
    para_stats: BTreeMap<ParaId, ParaStats>,
}

impl ParaRecord {
    pub fn with_group_and_peers(group_index: GroupIndex, peers: Vec<AuthorityIndex>) -> Self {
        Self {
            group: Some(group_index),
            core: None,
            peers,
            para_stats: BTreeMap::new(),
        }
    }

    pub fn group(&self) -> Option<GroupIndex> {
        self.group
    }

    pub fn core(&self) -> Option<CoreIndex> {
        self.core
    }

    pub fn peers(&self) -> Vec<AuthorityIndex> {
        self.peers.to_vec()
    }

    pub fn update(
        &mut self,
        core: CoreIndex,
        para_id: ParaId,
        points: Points,
        is_block_author: bool,
    ) {
        let is_different_core = if let Some(previous_core) = self.core {
            previous_core != core
        } else {
            true
        };
        self.core = Some(core);

        // increment current points, increment core assignments and increment authored blocks
        let mut stats = self
            .para_stats
            .entry(para_id)
            .or_insert(ParaStats::default());
        stats.points += points;
        stats.core_assignments += is_different_core as u32;
        stats.authored_blocks += is_block_author as u32;
    }

    pub fn get_para_id_stats(&self, para_id: ParaId) -> Option<&ParaStats> {
        self.para_stats.get(&para_id)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ParaStats {
    points: Points,
    core_assignments: u32,
    authored_blocks: AuthoredBlocks,
}

impl ParaStats {
    pub fn points(&self) -> Points {
        self.points
    }

    pub fn core_assignments(&self) -> u32 {
        self.core_assignments
    }

    pub fn authored_blocks(&self) -> AuthoredBlocks {
        self.authored_blocks
    }
}

#[derive(Debug, Clone)]
pub struct Subscribers {
    current_era: EraIndex,
    current_epoch: EpochIndex,
    subscribers: HashMap<EpochKey, Vec<AccountId32>>,
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

    pub fn subscribe(&mut self, account: AccountId32) {
        let key = EpochKey(self.current_era, self.current_epoch);
        if let Some(s) = self.subscribers.get_mut(&key) {
            s.push(account.clone());
        } else {
            self.subscribers.insert(key, vec![account.clone()]);
        }
        info!(
            "Account {} subscribed for epoch {} era {}",
            account.to_string(),
            self.current_epoch(),
            self.current_era(),
        );
    }

    pub fn get(&self, key: Option<EpochKey>) -> Option<&Vec<AccountId32>> {
        if let Some(key) = key {
            self.subscribers.get(&key)
        } else {
            let key = EpochKey(self.current_era, self.current_epoch);
            self.subscribers.get(&key)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        subscribers.subscribe(account);
        assert_eq!(subscribers.get(None).is_some(), true);
        assert_eq!(subscribers.get(Some(EpochKey(era, epoch))).is_some(), true);
        assert_eq!(subscribers.get(Some(EpochKey(era, 30))).is_none(), true);
        assert_eq!(
            subscribers.get(Some(EpochKey(era, epoch))),
            Some(&vec![AccountId32::from_str(
                "DSov56qpKEc32ZjhCN1qTPmTYW3tM65wmsXVkrrtXV3ywpV"
            )
            .unwrap()])
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
        let ar = AuthorityRecord::with_index_address_points_and_blocks(
            authority_idx,
            account.clone(),
            300,
            2,
        );
        assert_eq!(ar.authority_index(), &authority_idx);
        assert_eq!(ar.address(), &account);
        assert_eq!(ar.start_points(), 300);
        assert_eq!(ar.end_points().is_none(), true);
        assert_eq!(ar.authored_blocks(), 2);

        let pr = ParaRecord::with_group_and_peers(2, vec![456, 789]);
        assert_eq!(pr.group(), Some(2));
        assert_eq!(pr.peers(), vec![456, 789]);

        records.insert(&account, authority_idx, ar, Some(pr));

        assert_eq!(records.get_authorities(None).is_some(), true);
        assert_eq!(
            records
                .get_authorities(Some(EpochKey(era, epoch)))
                .is_some(),
            true
        );
        assert_eq!(
            records.get_authorities(Some(EpochKey(era, 0))).is_none(),
            true
        );

        if let Some(authorities) = records.get_authorities(None) {
            assert_eq!(*authorities, vec![authority_idx]);
        }

        // Increment authored blocks and current points
        if let Some(ar) = records.get_mut_authority_record(authority_idx) {
            ar.inc_authored_blocks();
            assert_eq!(ar.authored_blocks(), 3);
            let diff = ar.update_current_points(1900);
            assert_eq!(diff, 1600);
            assert_eq!(ar.start_points(), 300);
            assert_eq!(ar.end_points().is_some(), true);
            assert_eq!(ar.end_points().unwrap(), 1900);
            assert_eq!(ar.points(), 1600);
        }

        // Increment authored blocks and current points
        if let Some(pr) = records.get_mut_para_record(authority_idx) {
            pr.update(3, 1001, 1600, true);
            assert_eq!(pr.group(), Some(2));
            assert_eq!(pr.core(), Some(3));
            assert_eq!(pr.get_para_id_stats(1001).is_some(), true);
            assert_eq!(pr.get_para_id_stats(1002).is_none(), true);
            if let Some(stats) = pr.get_para_id_stats(1001) {
                assert_eq!(stats.points(), 1600);
                assert_eq!(stats.core_assignments(), 1);
                assert_eq!(stats.authored_blocks(), 1);
            }
            pr.update(4, 1001, 10, false);
            if let Some(stats) = pr.get_para_id_stats(1001) {
                assert_eq!(stats.points(), 1610);
                assert_eq!(stats.core_assignments(), 2);
                assert_eq!(stats.authored_blocks(), 1);
            }
            pr.update(5, 1020, 100, false);
            if let Some(stats) = pr.get_para_id_stats(1020) {
                assert_eq!(stats.points(), 100);
                assert_eq!(stats.core_assignments(), 1);
                assert_eq!(stats.authored_blocks(), 0);
            }
        }
    }
}
