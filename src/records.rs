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
#![allow(dead_code)]
use crate::config::CONFIG;
use crate::matrix::UserID;
use codec::Decode;
use log::info;
use serde::{Deserialize, Serialize};
use sp_consensus_babe::digests::PreDigest;
use std::{collections::BTreeMap, collections::HashMap, collections::HashSet, hash::Hash};
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
pub type Ratio = f64;
pub type ParaEpochs = Vec<EpochIndex>;
pub type Pattern = Vec<Glyph>;
pub type FlaggedEpochs = Vec<EpochIndex>;
// pub type RecordKey = String;
pub type SS58 = String;

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

pub fn grade(ratio: f64) -> String {
    let p = (ratio * 10000.0).round() as u32;
    match p {
        9901..=10000 => "A+".to_string(),
        9501..=9900 => "A".to_string(),
        9001..=9500 => "B+".to_string(),
        8001..=9000 => "B".to_string(),
        7001..=8000 => "C+".to_string(),
        6001..=7000 => "C".to_string(),
        5001..=6000 => "D+".to_string(),
        4001..=5000 => "D".to_string(),
        _ => "F".to_string(),
    }
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
    first_epoch: EpochIndex,
    eras: HashMap<EpochIndex, EraIndex>,
    blocks: HashMap<BlockKey, BlockNumber>,
    authorities: HashMap<EpochKey, HashSet<AuthorityIndex>>,
    addresses: HashMap<AddressKey, AuthorityIndex>,
    authority_records: HashMap<RecordKey, AuthorityRecord>,
    para_authorities: HashMap<EpochKey, HashSet<AuthorityIndex>>,
    para_records: HashMap<RecordKey, ParaRecord>,
    // Note: we use the following maps to easily manage missed votes and para_id assignment changes
    para_group: HashMap<ParaId, GroupIndex>,
    groups: HashMap<GroupIndex, Vec<AuthorityIndex>>,
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
        let mut eras = HashMap::new();
        eras.insert(current_epoch, current_era);
        Self {
            current_era,
            current_epoch,
            first_epoch: current_epoch,
            eras,
            blocks,
            authorities: HashMap::new(),
            addresses: HashMap::new(),
            authority_records: HashMap::new(),
            para_authorities: HashMap::new(),
            para_records: HashMap::new(),
            para_group: HashMap::new(),
            groups: HashMap::new(),
        }
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
            return self.blocks.get(&BlockKey(epoch_key, BlockKind::Start));
        } else {
            let epoch_key = EpochKey(self.current_era, self.current_epoch);
            return self.blocks.get(&BlockKey(epoch_key, BlockKind::Start));
        }
    }

    pub fn end_block(&self, epoch_key: Option<EpochKey>) -> Option<&BlockNumber> {
        if let Some(epoch_key) = epoch_key {
            return self.blocks.get(&BlockKey(epoch_key, BlockKind::End));
        } else {
            let epoch_key = EpochKey(self.current_era, self.current_epoch);
            return self.blocks.get(&BlockKey(epoch_key, BlockKind::End));
        }
    }

    pub fn current_block(&self) -> Option<&BlockNumber> {
        let block = self.end_block(Some(EpochKey(self.current_era, self.current_epoch)));
        if block.is_none() {
            return self.start_block(Some(EpochKey(self.current_era, self.current_epoch)));
        }
        block
    }

    pub fn start_new_epoch(&mut self, era: EraIndex, epoch: EpochIndex) {
        self.current_era = era;
        self.current_epoch = epoch;
        self.eras.insert(epoch, era);
        info!("New epoch {} at era {} started.", epoch, era);
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
    ) -> Option<(
        bool,
        Option<(
            TotalParaEpochs,
            TotalExceptionalEpochs,
            TotalFlaggedEpochs,
            Ratio,
        )>,
    )> {
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
            if let Some(era_index) = self.eras.get(&epoch_index) {
                let key = EpochKey(*era_index, epoch_index);
                if let Some(auth_idx) = self
                    .addresses
                    .get(&AddressKey(key.clone(), address.to_string()))
                {
                    is_active = true;
                    if let Some(para_record) = self
                        .para_records
                        .get(&RecordKey(key.clone(), auth_idx.clone()))
                    {
                        para_epochs += 1;
                        let tv = para_record.total_votes();
                        let mv = para_record.total_missed_votes();
                        let mvr = mv as f64 / (tv + mv) as f64;
                        // Identify failed and exceptional epochs
                        let grade = grade(1.0 - mvr);
                        if grade == "F" {
                            flagged_epochs += 1;
                        } else if grade == "A+" {
                            exceptional_epochs += 1;
                        }
                        total_votes += tv;
                        missed_votes += mv;
                    }
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

    pub fn get_data_from_all_full_epochs(
        &self,
        address: &AccountId32,
    ) -> Option<(
        (TotalActiveEpochs, AuthoredBlocks, Pattern),
        Option<(
            TotalParaEpochs,
            Points,
            ExplicitVotes,
            ImplicitVotes,
            MissedVotes,
            CoreAssignments,
        )>,
    )> {
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
        let mut core_assignments: CoreAssignments = 0;

        let mut epoch_index = self.current_epoch() - self.total_full_epochs();
        while epoch_index < self.current_epoch() {
            if let Some(era_index) = self.eras.get(&epoch_index) {
                let key = EpochKey(*era_index, epoch_index);
                if let Some(auth_idx) = self
                    .addresses
                    .get(&AddressKey(key.clone(), address.to_string()))
                {
                    active_epochs += 1;
                    if let Some(authority_record) = self
                        .authority_records
                        .get(&RecordKey(key.clone(), auth_idx.clone()))
                    {
                        authored_blocks += authority_record.authored_blocks();
                        para_points += authority_record.para_points();
                        // Get para data
                        if let Some(para_record) = self
                            .para_records
                            .get(&RecordKey(key.clone(), auth_idx.clone()))
                        {
                            para_epochs += 1;
                            explicit_votes += para_record.total_explicit_votes();
                            implicit_votes += para_record.total_implicit_votes();
                            missed_votes += para_record.total_missed_votes();
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
                )),
            ))
        } else {
            Some(((active_epochs, authored_blocks, pattern), None))
        }
    }

    pub fn is_active_at(
        &self,
        address: &AccountId32,
        era_index: EraIndex,
        epoch_index: EpochIndex,
    ) -> bool {
        let key = EpochKey(era_index, epoch_index);
        self.addresses
            .get(&AddressKey(key.clone(), address.to_string()))
            .is_some()
    }

    pub fn insert_group(&mut self, group_idx: GroupIndex, authorities: Vec<AuthorityIndex>) {
        self.groups.insert(group_idx, authorities);
    }

    pub fn get_authorities_from_group(&self, index: GroupIndex) -> Option<Vec<AuthorityIndex>> {
        if let Some(authorities) = self.groups.get(&index) {
            Some(authorities.iter().map(|a| *a).collect())
        } else {
            None
        }
    }

    pub fn update_para_group(&mut self, para_id: ParaId, core: CoreIndex, group_idx: GroupIndex) {
        if let Some(previous_group_idx) = self.para_group.insert(para_id, group_idx) {
            if previous_group_idx == group_idx {
                return;
            }
            // remove assignement from authorities assigned to the current group
            if let Some(authorities) = self.get_authorities_from_group(previous_group_idx) {
                for authority_idx in authorities.iter() {
                    if let Some(para_record) = self.get_mut_para_record(*authority_idx) {
                        para_record.remove_scheduled_core(para_id);
                    }
                }
            }
        }
        // update scheduled core and para_id to the authorities assigned to the group_idx
        if let Some(authorities) = self.get_authorities_from_group(group_idx) {
            for authority_idx in authorities.iter() {
                if let Some(para_record) = self.get_mut_para_record(authority_idx.clone()) {
                    para_record.update_scheduled_core(para_id, core);
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
            // Insert authority_index to the set of para_authorities for the current epoch
            if let Some(para_authorities) = self.get_mut_para_authorities(None) {
                para_authorities.insert(authority_index);
            } else {
                self.para_authorities.insert(
                    EpochKey(self.current_era, self.current_epoch),
                    HashSet::from([authority_index]),
                );
            }
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

    pub fn get_para_authorities(&self, key: Option<EpochKey>) -> Option<Vec<AuthorityIndex>> {
        let key = if let Some(key) = key {
            key
        } else {
            EpochKey(self.current_era, self.current_epoch)
        };
        if let Some(para_authorities) = self.para_authorities.get(&key) {
            Some(para_authorities.iter().map(|a| *a).collect())
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

    pub fn get_mut_para_authorities(
        &mut self,
        key: Option<EpochKey>,
    ) -> Option<&mut HashSet<AuthorityIndex>> {
        if let Some(key) = key {
            self.para_authorities.get_mut(&key)
        } else {
            let key = EpochKey(self.current_era, self.current_epoch);
            self.para_authorities.get_mut(&key)
        }
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

    pub fn remove(&mut self, epoch_key: EpochKey) {
        // Maps that need to be cleaned up
        // blocks: HashMap<BlockKey, BlockNumber>,
        // authorities: HashMap<EpochKey, HashSet<AuthorityIndex>>,
        // addresses: HashMap<AddressKey, AuthorityIndex>,
        // authority_records: HashMap<RecordKey, AuthorityRecord>,
        // para_authorities: HashMap<EpochKey, HashSet<AuthorityIndex>>,
        // para_records: HashMap<RecordKey, ParaRecord>,

        let mut counter = 0;
        // Remove blocks map
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

        if let Some(authority_indexes) = self.authorities.get(&epoch_key.clone()) {
            for auth_idx in authority_indexes.iter() {
                // get authority address first
                if let Some(authority_record) = self
                    .authority_records
                    .get(&RecordKey(epoch_key.clone(), *auth_idx))
                {
                    // remove authority address from addresses map
                    if self
                        .addresses
                        .remove(&AddressKey(
                            epoch_key.clone(),
                            authority_record.address.to_string(),
                        ))
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
                // remove authority records
                if self
                    .authority_records
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthorityRecord {
    // index is the position of the stash in session().validators(None)
    #[serde(rename = "aix")]
    index: AuthorityIndex,
    #[serde(skip_serializing)]
    address: AccountId32,
    #[serde(rename = "sp")]
    start_points: Points,
    #[serde(rename = "ep")]
    end_points: Option<Points>,
    #[serde(rename = "ab")]
    authored_blocks: AuthoredBlocks,
    #[serde(skip_serializing)]
    is_flagged: bool,
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
            is_flagged: false,
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

    pub fn para_points(&self) -> Points {
        if self.points() < (self.authored_blocks() * 20) {
            return 0;
        }
        self.points() - (self.authored_blocks() * 20)
    }

    pub fn authored_blocks(&self) -> AuthoredBlocks {
        self.authored_blocks
    }

    pub fn inc_authored_blocks(&mut self) {
        self.authored_blocks += 1;
    }

    pub fn flag(&mut self) {
        self.is_flagged = true;
    }

    pub fn is_flagged(&self) -> bool {
        self.is_flagged
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
    #[serde(skip)]
    para_stats: BTreeMap<ParaId, ParaStats>,
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
            if para_id == id {
                return true;
            }
        }
        false
    }

    pub fn peers(&self) -> Vec<AuthorityIndex> {
        self.peers.to_vec()
    }

    pub fn update_scheduled_core(&mut self, para_id: ParaId, core: CoreIndex) {
        // Assign current scheduled para_id
        self.para_id = Some(para_id);
        // Verify if a different core as been assigned
        let is_different_core = if let Some(previous_core) = self.core {
            previous_core != core
        } else {
            true
        };
        self.core = Some(core);
        // if different core increment assignments
        if is_different_core {
            let stats = self
                .para_stats
                .entry(para_id)
                .or_insert(ParaStats::default());
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

    pub fn update_points(&mut self, points: Points, is_block_author: bool) {
        if let Some(para_id) = self.para_id {
            // increment current points and authored blocks if the author of the current finalized block
            let stats = self
                .para_stats
                .entry(para_id)
                .or_insert(ParaStats::default());
            stats.points += points;
            stats.authored_blocks += is_block_author as u32;
        }
    }

    pub fn inc_explicit_votes(&mut self, para_id: ParaId) {
        // increment current explicit_votes
        let stats = self
            .para_stats
            .entry(para_id)
            .or_insert(ParaStats::default());
        stats.explicit_votes += 1;
    }

    pub fn inc_implicit_votes(&mut self, para_id: ParaId) {
        // increment current explicit_votes
        let stats = self
            .para_stats
            .entry(para_id)
            .or_insert(ParaStats::default());
        stats.implicit_votes += 1;
    }

    pub fn inc_missed_votes(&mut self, para_id: ParaId) {
        // increment current missed_votes
        let stats = self
            .para_stats
            .entry(para_id)
            .or_insert(ParaStats::default());
        stats.missed_votes += 1;
    }

    pub fn total_points(&self) -> Points {
        self.para_stats.iter().map(|(_, stats)| stats.points).sum()
    }

    pub fn total_authored_blocks(&self) -> AuthoredBlocks {
        self.para_stats
            .iter()
            .map(|(_, stats)| stats.authored_blocks)
            .sum()
    }

    pub fn total_missed_votes(&self) -> Votes {
        self.para_stats
            .iter()
            .map(|(_, stats)| stats.missed_votes)
            .sum()
    }

    pub fn total_implicit_votes(&self) -> Votes {
        self.para_stats
            .iter()
            .map(|(_, stats)| stats.implicit_votes)
            .sum()
    }

    pub fn total_explicit_votes(&self) -> Votes {
        self.para_stats
            .iter()
            .map(|(_, stats)| stats.explicit_votes)
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
            return None;
        } else {
            // calculate ratio
            let ratio = total_missed_votes as f64
                / (total_missed_votes + self.total_implicit_votes() + self.total_explicit_votes())
                    as f64;

            return Some(ratio);
        }
    }

    pub fn total_core_assignments(&self) -> CoreAssignments {
        self.para_stats
            .iter()
            .map(|(_, stats)| stats.core_assignments)
            .sum()
    }

    pub fn get_para_id_stats(&self, para_id: ParaId) -> Option<&ParaStats> {
        self.para_stats.get(&para_id)
    }

    pub fn para_stats(&self) -> &BTreeMap<ParaId, ParaStats> {
        &self.para_stats
    }

    pub fn clone_without_stats(&self) -> ParaRecord {
        ParaRecord {
            index: self.index.clone(),
            group: self.group.clone(),
            core: self.core.clone(),
            para_id: self.para_id.clone(),
            peers: self.peers.clone(),
            para_stats: BTreeMap::new(),
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

#[derive(Debug, Clone)]
pub struct Subscribers {
    current_era: EraIndex,
    current_epoch: EpochIndex,
    subscribers: HashMap<EpochKey, Vec<(AccountId32, UserID)>>,
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

    pub fn subscribe(&mut self, account: AccountId32, user_id: UserID) {
        let key = EpochKey(self.current_era, self.current_epoch);
        if let Some(s) = self.subscribers.get_mut(&key) {
            s.push((account.clone(), user_id.to_string()));
        } else {
            self.subscribers
                .insert(key, vec![(account.clone(), user_id.to_string())]);
        }
        info!(
            "{} subscribed ({}) report for epoch {} era {}",
            user_id.to_string(),
            account.to_string(),
            self.current_epoch(),
            self.current_era(),
        );
    }

    pub fn get(&self, key: Option<EpochKey>) -> Option<&Vec<(AccountId32, UserID)>> {
        if let Some(key) = key {
            self.subscribers.get(&key)
        } else {
            let key = EpochKey(self.current_era, self.current_epoch);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

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
        subscribers.subscribe(account, "@subscriber:matrix.org".to_string());
        assert_eq!(subscribers.get(None).is_some(), true);
        assert_eq!(subscribers.get(Some(EpochKey(era, epoch))).is_some(), true);
        assert_eq!(subscribers.get(Some(EpochKey(era, 30))).is_none(), true);
        assert_eq!(
            subscribers.get(Some(EpochKey(era, epoch))),
            Some(&vec![(
                AccountId32::from_str("DSov56qpKEc32ZjhCN1qTPmTYW3tM65wmsXVkrrtXV3ywpV").unwrap(),
                "@subscriber:matrix.org".to_string()
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

        let pr = ParaRecord::with_index_group_and_peers(1, 2, vec![456, 789]);
        assert_eq!(pr.para_index(), &1);
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
            pr.update_scheduled_core(1001, 3);
            pr.update_points(1600, true);
            assert_eq!(pr.get_para_id_stats(1001).is_some(), true);
            assert_eq!(pr.get_para_id_stats(1002).is_none(), true);
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
    }
}
