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
use crate::errors::OnetError;
use crate::matrix::UserID;
use crate::onet::Param;
use crate::report::Subset;
use log::info;
use serde::{
    de::{Deserializer, Error as DeError},
    {Deserialize, Serialize, Serializer},
};

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    convert::TryInto,
    hash::Hash,
    net::IpAddr,
};
use subxt::utils::AccountId32;
pub trait Validity {
    fn is_empty(&self) -> bool;
}

pub type BlockNumber = u64;

impl Validity for BlockNumber {
    fn is_empty(&self) -> bool {
        *self == 0
    }
}

pub type EraIndex = u32;
pub type EpochIndex = u32;

impl Validity for EpochIndex {
    fn is_empty(&self) -> bool {
        *self == 0
    }
}

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
pub type DisputeKind = String;
pub type AuthorityDiscoveryKey = [u8; 32];

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
pub struct PublicKey(EpochKey, String);

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

pub fn grade(ratio: f64) -> Grade {
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
    discovery_records: HashMap<RecordKey, DiscoveryRecord>,
    // Note: we use the following maps to easily manage missed votes and para_id assignment changes and core assignments
    core_para: HashMap<CoreIndex, Option<ParaId>>,
    para_group: HashMap<ParaId, GroupIndex>,
    groups: HashMap<GroupIndex, Vec<AuthorityIndex>>,
    authority_discovery_keys: HashMap<PublicKey, AuthorityIndex>,
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
            discovery_records: HashMap::new(),
            core_para: HashMap::new(),
            para_group: HashMap::new(),
            groups: HashMap::new(),
            authority_discovery_keys: HashMap::new(),
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

    // deprecated: use finalized_block
    pub fn current_block(&self) -> Option<&BlockNumber> {
        let block = self.end_block(Some(EpochKey(self.current_era, self.current_epoch)));
        if block.is_none() {
            return self.start_block(Some(EpochKey(self.current_era, self.current_epoch)));
        }
        block
    }

    pub fn finalized_block(&self) -> Option<&BlockNumber> {
        let block = self.end_block(Some(EpochKey(self.current_era, self.current_epoch)));
        if block.is_none() {
            return self.start_block(Some(EpochKey(self.current_era, self.current_epoch)));
        }
        block
    }

    pub fn best_block(&self) -> Option<&BlockNumber> {
        let epoch_key = EpochKey(self.current_era, self.current_epoch);
        return self.blocks.get(&BlockKey(epoch_key, BlockKind::Best));
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

    pub fn set_best_block_number(&mut self, block_number: BlockNumber) {
        self.blocks.insert(
            BlockKey(
                EpochKey(self.current_era, self.current_epoch),
                BlockKind::Best,
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
                        if grade == Grade::F {
                            flagged_epochs += 1;
                        } else if grade == Grade::Ap {
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
                        authored_blocks += authority_record.total_authored_blocks();
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
                if let Some(para_record) =
                    self.get_mut_para_record(authority_idx.clone(), epoch_idx)
                {
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
                    if let Some(para_record) =
                        self.get_mut_para_record(authority_idx.clone(), epoch_idx)
                    {
                        para_record.set_core_assignment(para_id, core);
                    }
                }
            }
        }
    }

    pub fn update_core_free(&mut self, core: CoreIndex, epoch_idx: Option<EpochIndex>) {
        // update core_para map
        if let Some(previous_para_id) = self.core_para.insert(core, None) {
            if let Some(para_id) = previous_para_id {
                if let Some(group_idx) = self.para_group.get(&para_id) {
                    if let Some(authorities) = self.get_authorities_from_group(*group_idx) {
                        for authority_idx in authorities.iter() {
                            if let Some(para_record) =
                                self.get_mut_para_record(authority_idx.clone(), epoch_idx)
                            {
                                para_record.set_core_free();
                            }
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
                if let Some(para_record) =
                    self.get_mut_para_record(authority_idx.clone(), epoch_idx)
                {
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
                if let Some(para_record) =
                    self.get_mut_para_record(authority_idx.clone(), epoch_idx)
                {
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
            EpochKey(self.current_era, self.current_epoch),
            discovery_record.authority_discovery_key(),
        );
        self.authority_discovery_keys
            .entry(public_key)
            .or_insert(authority_index);

        // Map authority_index to the PeerToPeerRecord for the current epoch
        let record_key = RecordKey(
            EpochKey(self.current_era, self.current_epoch),
            authority_index,
        );
        self.discovery_records
            .entry(record_key.clone())
            .or_insert(discovery_record);
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
        epoch_index: Option<EpochIndex>,
    ) -> Option<&mut AuthorityRecord> {
        let epoch_key = if let Some(epoch_idx) = epoch_index {
            if let Some(&era_idx) = self.get_era_index(epoch_index) {
                EpochKey(era_idx, epoch_idx)
            } else {
                EpochKey(self.current_era, self.current_epoch)
            }
        } else {
            EpochKey(self.current_era, self.current_epoch)
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
            let key = EpochKey(self.current_era, self.current_epoch);
            self.para_authorities.get_mut(&key)
        }
    }

    pub fn get_mut_para_record(
        &mut self,
        index: AuthorityIndex,
        epoch_index: Option<EpochIndex>,
    ) -> Option<&mut ParaRecord> {
        let epoch_key = if let Some(epoch_idx) = epoch_index {
            if let Some(&era_idx) = self.get_era_index(epoch_index) {
                EpochKey(era_idx, epoch_idx)
            } else {
                EpochKey(self.current_era, self.current_epoch)
            }
        } else {
            EpochKey(self.current_era, self.current_epoch)
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

    pub fn get_discovery_record(
        &self,
        index: AuthorityIndex,
        key: Option<EpochKey>,
    ) -> Option<&DiscoveryRecord> {
        let epoch_key = if let Some(key) = key {
            key
        } else {
            EpochKey(self.current_era, self.current_epoch)
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
            EpochKey(self.current_era, self.current_epoch)
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
        // authorithy_discovery_keys: HashMap<PublicKey, AuthorityIndex>,
        // discovery_records: HashMap<RecordKey, DiscoveryRecord>,

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
    #[serde(rename = "ab")]
    authored_blocks: Vec<BlockNumber>,
    #[serde(default)]
    #[serde(skip_serializing)]
    is_flagged: bool,
}

impl AuthorityRecord {
    pub fn with_index_address_and_points(
        index: AuthorityIndex,
        address: AccountId32,
        start_points: Points,
    ) -> Self {
        Self {
            index: Some(index),
            address: Some(address),
            start_points,
            end_points: Some(start_points),
            ..Default::default()
        }
    }

    pub fn authority_index(&self) -> Option<AuthorityIndex> {
        self.index
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
            if end_points > self.start_points {
                end_points - self.start_points
            } else {
                0
            }
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

    pub fn update_current_points(&mut self, current_points: Points) -> Points {
        fn diff(current: Points, last: Points) -> Points {
            if current > last {
                current - last
            } else {
                0
            }
        }
        if let Some(end_points) = self.end_points {
            // Note: only update end_points if current_points > end_points
            if current_points > end_points {
                self.end_points = Some(current_points);
            }
            // calculate diff and return
            return diff(current_points, end_points);
        } else {
            // update end_points if None with current_points value
            self.end_points = Some(current_points);
            // calculate diff and return
            return diff(current_points, self.start_points);
        };
    }
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
}

impl Validity for DiscoveryRecord {
    fn is_empty(&self) -> bool {
        self.authority_discovery_key().is_empty()
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
            if para_id == id {
                return true;
            }
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

    pub fn set_core_assignment(&mut self, para_id: ParaId, core: CoreIndex) {
        self.core = Some(core);

        let stats = self
            .para_stats
            .entry(para_id)
            .or_insert(ParaStats::default());
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

    pub fn total_disputes(&self) -> u32 {
        self.disputes.len().try_into().unwrap()
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
            disputes: self.disputes.clone(),
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
        let key = EpochKey(self.current_era, self.current_epoch);
        if let Some(s) = self.subscribers.get_mut(&key) {
            s.push((account.clone(), user_id.to_string(), param.clone()));
        } else {
            self.subscribers.insert(
                key,
                vec![(account.clone(), user_id.to_string(), param.clone())],
            );
        }
        info!(
            "{} subscribed ({}) report for epoch {} era {}",
            user_id.to_string(),
            account.to_string(),
            self.current_epoch(),
            self.current_era(),
        );
    }

    pub fn get(&self, key: Option<EpochKey>) -> Option<&Vec<(AccountId32, UserID, Option<Param>)>> {
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
            is_oversubscribed: false,
            is_active: false,
            is_chilled: false,
            is_blocked: false,
        }
    }

    pub fn own_stake_trimmed(&self, chain_token_decimals: u32) -> u64 {
        use crate::mcda::criterias::DECIMALS;
        let base: u128 = 10_u128;
        (self.own_stake / base.pow(chain_token_decimals - DECIMALS)) as u64
    }

    pub fn nominators_stake_trimmed(&self, chain_token_decimals: u32) -> u64 {
        use crate::mcda::criterias::DECIMALS;
        let base: u128 = 10_u128;
        (self.nominators_stake / base.pow(chain_token_decimals - DECIMALS)) as u64
    }

    pub fn nominators_raw_stake_trimmed(&self, chain_token_decimals: u32) -> u64 {
        use crate::mcda::criterias::DECIMALS;
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
}

impl Validity for SessionStats {
    fn is_empty(&self) -> bool {
        self.authorities == 0
    }
}

#[derive(Serialize, Deserialize, Clone, Eq, Hash, PartialEq, Debug)]
pub enum SyncStatus {
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

impl Default for SyncStatus {
    fn default() -> SyncStatus {
        SyncStatus::Syncing
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
        assert_eq!(subscribers.get(None).is_some(), true);
        assert_eq!(subscribers.get(Some(EpochKey(era, epoch))).is_some(), true);
        assert_eq!(subscribers.get(Some(EpochKey(era, 30))).is_none(), true);
        assert_eq!(
            subscribers.get(Some(EpochKey(era, epoch))),
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
        let ar =
            AuthorityRecord::with_index_address_and_points(authority_idx, account.clone(), 300);
        assert_eq!(ar.authority_index(), Some(authority_idx));
        assert_eq!(ar.address(), Some(&account));
        assert_eq!(ar.start_points(), 300);
        assert_eq!(ar.end_points().is_none(), false);

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
        if let Some(ar) = records.get_mut_authority_record(authority_idx, None) {
            let diff = ar.update_current_points(1900);
            assert_eq!(diff, 1600);
            assert_eq!(ar.start_points(), 300);
            assert_eq!(ar.end_points().is_some(), true);
            assert_eq!(ar.end_points().unwrap(), 1900);
            assert_eq!(ar.points(), 1600);
        }

        // Increment authored blocks and current points
        if let Some(pr) = records.get_mut_para_record(authority_idx, None) {
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

        let dr: DiscoveryRecord = DiscoveryRecord::with_authority_discovery_key([0; 32]);
        assert_eq!(dr.authority_discovery_key(), "0000000000000000000000000000000000000000000000000000000000000000");

        records.set_discovery_record(authority_idx, dr);
        assert_eq!(records.get_authority_record(authority_idx, None).is_some(), true);

    }
}
