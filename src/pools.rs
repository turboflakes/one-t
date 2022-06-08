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

use crate::config::CONFIG;
use crate::errors::OnetError;
use crate::records::EraIndex;
use serde::{Deserialize, Serialize};
use std::{fs, result::Result, time::SystemTime};
use subxt::sp_core::H256;

pub const POOL_FILENAME: &str = ".pool";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Pool {
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub metadata: String,
    #[serde(default)]
    pub bonded: String,
    #[serde(default)]
    pub member_counter: u32,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub nominees: Option<PoolNominees>,
    #[serde(default)]
    pub ts: u64,
}

impl Pool {
    pub fn cache(&self) -> Result<(), OnetError> {
        let config = CONFIG.clone();
        // Pool cache filename
        let filename = format!(
            "{}{}_{}_{}",
            config.data_path,
            POOL_FILENAME,
            self.id,
            config.chain_name.to_lowercase()
        );
        // Serialize and cache
        let serialized = serde_json::to_string(&self)?;
        fs::write(&filename, serialized)?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Nominee {
    #[serde(default)]
    pub stash: String,
    #[serde(default)]
    pub identity: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LastNomination {
    #[serde(default)]
    pub sessions_counter: u32,
    #[serde(default)]
    pub block_number: u32,
    #[serde(default)]
    pub extrinsic_hash: H256,
    #[serde(default)]
    pub ts: u64,
}

impl LastNomination {
    pub fn cache(&self) -> Result<(), OnetError> {
        let config = CONFIG.clone();
        // Pool cache filename
        let filename = format!(
            "{}{}_last_nomination_{}",
            config.data_path,
            POOL_FILENAME,
            config.chain_name.to_lowercase()
        );
        // Serialize and cache
        let serialized = serde_json::to_string(&self)?;
        fs::write(&filename, serialized)?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PoolNominees {
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub nominees: Vec<Nominee>,
    #[serde(default)]
    pub apr: f64,
    #[serde(default)]
    pub ts: u64,
}

impl PoolNominees {
    pub fn cache(&self) -> Result<(), OnetError> {
        let config = CONFIG.clone();
        // Pool cache filename
        let filename = format!(
            "{}{}_{}_nominees_{}",
            config.data_path,
            POOL_FILENAME,
            self.id,
            config.chain_name.to_lowercase()
        );
        // Serialize and cache
        let serialized = serde_json::to_string(&self)?;
        fs::write(&filename, serialized)?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PoolsEra {
    #[serde(default)]
    pub era: u32,
    #[serde(default)]
    pub pools: Vec<Pool>,
    #[serde(default)]
    pub ts: u64,
}

impl PoolsEra {
    pub fn with_era(era: EraIndex) -> Self {
        let unix_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        Self {
            era,
            pools: Vec::new(),
            ts: unix_now.as_secs(),
        }
    }

    pub fn cache(&self) -> Result<(), OnetError> {
        let config = CONFIG.clone();
        let filename = format!(
            "{}{}s_stats_era_{}_{}",
            config.data_path,
            POOL_FILENAME,
            self.era,
            config.chain_name.to_lowercase()
        );
        // Serialize and cache
        let serialized = serde_json::to_string(&self)?;
        fs::write(&filename, serialized)?;

        // Cache as previous era
        let filename = format!(
            "{}{}s_stats_{}",
            config.data_path,
            POOL_FILENAME,
            config.chain_name.to_lowercase()
        );
        let serialized = serde_json::to_string(&self)?;
        fs::write(&filename, serialized)?;

        Ok(())
    }
}
