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

use crate::error::DnError;
use log::{info, warn};
use onet_config::CONFIG;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use subxt::utils::AccountId32;
use url::Url;

const DN_VALIDATORS_FILENAME: &str = ".dn";

#[derive(Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum Status {
    Active,
    Pending,
    Selected,
    Graduated,
    Removed,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Validator {
    #[serde(default)]
    identity: String,
    #[serde(default)]
    stash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<Status>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Term {
    #[serde(default)]
    start: String,
    #[serde(default)]
    end: String,
}

impl Validator {
    fn is_active(&self) -> bool {
        matches!(self.status, Some(Status::Active)) || matches!(self.status, Some(Status::Selected))
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    selected: Vec<Validator>,
    nominators: Vec<String>,
    #[serde(skip_serializing)]
    _statuses: BTreeMap<Status, String>,
    term: Term,
}

/// Fetch stashes from 1kv endpoint
/// eg. https://nodes.web3.foundation/api/cohort/1/polkadot/
/// eg. https://nodes.web3.foundation/api/cohort/2-1/polkadot/
pub async fn try_fetch_stashes_from_remote_url(
    is_loading: bool,
    cohort: Option<String>,
) -> Result<Vec<AccountId32>, DnError> {
    let config = CONFIG.clone();

    // Extract cohort number
    let cohort = cohort.unwrap_or_else(|| {
        config
            .dn_url
            .to_lowercase()
            .split('/')
            .filter(|s| !s.is_empty())
            .last()
            .expect("Failed to parse cohort from config.dn_url")
            .to_string()
    });

    // Construct filename for caching
    let filename = construct_cache_filename(cohort.clone());

    // Construct URL
    let url = construct_url(cohort)?;

    // Fetch or load validators
    let validators = if is_loading {
        read_cached_filename(&filename)?
    } else {
        fetch_or_fallback_to_cache(&url, &filename).await?
    };

    // Parse and filter stashes
    Ok(parse_stashes(validators))
}

fn construct_cache_filename(cohort: impl AsRef<str>) -> String {
    let config = CONFIG.clone();
    format!(
        "{}{}_{}_cohort_{}",
        config.data_path,
        DN_VALIDATORS_FILENAME,
        config.chain_name.to_lowercase(),
        cohort.as_ref()
    )
}

fn construct_url(cohort: impl AsRef<str>) -> Result<Url, DnError> {
    let config = CONFIG.clone();
    let dn_url = config.dn_url.to_lowercase();

    // Use regex to trim cohort patterns like /1/ or /2-1/ from the end of URL
    let re = Regex::new(r"/\d+(-\d+)?(/?)$").expect("Failed to create regex");
    let base_url = re
        .replace(&dn_url, "")
        .to_string()
        .trim_end_matches('/')
        .to_string();

    let url = format!(
        "{}/{}/{}/",
        base_url,
        cohort.as_ref(),
        config.chain_name.to_lowercase()
    );

    Url::parse(&url).map_err(Into::into)
}

async fn fetch_or_fallback_to_cache(url: &Url, filename: &str) -> Result<Vec<Validator>, DnError> {
    match fetch_validators(url).await {
        Ok(validators) => {
            // Cache the results
            let serialized = serde_json::to_string(&validators)?;
            fs::write(filename, serialized)?;
            Ok(validators)
        }
        Err(e) => {
            warn!("Remote fetch failed: {}. Falling back to cache.", e);
            read_cached_filename(filename)
        }
    }
}

async fn fetch_validators(url: &Url) -> Result<Vec<Validator>, DnError> {
    let response = reqwest::get(url.to_string()).await?;

    let data = response.json::<Response>().await?;

    info!("Fetched response: {:?}", data);
    Ok(data.selected)
}

fn parse_stashes(validators: Vec<Validator>) -> Vec<AccountId32> {
    validators
        .iter()
        .filter(|v| v.is_active())
        .filter_map(|x| AccountId32::from_str(&x.stash).ok())
        .collect()
}

pub fn read_cached_filename(filename: &str) -> Result<Vec<Validator>, DnError> {
    // Try to read from cached file
    if Path::new(filename).exists() {
        let serialized = fs::read_to_string(filename)?;
        let validators: Vec<Validator> = serde_json::from_str(&serialized).unwrap();

        info!("Read from cached file: {:?}", validators);
        Ok(validators)
    } else {
        Ok(Vec::new())
    }
}
