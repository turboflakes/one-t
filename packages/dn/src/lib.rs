use log::{info, warn};
use onet_config::CONFIG;
use onet_errors::OnetError;
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
    statuses: BTreeMap<Status, String>,
    term: Term,
}

/// Fetch stashes from 1kv endpoint https://nodes.web3.foundation/api/cohort/1/polkadot/
pub async fn try_fetch_stashes_from_remote_url(
    is_loading: bool,
    cohort: Option<u32>,
) -> Result<Vec<AccountId32>, OnetError> {
    let config = CONFIG.clone();

    // Extract cohort number
    let cohort = cohort.unwrap_or_else(|| {
        config
            .dn_url
            .to_lowercase()
            .split('/')
            .last()
            .and_then(|s| s.parse().ok())
            .expect("Failed to parse cohort number")
    });

    // Construct filename for caching
    let filename = construct_cache_filename(cohort);

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

fn construct_cache_filename(cohort: u32) -> String {
    let config = CONFIG.clone();
    format!(
        "{}{}_{}_cohort_{}",
        config.data_path,
        DN_VALIDATORS_FILENAME,
        config.chain_name.to_lowercase(),
        cohort
    )
}

fn construct_url(cohort: u32) -> Result<Url, OnetError> {
    let config = CONFIG.clone();
    let dn_url = config.dn_url.to_lowercase();
    let base_url = dn_url
        .trim_end_matches(|c: char| c.is_digit(10))
        .trim_end_matches('/');

    let url = format!(
        "{}/{}/{}/",
        base_url,
        cohort,
        config.chain_name.to_lowercase()
    );

    Url::parse(&url).map_err(Into::into)
}

async fn fetch_or_fallback_to_cache(
    url: &Url,
    filename: &str,
) -> Result<Vec<Validator>, OnetError> {
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

async fn fetch_validators(url: &Url) -> Result<Vec<Validator>, OnetError> {
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

pub fn read_cached_filename(filename: &str) -> Result<Vec<Validator>, OnetError> {
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
