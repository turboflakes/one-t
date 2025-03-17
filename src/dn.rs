use crate::config::CONFIG;
use crate::errors::OnetError;
use log::{info, warn};
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
) -> Result<Vec<AccountId32>, OnetError> {
    let config = CONFIG.clone();
    let url = format!(
        "{}/{}/",
        config.dn_url.to_lowercase(),
        config.chain_name.to_lowercase()
    );

    let url = Url::parse(&*url)?;

    let filename = format!(
        "{}{}_{}",
        config.data_path,
        DN_VALIDATORS_FILENAME,
        config.chain_name.to_lowercase()
    );

    let validators: Vec<Validator> = if is_loading {
        // Try to read from cached file
        read_cached_filename(&filename)?
    } else {
        match reqwest::get(url.to_string()).await {
            Ok(request) => {
                match request.json::<Response>().await {
                    Ok(response) => {
                        info!("response {:?}", response);
                        // Serialize and cache
                        let serialized = serde_json::to_string(&response.selected)?;
                        fs::write(&filename, serialized)?;
                        response.selected
                    }
                    Err(e) => {
                        warn!("Parsing json from url {} failed with error: {:?}", url, e);
                        // Try to read from cached file
                        read_cached_filename(&filename)?
                    }
                }
            }
            Err(e) => {
                warn!("Fetching url {} failed with error: {:?}", url, e);
                // Try to read from cached file
                read_cached_filename(&filename)?
            }
        }
    };

    // Parse stashes
    let v: Vec<AccountId32> = validators
        .iter()
        .filter(|v| v.is_active())
        .map(|x| AccountId32::from_str(&x.stash).unwrap())
        .collect();

    Ok(v)
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
