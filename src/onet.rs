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
use crate::config::{Config, CONFIG};
use crate::errors::OnetError;
use crate::matrix::{Matrix, UserID, MATRIX_SUBSCRIBERS_FILENAME};
use crate::records::EpochIndex;
use crate::runtimes::{
    kusama, polkadot,
    support::{ChainPrefix, SupportedRuntime},
    westend,
};
use log::{debug, error, info, warn};
use regex::Regex;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{
    convert::TryInto,
    fs,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    result::Result,
    str::FromStr,
    thread, time,
};
use subxt::{
    sp_core::{crypto, sr25519, storage::StorageKey, Pair},
    sp_runtime::AccountId32,
    Client, ClientBuilder, DefaultConfig,
};

const TVP_VALIDATORS_FILENAME: &str = ".tvp";
pub const EPOCH_FILENAME: &str = ".epoch";

type Message = Vec<String>;

trait MessageTrait {
    fn log(&self);
    fn show_or_hide(&mut self, value: String, hidden: bool);
    fn show_or_hide_and_log(&mut self, value: String, hidden: bool);
}

impl MessageTrait for Message {
    fn log(&self) {
        info!("{}", &self[self.len() - 1]);
    }

    fn show_or_hide(&mut self, value: String, hidden: bool) {
        if !hidden {
            self.push(value);
        }
    }

    fn show_or_hide_and_log(&mut self, value: String, hidden: bool) {
        if !hidden {
            self.push(value);
            self.log();
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub enum ReportType {
    Groups,
    Parachains,
    Validator,
    Insights,
}

impl ReportType {
    pub fn name(&self) -> String {
        match self {
            Self::Groups => "Val. Groups Performance Report".to_string(),
            Self::Parachains => "Parachains Performance Report".to_string(),
            Self::Validator => "Validator Performance Report".to_string(),
            Self::Insights => "Validators Performance Insights Report".to_string(),
        }
    }
}

impl std::fmt::Display for ReportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Groups => write!(f, "Groups"),
            Self::Parachains => write!(f, "Parachains"),
            Self::Validator => write!(f, "Validator"),
            Self::Insights => write!(f, "Insights"),
        }
    }
}

pub async fn create_substrate_node_client(
    config: Config,
) -> Result<Client<DefaultConfig>, subxt::BasicError> {
    ClientBuilder::new()
        .set_url(config.substrate_ws_url)
        .build::<DefaultConfig>()
        .await
}

pub async fn create_or_await_substrate_node_client(config: Config) -> Client<DefaultConfig> {
    loop {
        match create_substrate_node_client(config.clone()).await {
            Ok(client) => {
                let chain = client
                    .rpc()
                    .system_chain()
                    .await
                    .unwrap_or_else(|_| "Chain undefined".to_string());
                let name = client
                    .rpc()
                    .system_name()
                    .await
                    .unwrap_or_else(|_| "Node name undefined".to_string());
                let version = client
                    .rpc()
                    .system_version()
                    .await
                    .unwrap_or_else(|_| "Node version undefined".to_string());

                info!(
                    "Connected to {} network using {} * Substrate node {} v{}",
                    chain, config.substrate_ws_url, name, version
                );
                break client;
            }
            Err(e) => {
                error!("{}", e);
                info!("Awaiting for connection using {}", config.substrate_ws_url);
                thread::sleep(time::Duration::from_secs(6));
            }
        }
    }
}

pub struct Onet {
    runtime: SupportedRuntime,
    client: Client<DefaultConfig>,
    matrix: Matrix,
}

impl Onet {
    pub async fn new() -> Onet {
        let client = create_or_await_substrate_node_client(CONFIG.clone()).await;

        let properties = client.properties();
        // Display SS58 addresses based on the connected chain
        let chain_prefix: ChainPrefix = if let Some(ss58_format) = properties.get("ss58Format") {
            ss58_format.as_u64().unwrap_or_default().try_into().unwrap()
        } else {
            0
        };
        crypto::set_default_ss58_version(crypto::Ss58AddressFormat::custom(chain_prefix));

        // Check for supported runtime
        let runtime = SupportedRuntime::from(chain_prefix);

        // Initialize matrix client
        let mut matrix: Matrix = Matrix::new();
        matrix
            .authenticate(chain_prefix.into())
            .await
            .unwrap_or_else(|e| {
                error!("{}", e);
                Default::default()
            });

        Onet {
            runtime,
            client,
            matrix,
        }
    }

    pub fn client(&self) -> &Client<DefaultConfig> {
        &self.client
    }

    /// Returns the matrix configuration
    pub fn matrix(&self) -> &Matrix {
        &self.matrix
    }

    /// Spawn and restart on error
    pub fn spawn() {
        let config = CONFIG.clone();
        // Authenticate matrix and spawn lazy load commands
        spawn_and_restart_matrix_lazy_load_on_error(config.chain_name.into());
        // Subscribe on-chain events
        spawn_and_restart_on_error();
    }

    async fn subscribe_on_chain_events(&self) -> Result<(), OnetError> {
        // initialize and load TVP stashes
        try_fetch_stashes_from_remote_url().await?;

        match self.runtime {
            SupportedRuntime::Polkadot => polkadot::init_and_subscribe_on_chain_events(self).await,
            SupportedRuntime::Kusama => kusama::init_and_subscribe_on_chain_events(self).await,
            SupportedRuntime::Westend => westend::init_and_subscribe_on_chain_events(self).await,
        }
    }
}

fn spawn_and_restart_matrix_lazy_load_on_error(chain: SupportedRuntime) {
    async_std::task::spawn(async move {
        let config = CONFIG.clone();
        loop {
            let mut m = Matrix::new();
            if let Err(e) = m.authenticate(chain).await {
                error!("authenticate error: {}", e);
                thread::sleep(time::Duration::from_secs(config.error_interval));
                continue;
            }
            if let Err(e) = m.lazy_load_and_process_commands().await {
                error!("lazy_load_and_process_commands error: {}", e);
                thread::sleep(time::Duration::from_secs(config.error_interval));
                continue;
            }
        }
    });
}

fn spawn_and_restart_on_error() {
    let t = async_std::task::spawn(async {
        let config = CONFIG.clone();
        loop {
            // Initialize a new instance
            let t = Onet::new().await;
            if let Err(e) = t.subscribe_on_chain_events().await {
                match e {
                    OnetError::SubscriptionFinished => warn!("{}", e),
                    _ => {
                        error!("subscribe_on_chain_events error: {}", e);
                        thread::sleep(time::Duration::from_secs(config.error_interval));
                        continue;
                    }
                }
                thread::sleep(time::Duration::from_secs(1));
            };
        }
    });
    async_std::task::block_on(t);
}

#[derive(Serialize, Deserialize, Debug)]
struct Validator {
    #[serde(default)]
    stash: String,
    #[serde(default)]
    valid: bool,
}

fn read_tvp_cached_filename(filename: &str) -> Result<Vec<Validator>, OnetError> {
    // Try to read from cached file
    if Path::new(filename).exists() {
        let serialized = fs::read_to_string(filename)?;
        let validators: Vec<Validator> = serde_json::from_str(&serialized).unwrap();
        Ok(validators)
    } else {
        Ok(Vec::new())
    }
}

/// Fetch stashes from 1kv endpoint https://polkadot.w3f.community/candidates
pub async fn try_fetch_stashes_from_remote_url() -> Result<Vec<AccountId32>, OnetError> {
    let config = CONFIG.clone();
    let url = format!(
        "https://{}.w3f.community/candidates",
        config.chain_name.to_lowercase()
    );
    let url = Url::parse(&*url)?;

    let tvp_validators_filename = format!(
        "{}{}_{}",
        config.data_path,
        TVP_VALIDATORS_FILENAME,
        config.chain_name.to_lowercase()
    );

    let validators: Vec<Validator> = if let Ok(request) = reqwest::get(url).await {
        if let Ok(validators) = request.json::<Vec<Validator>>().await {
            debug!("validators {:?}", validators);
            // Serialize and cache
            let serialized = serde_json::to_string(&validators)?;
            fs::write(&tvp_validators_filename, serialized)?;
            validators
        } else {
            // Try to read from cached file
            read_tvp_cached_filename(&tvp_validators_filename)?
        }
    } else {
        read_tvp_cached_filename(&tvp_validators_filename)?
    };

    // Parse stashes
    let v: Vec<AccountId32> = validators
        .iter()
        .filter(|v| v.valid)
        .map(|x| AccountId32::from_str(&x.stash).unwrap())
        .collect();
    Ok(v)
}

pub fn get_account_id_from_storage_key(key: StorageKey) -> AccountId32 {
    let s = &key.0[key.0.len() - 32..];
    let v: [u8; 32] = s.try_into().expect("slice with incorrect length");
    AccountId32::new(v)
}

pub fn get_subscribers() -> Result<Vec<(AccountId32, UserID)>, OnetError> {
    let config = CONFIG.clone();
    let subscribers_filename = format!("{}{}", config.data_path, MATRIX_SUBSCRIBERS_FILENAME);
    let mut out: Vec<(AccountId32, UserID)> = Vec::new();
    let file = File::open(&subscribers_filename)?;

    // Read each subscriber (stash,user_id) and parse stash to AccountId
    for line in BufReader::new(file).lines() {
        if let Ok(s) = line {
            let v: Vec<&str> = s.split(',').collect();
            let acc = AccountId32::from_str(&v[0])?;
            out.push((acc, v[1].to_string()));
        }
    }

    Ok(out)
}

pub fn get_subscribers_by_epoch(
    report_type: ReportType,
    epoch: Option<EpochIndex>,
) -> Result<Vec<UserID>, OnetError> {
    let config = CONFIG.clone();
    let subscribers_filename = if let Some(epoch) = epoch {
        format!(
            "{}{}.{}.{}",
            config.data_path,
            MATRIX_SUBSCRIBERS_FILENAME,
            report_type.to_string().to_lowercase(),
            epoch
        )
    } else {
        format!(
            "{}{}.{}",
            config.data_path,
            MATRIX_SUBSCRIBERS_FILENAME,
            report_type.to_string().to_lowercase()
        )
    };

    let mut out: Vec<UserID> = Vec::new();
    let file = File::open(&subscribers_filename)?;

    for line in BufReader::new(file).lines() {
        if let Ok(s) = line {
            out.push(s);
        }
    }

    Ok(out)
}

/// Helper function to generate a crypto pair from seed
pub fn get_from_seed(seed: &str, pass: Option<&str>) -> sr25519::Pair {
    // Use regex to remove control characters
    let re = Regex::new(r"[\x00-\x1F]").unwrap();
    let clean_seed = re.replace_all(&seed.trim(), "");
    sr25519::Pair::from_string(&clean_seed, pass)
        .expect("constructed from known-good static value; qed")
}
