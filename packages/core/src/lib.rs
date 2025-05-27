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

use log::{error, info, warn};
use onet_cache::{create_or_await_pool, CacheKey, RedisPool};
use onet_chains::{ChainPrefix, ChainTokenSymbol, SupportedRuntime};
use onet_config::{Config, BLOCK_FILENAME, CONFIG};
use onet_errors::{CacheError, OnetError};
use onet_matrix::{Matrix, UserID, MATRIX_SUBSCRIBERS_FILENAME};
use onet_records::EpochIndex;
use onet_report::{Network, ReportType};
use redis::aio::Connection;
use serde::{Deserialize, Serialize};
use sp_core::crypto;
use std::{
    collections::BTreeMap,
    convert::TryInto,
    fs,
    fs::File,
    io::{BufRead, BufReader},
    result::Result,
    str::FromStr,
    thread, time,
};
use subxt::{
    backend::{
        legacy::{rpc_methods::StorageKey, LegacyRpcMethods},
        rpc::reconnecting_rpc_client::{ExponentialBackoff, RpcClient},
    },
    ext::subxt_rpcs::utils::validate_url_is_secure,
    utils::AccountId32,
    OnlineClient, PolkadotConfig,
};
use subxt_signer::{bip39::Mnemonic, sr25519::Keypair};

// DEPRECATED
pub async fn _create_substrate_node_client(
    config: Config,
) -> Result<OnlineClient<PolkadotConfig>, subxt::Error> {
    OnlineClient::<PolkadotConfig>::from_url(config.substrate_ws_url).await
}

pub async fn create_substrate_rpc_client_from_config(
    config: Config,
) -> Result<RpcClient, OnetError> {
    if let Err(_) = validate_url_is_secure(config.substrate_ws_url.as_ref()) {
        warn!("Insecure URL provided: {}", config.substrate_ws_url);
    };

    RpcClient::builder()
        .retry_policy(ExponentialBackoff::from_millis(100).max_delay(time::Duration::from_secs(10)))
        .build(config.substrate_ws_url)
        .await
        .map_err(|err| OnetError::RpcError(err.into()))
}

pub async fn create_substrate_client_from_supported_runtime(
    runtime: SupportedRuntime,
) -> Result<Option<OnlineClient<PolkadotConfig>>, OnetError> {
    if runtime.is_people_runtime_available() {
        let reconnecting_client = RpcClient::builder()
            .retry_policy(
                ExponentialBackoff::from_millis(100).max_delay(time::Duration::from_secs(10)),
            )
            .build(runtime.people_runtime().default_rpc_url())
            .await
            .map_err(|err| OnetError::RpcError(err.into()))?;

        let client =
            create_substrate_client_from_rpc_client(reconnecting_client.clone().into()).await?;
        Ok(Some(client))
    } else {
        Ok(None)
    }
}

pub async fn create_substrate_client_from_rpc_client(
    rpc_client: RpcClient,
) -> Result<OnlineClient<PolkadotConfig>, OnetError> {
    OnlineClient::<PolkadotConfig>::from_rpc_client(rpc_client)
        .await
        .map_err(|err| OnetError::SubxtError(err.into()))
}

pub async fn create_or_await_substrate_node_client(
    config: Config,
) -> (
    OnlineClient<PolkadotConfig>,
    LegacyRpcMethods<PolkadotConfig>,
    Option<OnlineClient<PolkadotConfig>>,
    SupportedRuntime,
) {
    loop {
        match create_substrate_rpc_client_from_config(config.clone()).await {
            Ok(rpc_client) => {
                let legacy_rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client.clone().into());
                let chain = legacy_rpc.system_chain().await.unwrap_or_default();
                let name = legacy_rpc.system_name().await.unwrap_or_default();
                let version = legacy_rpc.system_version().await.unwrap_or_default();
                let properties = legacy_rpc.system_properties().await.unwrap_or_default();

                // Display SS58 addresses based on the connected chain
                let chain_prefix: ChainPrefix =
                    if let Some(ss58_format) = properties.get("ss58Format") {
                        ss58_format.as_u64().unwrap_or_default().try_into().unwrap()
                    } else {
                        0
                    };

                crypto::set_default_ss58_version(crypto::Ss58AddressFormat::custom(chain_prefix));

                let chain_token_symbol: ChainTokenSymbol =
                    if let Some(token_symbol) = properties.get("tokenSymbol") {
                        use serde_json::Value::String;
                        match token_symbol {
                            String(token_symbol) => token_symbol.to_string(),
                            _ => unreachable!("Token symbol with wrong type"),
                        }
                    } else {
                        String::from("")
                    };

                info!(
                    "Connected to {} network using {} * Substrate node {} v{}",
                    chain, config.substrate_ws_url, name, version
                );

                match create_substrate_client_from_rpc_client(rpc_client.clone().into()).await {
                    Ok(relay_client) => {
                        // Create people chain client depending on the runtime selected
                        let runtime = SupportedRuntime::from(chain_token_symbol);
                        match create_substrate_client_from_supported_runtime(runtime).await {
                            Ok(people_client_option) => {
                                break (relay_client, legacy_rpc, people_client_option, runtime);
                            }

                            Err(e) => {
                                error!("{}", e);
                                info!("Awaiting for connection using {}", config.substrate_ws_url);
                                thread::sleep(time::Duration::from_secs(6));
                            }
                        }
                    }
                    Err(e) => {
                        error!("{}", e);
                        info!("Awaiting for connection using {}", config.substrate_ws_url);
                        thread::sleep(time::Duration::from_secs(6));
                    }
                }
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
    client: OnlineClient<PolkadotConfig>,
    rpc: LegacyRpcMethods<PolkadotConfig>,
    // Note: Use people client as optional only until we get people chain available
    // on Polkadot, as soon as it is available it can go away
    people_client_option: Option<OnlineClient<PolkadotConfig>>,
    matrix: Matrix,
    pub cache: RedisPool,
}

impl Onet {
    pub async fn new() -> Onet {
        let (client, rpc, people_client_option, runtime) =
            create_or_await_substrate_node_client(CONFIG.clone()).await;

        // Initialize matrix client
        let mut matrix: Matrix = Matrix::new();
        matrix.authenticate(runtime).await.unwrap_or_else(|e| {
            error!("{}", e);
            Default::default()
        });

        Onet {
            runtime,
            client,
            rpc,
            people_client_option,
            matrix,
            cache: create_or_await_pool(CONFIG.clone()),
        }
    }

    pub async fn init() -> Onet {
        let config = CONFIG.clone();
        let onet: Onet = Onet::new().await;

        let chain = onet.rpc().system_chain().await.unwrap_or_default();
        let name = onet.rpc().system_name().await.unwrap_or_default();
        let version = onet.rpc().system_version().await.unwrap_or_default();
        info!(
            "Connected to {} network using {} * Substrate node {} v{}",
            chain, config.substrate_ws_url, name, version
        );

        // initialize cache
        if let Err(e) = onet.cache_network().await {
            error!("Failed to initialize cache: {}", e);
        }

        onet
    }

    pub fn client(&self) -> &OnlineClient<PolkadotConfig> {
        &self.client
    }

    pub fn people_client(&self) -> &Option<OnlineClient<PolkadotConfig>> {
        &self.people_client_option
    }

    pub fn rpc(&self) -> &LegacyRpcMethods<PolkadotConfig> {
        &self.rpc
    }

    /// Returns the matrix configuration
    pub fn matrix(&self) -> &Matrix {
        &self.matrix
    }

    pub fn runtime(&self) -> &SupportedRuntime {
        &self.runtime
    }

    // cache methods
    async fn cache_network(&self) -> Result<(), OnetError> {
        let config = CONFIG.clone();
        if config.cache_writer_enabled {
            let mut conn = self.cache.get().await.map_err(CacheError::RedisPoolError)?;

            let mut data: BTreeMap<String, String> = BTreeMap::new();

            let network = Network::load(self.rpc()).await?;
            // Get Network details
            data.insert(String::from("name"), network.name);
            data.insert(String::from("token_symbol"), network.token_symbol);
            data.insert(
                String::from("token_decimals"),
                network.token_decimals.to_string(),
            );
            data.insert(String::from("ss58_format"), network.ss58_format.to_string());

            // Cache genesis hash
            let genesis_hash = self.rpc().genesis_hash().await?;
            data.insert("genesis_hash".to_string(), format!("{:?}", genesis_hash));

            let _: () = redis::cmd("HSET")
                .arg(CacheKey::Network)
                .arg(data)
                .query_async(&mut conn as &mut Connection)
                .await
                .map_err(CacheError::RedisCMDError)?;
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Validator {
    #[serde(default)]
    stash: String,
    #[serde(default)]
    validity: Vec<Validity>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Validity {
    #[serde(default)]
    valid: bool,
    #[serde(default)]
    r#type: String,
}

pub fn get_account_id_from_storage_key(key: StorageKey) -> AccountId32 {
    let s = &key[key.len() - 32..];
    let v: [u8; 32] = s.try_into().expect("slice with incorrect length");
    v.into()
}

pub fn get_subscribers() -> Result<Vec<(AccountId32, UserID, Option<String>)>, OnetError> {
    let config = CONFIG.clone();
    let subscribers_filename = format!("{}{}", config.data_path, MATRIX_SUBSCRIBERS_FILENAME);
    let mut out: Vec<(AccountId32, UserID, Option<String>)> = Vec::new();
    if config.matrix_disabled {
        return Ok(out);
    }

    let file = File::open(&subscribers_filename)?;

    // Read each subscriber (stash,user_id) and parse stash to AccountId
    for line in BufReader::new(file).lines() {
        if let Ok(s) = line {
            let v: Vec<&str> = s.split(',').collect();
            let acc = AccountId32::from_str(&v[0]).map_err(|e| {
                OnetError::Other(format!("Invalid account: {:?} error: {e:?}", &v[0]))
            })?;
            if let Some(param) = v.get(2) {
                out.push((acc, v[1].to_string(), Some(param.to_string())));
            } else {
                out.push((acc, v[1].to_string(), None));
            }
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

// /// Helper function to generate a crypto pair from seed
// pub fn get_from_seed_DEPRECATED(seed: &str, pass: Option<&str>) -> sr25519::Pair {
//     // Use regex to remove control characters
//     let re = Regex::new(r"[\x00-\x1F]").unwrap();
//     let clean_seed = re.replace_all(&seed.trim(), "");
//     sr25519::Pair::from_string(&clean_seed, pass)
//         .expect("constructed from known-good static value; qed")
// }

/// Helper function to generate a crypto pair from seed
pub fn get_signer_from_seed(seed: &str, pass: Option<&str>) -> Keypair {
    let mnemonic = Mnemonic::parse(seed).unwrap();
    Keypair::from_phrase(&mnemonic, pass).unwrap()
}

pub fn get_latest_block_number_processed() -> Result<u64, OnetError> {
    let config = CONFIG.clone();
    let filename = format!("{}{}", config.data_path, BLOCK_FILENAME);
    if let Ok(number) = fs::read_to_string(&filename) {
        Ok(number.parse().unwrap_or(config.initial_block_number))
    } else {
        fs::write(&filename, config.initial_block_number.to_string())?;
        Ok(config.initial_block_number)
    }
}

pub fn write_latest_block_number_processed(block_number: u64) -> Result<(), OnetError> {
    let config = CONFIG.clone();
    let filename = format!("{}{}", config.data_path, BLOCK_FILENAME);
    fs::write(&filename, block_number.to_string())?;
    Ok(())
}
