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
use onet_chains::{ChainPrefix, ChainTokenSymbol, SupportedParasRuntimeType, SupportedRuntime};
use onet_config::{Config, BLOCK_FILENAME, CONFIG};
use onet_errors::{CacheError, OnetError};
use onet_matrix::{Matrix, UserID, MATRIX_SUBSCRIBERS_FILENAME};
use onet_records::EpochIndex;
use onet_report::{Network, ReportType};
use redis::aio::Connection;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    convert::TryInto,
    fs,
    fs::File,
    io::{BufRead, BufReader},
    result::Result,
    str::FromStr,
    thread, time,
    time::Duration,
};
use subxt::{
    backend::{
        legacy::{rpc_methods::StorageKey, LegacyRpcMethods},
        rpc::reconnecting_rpc_client::{ExponentialBackoff, RpcClient},
    },
    ext::sp_core::crypto,
    utils::{validate_url_is_secure, AccountId32},
    OnlineClient, PolkadotConfig,
};
use subxt_signer::{bip39::Mnemonic, sr25519::Keypair};

const INITIAL_RETRY_DELAY_MS: u64 = 100;
const MAX_RETRY_DELAY_SECS: u64 = 10;
const RECONNECTION_DELAY_SECS: u64 = 6;

async fn create_substrate_rpc_client_from_config(config: Config) -> Result<RpcClient, OnetError> {
    if let Err(_) = validate_url_is_secure(config.substrate_ws_url.as_ref()) {
        warn!("Insecure URL provided: {}", config.substrate_ws_url);
    };

    let rpc_client = build_rpc_reconnecting_client(&config.substrate_ws_url).await?;

    Ok(rpc_client)
}

/// Builds an RPC client with configured retry policy
async fn build_rpc_reconnecting_client(url: &str) -> Result<RpcClient, OnetError> {
    RpcClient::builder()
        .retry_policy(
            ExponentialBackoff::from_millis(INITIAL_RETRY_DELAY_MS)
                .max_delay(time::Duration::from_secs(MAX_RETRY_DELAY_SECS)),
        )
        .build(url)
        .await
        .map_err(|err| OnetError::RpcError(err.into()))
}

async fn create_para_client_from_supported_runtime(
    runtime: SupportedRuntime,
    para_type: SupportedParasRuntimeType,
) -> Result<Option<OnlineClient<PolkadotConfig>>, OnetError> {
    // Check runtime availability and get RPC URL based on client type
    let (is_available, rpc_url) = match para_type {
        SupportedParasRuntimeType::People => (
            runtime.is_people_runtime_available(),
            runtime.people_runtime().default_rpc_url(),
        ),
        SupportedParasRuntimeType::AssetHub => (
            runtime.is_asset_hub_runtime_available(),
            runtime.asset_hub_runtime().default_rpc_url(),
        ),
    };

    // Early return if runtime is not available
    if !is_available {
        return Ok(None);
    }

    // Create and return client
    let rpc_client = build_rpc_reconnecting_client(&rpc_url).await?;
    let client = create_substrate_client_from_rpc_client(rpc_client.into()).await?;
    Ok(Some(client))
}

async fn create_para_legacy_rpc_from_supported_runtime(
    runtime: SupportedRuntime,
    para_type: SupportedParasRuntimeType,
) -> Result<Option<LegacyRpcMethods<PolkadotConfig>>, OnetError> {
    // Check runtime availability and get RPC URL based on client type
    let (is_available, rpc_url) = match para_type {
        SupportedParasRuntimeType::People => (
            runtime.is_people_runtime_available(),
            runtime.people_runtime().default_rpc_url(),
        ),
        SupportedParasRuntimeType::AssetHub => (
            runtime.is_asset_hub_runtime_available(),
            runtime.asset_hub_runtime().default_rpc_url(),
        ),
    };

    // Early return if runtime is not available
    if !is_available {
        return Ok(None);
    }

    // Create and return client
    let rpc_client = build_rpc_reconnecting_client(&rpc_url).await?;
    let legacy_rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client.clone().into());
    Ok(Some(legacy_rpc))
}

/// Convenience wrapper for creating a People runtime client
async fn create_people_client_from_supported_runtime(
    runtime: SupportedRuntime,
) -> Result<Option<OnlineClient<PolkadotConfig>>, OnetError> {
    create_para_client_from_supported_runtime(runtime, SupportedParasRuntimeType::People).await
}

/// Convenience wrapper for creating an Asset Hub runtime client
async fn create_asset_hub_client_from_supported_runtime(
    runtime: SupportedRuntime,
) -> Result<Option<OnlineClient<PolkadotConfig>>, OnetError> {
    create_para_client_from_supported_runtime(runtime, SupportedParasRuntimeType::AssetHub).await
}

/// Convenience wrapper for creating an Asset Hub legacy rpc client
async fn create_asset_hub_legacy_rpc_from_supported_runtime(
    runtime: SupportedRuntime,
) -> Result<Option<LegacyRpcMethods<PolkadotConfig>>, OnetError> {
    create_para_legacy_rpc_from_supported_runtime(runtime, SupportedParasRuntimeType::AssetHub)
        .await
}

async fn create_substrate_client_from_rpc_client(
    rpc_client: RpcClient,
) -> Result<OnlineClient<PolkadotConfig>, OnetError> {
    OnlineClient::<PolkadotConfig>::from_rpc_client(rpc_client)
        .await
        .map_err(|err| OnetError::SubxtError(err.into()))
}

/// Represents the connection details for a substrate node
#[derive(Debug)]
struct NodeConnection {
    chain: String,
    name: String,
    version: String,
    properties: serde_json::Map<String, serde_json::Value>,
}

/// Result type for substrate client creation
#[derive(Debug)]
pub struct SubstrateClients {
    pub relay_client: OnlineClient<PolkadotConfig>,
    pub relay_rpc: LegacyRpcMethods<PolkadotConfig>,
    pub people_client: Option<OnlineClient<PolkadotConfig>>,
    pub asset_hub_client: Option<OnlineClient<PolkadotConfig>>,
    pub asset_hub_rpc: Option<LegacyRpcMethods<PolkadotConfig>>,
    pub runtime: SupportedRuntime,
}

/// Creates or awaits a connection to a substrate node
///
/// # Arguments
///
/// * `config` - Configuration for the substrate node connection
///
/// # Returns
///
/// Returns a tuple containing the relay client, legacy RPC methods, optional people client, and runtime
pub async fn create_or_await_substrate_node_clients(config: Config) -> SubstrateClients {
    loop {
        match attempt_connection(&config).await {
            Ok(clients) => break clients,
            Err(e) => handle_connection_error(&e, &config.substrate_ws_url).await,
        }
    }
}

async fn attempt_connection(config: &Config) -> Result<SubstrateClients, OnetError> {
    let rpc_client = create_substrate_rpc_client_from_config(config.clone()).await?;
    let relay_rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client.clone().into());

    let node_connection = fetch_node_connection_details(&relay_rpc).await?;
    configure_chain_settings(&node_connection);

    let relay_client = create_substrate_client_from_rpc_client(rpc_client.into()).await?;
    let runtime = SupportedRuntime::from(get_chain_token_symbol(&node_connection.properties));
    let people_client = create_people_client_from_supported_runtime(runtime).await?;
    let asset_hub_client = create_asset_hub_client_from_supported_runtime(runtime).await?;
    let asset_hub_rpc = create_asset_hub_legacy_rpc_from_supported_runtime(runtime).await?;

    info!(
        "Connected to {} network using {} * Substrate node {} v{}",
        node_connection.chain,
        config.substrate_ws_url,
        node_connection.name,
        node_connection.version
    );

    Ok(SubstrateClients {
        relay_client,
        relay_rpc,
        people_client,
        asset_hub_client,
        asset_hub_rpc,
        runtime,
    })
}

async fn fetch_node_connection_details(
    legacy_rpc: &LegacyRpcMethods<PolkadotConfig>,
) -> Result<NodeConnection, OnetError> {
    Ok(NodeConnection {
        chain: legacy_rpc.system_chain().await.unwrap_or_default(),
        name: legacy_rpc.system_name().await.unwrap_or_default(),
        version: legacy_rpc.system_version().await.unwrap_or_default(),
        properties: legacy_rpc.system_properties().await.unwrap_or_default(),
    })
}

fn configure_chain_settings(node_connection: &NodeConnection) {
    let chain_prefix = get_chain_prefix(&node_connection.properties);
    crypto::set_default_ss58_version(crypto::Ss58AddressFormat::custom(chain_prefix));
}

fn get_chain_prefix(properties: &serde_json::Map<String, serde_json::Value>) -> ChainPrefix {
    properties
        .get("ss58Format")
        .and_then(|format| format.as_u64())
        .map(|prefix| prefix.try_into().unwrap_or_default())
        .unwrap_or_default()
}

fn get_chain_token_symbol(
    properties: &serde_json::Map<String, serde_json::Value>,
) -> ChainTokenSymbol {
    properties
        .get("tokenSymbol")
        .and_then(|symbol| symbol.as_str())
        .map(String::from)
        .unwrap_or_default()
}

async fn handle_connection_error(error: &OnetError, ws_url: &str) {
    error!("{}", error);
    info!("Awaiting for connection using {}", ws_url);
    thread::sleep(Duration::from_secs(RECONNECTION_DELAY_SECS));
}

// DEPRECATED
// pub async fn create_or_await_substrate_node_client(
//     config: Config,
// ) -> (
//     OnlineClient<PolkadotConfig>,
//     LegacyRpcMethods<PolkadotConfig>,
//     Option<OnlineClient<PolkadotConfig>>,
//     SupportedRuntime,
// ) {
//     loop {
//         match create_substrate_rpc_client_from_config(config.clone()).await {
//             Ok(rpc_client) => {
//                 let legacy_rpc = LegacyRpcMethods::<PolkadotConfig>::new(rpc_client.clone().into());
//                 let chain = legacy_rpc.system_chain().await.unwrap_or_default();
//                 let name = legacy_rpc.system_name().await.unwrap_or_default();
//                 let version = legacy_rpc.system_version().await.unwrap_or_default();
//                 let properties = legacy_rpc.system_properties().await.unwrap_or_default();

//                 // Display SS58 addresses based on the connected chain
//                 let chain_prefix: ChainPrefix =
//                     if let Some(ss58_format) = properties.get("ss58Format") {
//                         ss58_format.as_u64().unwrap_or_default().try_into().unwrap()
//                     } else {
//                         0
//                     };

//                 crypto::set_default_ss58_version(crypto::Ss58AddressFormat::custom(chain_prefix));

//                 let chain_token_symbol: ChainTokenSymbol =
//                     if let Some(token_symbol) = properties.get("tokenSymbol") {
//                         use serde_json::Value::String;
//                         match token_symbol {
//                             String(token_symbol) => token_symbol.to_string(),
//                             _ => unreachable!("Token symbol with wrong type"),
//                         }
//                     } else {
//                         String::from("")
//                     };

//                 info!(
//                     "Connected to {} network using {} * Substrate node {} v{}",
//                     chain, config.substrate_ws_url, name, version
//                 );

//                 match create_substrate_client_from_rpc_client(rpc_client.clone().into()).await {
//                     Ok(relay_client) => {
//                         // Create people chain client depending on the runtime selected
//                         let runtime = SupportedRuntime::from(chain_token_symbol);
//                         match create_people_client_from_supported_runtime(runtime).await {
//                             Ok(people_client_option) => {
//                                 break (relay_client, legacy_rpc, people_client_option, runtime);
//                             }

//                             Err(e) => {
//                                 error!("{}", e);
//                                 info!("Awaiting for connection using {}", config.substrate_ws_url);
//                                 thread::sleep(time::Duration::from_secs(6));
//                             }
//                         }
//                     }
//                     Err(e) => {
//                         error!("{}", e);
//                         info!("Awaiting for connection using {}", config.substrate_ws_url);
//                         thread::sleep(time::Duration::from_secs(6));
//                     }
//                 }
//             }
//             Err(e) => {
//                 error!("{}", e);
//                 info!("Awaiting for connection using {}", config.substrate_ws_url);
//                 thread::sleep(time::Duration::from_secs(6));
//             }
//         }
//     }
// }

pub struct Onet {
    runtime: SupportedRuntime,
    client: OnlineClient<PolkadotConfig>,
    rpc: LegacyRpcMethods<PolkadotConfig>,
    // Note: people_client is optional to easily enable/disable identity logic from people's chain
    // or relay chain
    people_client_option: Option<OnlineClient<PolkadotConfig>>,
    // Note: asset_hub_client is optional to easily enable/disable staking logic from asset hub chain
    // or relay chain
    asset_hub_client_option: Option<OnlineClient<PolkadotConfig>>,
    asset_hub_rpc_option: Option<LegacyRpcMethods<PolkadotConfig>>,
    matrix: Matrix,
    pub cache: RedisPool,
    config: Config,
}

impl Onet {
    pub async fn new() -> Onet {
        let config = CONFIG.clone();
        let clients = create_or_await_substrate_node_clients(CONFIG.clone()).await;

        // Initialize matrix client
        let mut matrix: Matrix = Matrix::new();
        matrix
            .authenticate(clients.runtime)
            .await
            .unwrap_or_else(|e| {
                error!("{}", e);
                Default::default()
            });

        Onet {
            runtime: clients.runtime,
            client: clients.relay_client,
            rpc: clients.relay_rpc,
            people_client_option: clients.people_client,
            asset_hub_client_option: clients.asset_hub_client,
            asset_hub_rpc_option: clients.asset_hub_rpc,
            matrix,
            cache: create_or_await_pool(CONFIG.clone()),
            config,
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

    // DEPRECATE, use relay_client
    pub fn client(&self) -> &OnlineClient<PolkadotConfig> {
        &self.client
    }

    // DEPRECATE, use relay_rpc
    pub fn rpc(&self) -> &LegacyRpcMethods<PolkadotConfig> {
        &self.rpc
    }

    pub fn relay_rpc(&self) -> &LegacyRpcMethods<PolkadotConfig> {
        &self.rpc
    }

    pub fn relay_client(&self) -> &OnlineClient<PolkadotConfig> {
        &self.client
    }

    pub fn people_client(&self) -> &OnlineClient<PolkadotConfig> {
        &self.people_client_option.as_ref().unwrap_or(&self.client)
    }

    pub fn asset_hub_client(&self) -> &OnlineClient<PolkadotConfig> {
        self.asset_hub_client_option
            .as_ref()
            .unwrap_or(&self.client)
    }

    pub fn asset_hub_rpc(&self) -> &LegacyRpcMethods<PolkadotConfig> {
        self.asset_hub_rpc_option.as_ref().unwrap_or(&self.rpc)
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
        if !self.config.cache_writer_enabled {
            return Ok(());
        }

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
