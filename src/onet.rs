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
use crate::matrix::Matrix;
use crate::runtimes::{
    kusama,
    support::{ChainPrefix, SupportedRuntime},
};
use log::{debug, error, info, warn};
use reqwest::Url;
use serde::Deserialize;
use std::{convert::TryInto, result::Result, str::FromStr, thread, time};
use subxt::{
    sp_core::{crypto, storage::StorageKey},
    sp_runtime::AccountId32,
    Client, ClientBuilder, DefaultConfig,
};

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

    pub async fn send_message(
        &self,
        message: &str,
        formatted_message: &str,
    ) -> Result<(), OnetError> {
        self.matrix()
            .send_message(message, formatted_message)
            .await?;
        Ok(())
    }

    /// Spawn and restart subscription on error
    pub fn subscribe() {
        spawn_and_restart_subscription_on_error();
    }

    async fn subscribe_on_chain_events(&self) -> Result<(), OnetError> {
        let config = CONFIG.clone();

        match self.runtime {
            SupportedRuntime::Polkadot => kusama::init_and_subscribe_on_chain_events(self).await,
            SupportedRuntime::Kusama => kusama::init_and_subscribe_on_chain_events(self).await,
        }
    }
}

fn spawn_and_restart_subscription_on_error() {
    let t = async_std::task::spawn(async {
        let config = CONFIG.clone();
        loop {
            let t: Onet = Onet::new().await;
            if let Err(e) = t.subscribe_on_chain_events().await {
                match e {
                    OnetError::SubscriptionFinished => warn!("{}", e),
                    OnetError::MatrixError(_) => warn!("Matrix message skipped!"),
                    _ => {
                        error!("{}", e);
                        let message = format!("On hold for {} min!", config.error_interval);
                        let formatted_message = format!("<br/>🚨 An error was raised -> <code>onet</code> on hold for {} min while rescue is on the way 🚁 🚒 🚑 🚓<br/><br/>", config.error_interval);
                        t.send_message(&message, &formatted_message).await.unwrap();
                        thread::sleep(time::Duration::from_secs(60 * config.error_interval));
                        continue;
                    }
                }
                thread::sleep(time::Duration::from_secs(1));
            };
        }
    });
    async_std::task::block_on(t);
}

fn skip_serializing_stash<String: std::fmt::Display + std::fmt::Debug>(stash: &String) -> bool {
    warn!("skip_serializing_stash_ {:?}", stash);
    true
}

type ValidatorsFromTVP = Vec<ValidatorFromTVP>;

#[derive(Deserialize, Debug)]
struct ValidatorFromTVP {
    #[serde(default)]
    stash: String,
}

/// Fetch stashes from 1kv endpoint https://polkadot.w3f.community/candidates
pub async fn try_fetch_stashes_from_remote_url(
    chain_name: &str,
) -> Result<Option<Vec<AccountId32>>, OnetError> {
    let url = format!(
        "https://{}.w3f.community/candidates",
        chain_name.to_lowercase()
    );
    let url = Url::parse(&*url)?;

    let validators: ValidatorsFromTVP = reqwest::get(url).await?.json().await?;
    debug!("validators {:?}", validators);

    let v: Vec<AccountId32> = validators
        .iter()
        .map(|x| AccountId32::from_str(&x.stash).unwrap())
        .collect();
    Ok(Some(v))
}

pub fn get_account_id_from_storage_key(key: StorageKey) -> AccountId32 {
    let s = &key.0[key.0.len() - 32..];
    let v: [u8; 32] = s.try_into().expect("slice with incorrect length");
    AccountId32::new(v)
}
