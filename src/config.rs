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

// Load environment variables into a Config struct
//
// Envy is a library for deserializing environment variables into
// typesafe structs
//
// Dotenv loads environment variables from a .env file, if available,
// and mashes those with the actual environment variables provided by
// the operative system.
//
// Set Config struct into a CONFIG lazy_static to avoid multiple processing.
//
use clap::{App, Arg};
use dotenv;
use lazy_static::lazy_static;
use log::info;
use serde::Deserialize;
use std::env;

// Set Config struct into a CONFIG lazy_static to avoid multiple processing
lazy_static! {
    pub static ref CONFIG: Config = get_config();
}

/// provides default value for subscribers_path if ONET_SUBSCRIBERS_PATH env var is not set
fn default_chain_name() -> String {
    "polkadot".into()
}

/// provides default value for interval if ONET_INTERVAL env var is not set
fn default_interval() -> u64 {
    21600
}

/// provides default value for eras_per_day if ONET_ERAS_PER_DAY var is not set
fn default_eras_per_day() -> u32 {
    1
}

/// provides default value for blocks per session target if ONET_BLOCKS_PER_SESSION var is not set
/// kusama = 600
/// polkadot = 4 * 600 = 2400
fn default_blocks_per_session() -> u32 {
    2400
}

/// provides default value in seconds for error interval if ONET_ERROR_INTERVAL env var is not set
fn default_error_interval() -> u64 {
    30
}

/// provides default value for data_path if ONET_DATA_PATH env var is not set
fn default_data_path() -> String {
    "./".into()
}

/// provides default value for maximum_subscribers if ONET_MAXIMUM_SUBSCRIBERS env var is not set
fn default_maximum_subscribers() -> u32 {
    1000
}

/// provides default value for minimum_initial_eras if ONET_MINIMUM_INITIAL_ERAS env var is not set
fn default_minimum_initial_eras() -> u32 {
    0
}

/// provides default value for maximum_eras if ONET_MAXIMUM_HISTORY_ERAS env var is not set
fn default_maximum_history_eras() -> u32 {
    8
}

/// provides default value for maximum_reports if ONET_MAXIMUM_REPORTS env var is not set
fn default_maximum_reports() -> u32 {
    6
}

/// provides default value for callout_epoch_rate if ONET_MATRIX_CALLOUT_EPOCH_RATE env var is not set
fn default_matrix_callout_epoch_rate() -> u32 {
    6
}

/// provides default value for callout_epoch_rate if ONET_MATRIX_NETWORK_REPORT_EPOCH_RATE env var is not set
/// example: 1 era = 6 sessions/epochs
fn default_matrix_network_report_epoch_rate() -> u32 {
    6
}

/// provides default value for mvr_level_1 if ONET_MVR_LEVEL_1 env var is not set
/// example: 20% = 2000
fn default_mvr_level_1() -> u32 {
    2000
}
fn default_mvr_level_2() -> u32 {
    4000
}
fn default_mvr_level_3() -> u32 {
    6000
}
fn default_mvr_level_4() -> u32 {
    9000
}

/// provides default value for pools_nominate_rate if ONET_POOLS_NOMINATE_RATE env var is not set
/// example: 1 era = 6 sessions/epochs
fn default_pools_nominate_rate() -> u32 {
    6
}

/// provides default value for seed_path if ONET_POOLS_NOMINATOR_SEED_PATH env var is not set
fn default_pools_nominator_seed_path() -> String {
    ".nominator.seed".into()
}

/// provides default value for nomination_pools_nominate_rate if ONET_POOLS_MINIMUM_SESSIONS env var is not set
/// example: 1 era = 6 sessions/epochs
fn default_pools_minimum_sessions() -> u32 {
    6
}

/// provides default value for pools_maximum_nominations if ONET_POOLS_MAXIMUM_NOMINATIONS env var is not set
/// example: 16 for Polkadot and 24 for Kusama
fn default_pools_maximum_nominations() -> u32 {
    16
}

/// provides default value for nomination_pools_nominate_rate if ONET_MAXIMUM_TOP_RANKING env var is not set
fn default_maximum_top_ranking() -> u32 {
    16
}

/// provides default value for nomination_pools_nominate_rate if ONET_MAXIMUM_TOP_RANKING_CALLOUT env var is not set
fn default_maximum_top_ranking_callout() -> u32 {
    4
}

/// provides default value for api_host if ONET_API_HOST env var is not set
fn default_api_host() -> String {
    "127.0.0.1".into()
}

/// provides default value for api_port if ONET_API_PORT env var is not set
fn default_api_port() -> u16 {
    5010
}

/// provides default value for api_port if ONET_API_PORT env var is not set
fn default_api_cors_allow_origin() -> String {
    "*".into()
}

/// provides default value for redis_host if ONET_REDIS_HOST env var is not set
fn default_redis_host() -> String {
    "127.0.0.1".into()
}

/// provides default value for redis_database if ONET_REDIS_DATABASE env var is not set
fn default_redis_database() -> u8 {
    0
}

#[derive(Clone, Deserialize, Debug)]
pub struct Config {
    // general
    #[serde(default = "default_chain_name")]
    pub chain_name: String,
    #[serde(default = "default_interval")]
    pub interval: u64,
    #[serde(default = "default_eras_per_day")]
    pub eras_per_day: u32,
    #[serde(default = "default_blocks_per_session")]
    pub blocks_per_session: u32,
    #[serde(default = "default_error_interval")]
    pub error_interval: u64,
    pub substrate_ws_url: String,
    #[serde(default = "default_data_path")]
    pub data_path: String,
    #[serde(default = "default_maximum_subscribers")]
    pub maximum_subscribers: u32,
    #[serde(default = "default_minimum_initial_eras")]
    pub minimum_initial_eras: u32,
    #[serde(default = "default_maximum_history_eras")]
    pub maximum_history_eras: u32,
    #[serde(default = "default_maximum_reports")]
    pub maximum_reports: u32,
    #[serde(default = "default_mvr_level_1")]
    pub mvr_level_1: u32,
    #[serde(default = "default_mvr_level_2")]
    pub mvr_level_2: u32,
    #[serde(default = "default_mvr_level_3")]
    pub mvr_level_3: u32,
    #[serde(default = "default_mvr_level_4")]
    pub mvr_level_4: u32,
    #[serde(default)]
    pub is_debug: bool,
    #[serde(default)]
    pub initial_block_number: u64,
    // ranking
    #[serde(default = "default_maximum_top_ranking")]
    pub maximum_top_ranking: u32,
    #[serde(default = "default_maximum_top_ranking_callout")]
    pub maximum_top_ranking_callout: u32,
    // nomination pools
    #[serde(default)]
    pub pools_enabled: bool,
    #[serde(default)]
    pub pool_id_1: u32,
    #[serde(default)]
    pub pool_id_2: u32,
    #[serde(default = "default_pools_nominator_seed_path")]
    pub pools_nominator_seed_path: String,
    #[serde(default = "default_pools_nominate_rate")]
    pub pools_nominate_rate: u32,
    #[serde(default = "default_pools_minimum_sessions")]
    pub pools_minimum_sessions: u32,
    #[serde(default = "default_pools_maximum_nominations")]
    pub pools_maximum_nominations: u32,
    // matrix configuration
    #[serde(default)]
    pub matrix_public_room: String,
    #[serde(default)]
    pub matrix_callout_public_rooms: Vec<String>,
    #[serde(default)]
    pub matrix_callout_public_room_ids: Vec<String>,
    #[serde(default = "default_matrix_callout_epoch_rate")]
    pub matrix_callout_epoch_rate: u32,
    #[serde(default = "default_matrix_network_report_epoch_rate")]
    pub matrix_network_report_epoch_rate: u32,
    #[serde(default)]
    pub matrix_bot_user: String,
    #[serde(default)]
    pub matrix_bot_password: String,
    #[serde(default)]
    pub matrix_disabled: bool,
    #[serde(default)]
    pub matrix_public_room_disabled: bool,
    #[serde(default)]
    pub matrix_bot_display_name_disabled: bool,
    // api
    #[serde(default)]
    pub api_enabled: bool,
    #[serde(default = "default_api_host")]
    pub api_host: String,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    #[serde(default = "default_api_cors_allow_origin")]
    pub api_cors_allow_origin: String,
    // redis configuration
    #[serde(default = "default_redis_host")]
    pub redis_hostname: String,
    #[serde(default)]
    pub redis_password: String,
    #[serde(default = "default_redis_database")]
    pub redis_database: u8,
}

/// Inject dotenv and env vars into the Config struct
fn get_config() -> Config {
    // Define CLI flags with clap
    let matches = App::new(env!("CARGO_PKG_NAME"))
    .version(env!("CARGO_PKG_VERSION"))
    .author(env!("CARGO_PKG_AUTHORS"))
    .about(env!("CARGO_PKG_DESCRIPTION"))
    .arg(
      Arg::with_name("CHAIN")
          .index(1)
          .possible_values(&["westend", "kusama", "polkadot"])
          .help(
            "Sets the substrate-based chain for which 'onet' will try to connect",
          )
    )
    .arg(
      Arg::with_name("debug")
        .long("debug")
        .help("Prints debug information verbosely.")
      )
    .arg(
      Arg::with_name("maximum-subscribers")
            .long("maximum-subscribers")
            .takes_value(true)
            .help("Maximum number of subscribers allowed. [default: 1000]")
    )
    .arg(
      Arg::with_name("matrix-public-room")
        .long("matrix-public-room")
        .takes_value(true)
        .help("Matrix public room where 'ONE-T' will publish reports and listen for subscriptions.")
      )
    .arg(
      Arg::with_name("matrix-callout-public-rooms")
        .long("matrix-callout-public-rooms")
        .takes_value(true)
        .help("Matrix public rooms where 'ONE-T' will publish callout messages.")
    )
    .arg(
      Arg::with_name("matrix-bot-user")
        .long("matrix-bot-user")
        .takes_value(true)
        .help("'ONE-T'  matrix user. e.g. '@your-own-bot-account:matrix.org' this user account will be your 'ONE-T' which will be responsible to send messages/notifications to your private or public 'ONE-T' rooms.")
      )
    .arg(
      Arg::with_name("matrix-bot-password")
        .long("matrix-bot-password")
        .takes_value(true)
        .help("Password for the 'ONE-T' matrix user sign in.")
      )
    .arg(
      Arg::with_name("disable-matrix")
        .long("disable-matrix")
        .help(
          "Disable matrix bot for 'onet'. (e.g. with this flag active 'onet' will not send messages/notifications about claimed or unclaimed staking rewards to your private or public 'ONE-T' rooms) (https://matrix.org/)",
        ),
      )
    .arg(
      Arg::with_name("disable-public-matrix-room")
        .long("disable-public-matrix-room")
        .help(
          "Disable notification reports to be sent to the matrix public room",
        ),
      )
    .arg(
      Arg::with_name("disable-matrix-bot-display-name")
        .long("disable-matrix-bot-display-name")
        .help(
          "Disable matrix bot display name update for 'onet'. (e.g. with this flag active 'onet' will not change the matrix bot user display name)",
        ),
      )
    .arg(
      Arg::with_name("short")
        .long("short")
        .help("Display only essential information (e.g. with this flag active 'onet' will only send essential messages/notifications about claimed rewards)")
      )
    .arg(
      Arg::with_name("error-interval")
        .long("error-interval")
        .takes_value(true)
        .help("Interval value (in minutes) from which 'onet' will restart again in case of a critical error.")
      )
    .arg(
      Arg::with_name("substrate-ws-url")
        .short("w")
        .long("substrate-ws-url")
        .takes_value(true)
        .help(
          "Substrate websocket endpoint for which 'onet' will try to connect. (e.g. wss://kusama-rpc.polkadot.io) (NOTE: substrate_ws_url takes precedence than <CHAIN> argument)",
        ),
    )
    .arg(
      Arg::with_name("maximum-history-eras")
            .long("maximum-history-eras")
            .takes_value(true)
            .help("Maximum number of history eras for which `onet` will calculate the average of points collected. The maximum value supported is the one defined by the constant history_depth which normal value is 84. [default: 8]")
    )
    .arg(
      Arg::with_name("maximum-reports")
            .long("maximum-reports")
            .takes_value(true)
            .help("Maximum number of reports subscribed. [default: 6]")
    )
    .arg(
      Arg::with_name("matrix-callout-epoch-rate")
            .long("matrix-callout-epoch-rate")
            .takes_value(true)
            .help("The frequency at which the callout message is triggered. Recommended every 6 sessions on Polkadot (24 hours) and every 24 sessions on Kusama (24 hours). [default: 6]")
    )
    .arg(
      Arg::with_name("matrix-network-report-epoch-rate")
            .long("matrix-network-report-epoch-rate")
            .takes_value(true)
            .help("The frequency at which the network report message is triggered. Recommended every 6 sessions on Polkadot (24 hours) and every 6 sessions on Kusama (6 hours). [default: 6]")
    )
    .arg(
      Arg::with_name("config-path")
        .short("c")
        .long("config-path")
        .takes_value(true)
        .value_name("FILE")
        .default_value(".env")
        .help(
          "Sets a custom config file path. The config file contains 'one-t' configuration variables.",
        ),
    )
    .arg(
      Arg::with_name("data-path")
        .long("data-path")
        .takes_value(true)
        .help(
          "Sets a custom directory path to store data files. The data directory contains 'one-t' data files.",
        ),
    )
    .get_matches();

    // Try to load configuration from file first
    let config_path = matches.value_of("config-path").unwrap_or(".env");
    match dotenv::from_filename(&config_path).ok() {
        Some(_) => info!("Loading configuration from {} file", &config_path),
        None => {
            let config_path = env::var("ONET_CONFIG_FILENAME").unwrap_or(".env".to_string());
            if let Some(_) = dotenv::from_filename(&config_path).ok() {
                info!("Loading configuration from {} file", &config_path);
            }
        }
    }

    match matches.value_of("CHAIN") {
        Some("westend") => {
            if env::var("ONET_SUBSTRATE_WS_URL").is_err() {
                env::set_var("ONET_SUBSTRATE_WS_URL", "wss://westend-rpc.polkadot.io:443");
            }
            env::set_var("ONET_CHAIN_NAME", "westend");
        }
        Some("kusama") => {
            if env::var("ONET_SUBSTRATE_WS_URL").is_err() {
                env::set_var("ONET_SUBSTRATE_WS_URL", "wss://kusama-rpc.polkadot.io:443");
            }
            env::set_var("ONET_CHAIN_NAME", "kusama");
        }
        Some("polkadot") => {
            if env::var("ONET_SUBSTRATE_WS_URL").is_err() {
                env::set_var("ONET_SUBSTRATE_WS_URL", "wss://rpc.polkadot.io:443");
            }
            env::set_var("ONET_CHAIN_NAME", "polkadot");
        }
        _ => {
            if env::var("ONET_SUBSTRATE_WS_URL").is_err() {
                env::set_var("ONET_SUBSTRATE_WS_URL", "ws://127.0.0.1:9944");
            };
        }
    }

    if let Some(data_path) = matches.value_of("data-path") {
        env::set_var("ONET_DATA_PATH", data_path);
    }

    if let Some(substrate_ws_url) = matches.value_of("substrate-ws-url") {
        env::set_var("ONET_SUBSTRATE_WS_URL", substrate_ws_url);
    }

    if let Some(maximum_subscribers) = matches.value_of("maximum-subscribers") {
        env::set_var("ONET_MAXIMUM_SUBSCRIBERS", maximum_subscribers);
    }

    if let Some(maximum_history_eras) = matches.value_of("maximum-history-eras") {
        env::set_var("ONET_MAXIMUM_HISTORY_ERAS", maximum_history_eras);
    }

    if let Some(maximum_reports) = matches.value_of("maximum-reports") {
        env::set_var("ONET_MAXIMUM_REPORTS", maximum_reports);
    }

    if matches.is_present("disable-matrix") {
        env::set_var("ONET_MATRIX_DISABLED", "true");
    }

    if matches.is_present("disable-public-matrix-room") {
        env::set_var("ONET_MATRIX_PUBLIC_ROOM_DISABLED", "true");
    }

    if let Some(matrix_public_room) = matches.value_of("matrix-public-room") {
        env::set_var("ONET_MATRIX_PUBLIC_ROOM", matrix_public_room);
    }

    if let Some(matrix_callout_public_rooms) = matches.value_of("matrix-callout-public-rooms") {
        env::set_var(
            "ONET_MATRIX_CALLOUT_PUBLIC_ROOMS",
            matrix_callout_public_rooms,
        );
    }
    // NOTE: matrix_callout_public_room_ids is needed because some public rooms are not available from room alias, only through room id
    if let Some(matrix_callout_public_room_ids) = matches.value_of("matrix-callout-public-room-ids")
    {
        env::set_var(
            "ONET_MATRIX_CALLOUT_PUBLIC_ROOM_IDS",
            matrix_callout_public_room_ids,
        );
    }

    if let Some(matrix_callout_epoch_rate) = matches.value_of("matrix-callout-epoch-rate") {
        env::set_var("ONET_MATRIX_CALLOUT_EPOCH_RATE", matrix_callout_epoch_rate);
    }

    if let Some(matrix_network_report_epoch_rate) =
        matches.value_of("matrix-network-report-epoch-rate")
    {
        env::set_var(
            "ONET_MATRIX_NETWORK_REPORT_EPOCH_RATE",
            matrix_network_report_epoch_rate,
        );
    }

    if let Some(matrix_bot_user) = matches.value_of("matrix-bot-user") {
        env::set_var("ONET_MATRIX_BOT_USER", matrix_bot_user);
    }

    if let Some(matrix_bot_password) = matches.value_of("matrix-bot-password") {
        env::set_var("ONET_MATRIX_BOT_PASSWORD", matrix_bot_password);
    }

    if let Some(error_interval) = matches.value_of("error-interval") {
        env::set_var("ONET_ERROR_INTERVAL", error_interval);
    }

    if matches.is_present("debug") {
        env::set_var("ONET_IS_DEBUG", "true");
    }

    match envy::prefixed("ONET_").from_env::<Config>() {
        Ok(config) => config,
        Err(error) => panic!("Configuration error: {:#?}", error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_gets_a_config() {
        let config = get_config();
        assert_ne!(config.substrate_ws_url, "".to_string());
    }

    #[test]
    fn it_gets_a_config_from_the_lazy_static() {
        let config = &CONFIG;
        assert_ne!(config.substrate_ws_url, "".to_string());
    }
}
