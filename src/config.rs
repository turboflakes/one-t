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

/// provides default value for interval if ONET_INTERVAL env var is not set
fn default_interval() -> u64 {
    21600
}

/// provides default value for error interval if ONET_ERROR_INTERVAL env var is not set
fn default_error_interval() -> u64 {
    5
}

/// provides default value for subscribers_path if ONET_SUBSCRIBERS_PATH env var is not set
fn default_subscribers_path() -> String {
    ".subscribers".into()
}

/// provides default value for maximum_subscribers if ONET_MAXIMUM_SUBSCRIBERS env var is not set
fn default_maximum_subscribers() -> u32 {
    1000
}

/// provides default value for maximum_eras if ONET_MAXIMUM_HISTORY_ERAS env var is not set
fn default_maximum_history_eras() -> u32 {
    8
}

/// provides default value for session_rate if ONET_SESSION_RATE env var is not set
fn default_session_rate() -> u32 {
    6
}

#[derive(Clone, Deserialize, Debug)]
pub struct Config {
    #[serde(default = "default_interval")]
    pub interval: u64,
    #[serde(default = "default_error_interval")]
    pub error_interval: u64,
    pub substrate_ws_url: String,
    #[serde(default = "default_subscribers_path")]
    pub subscribers_path: String,
    #[serde(default = "default_maximum_subscribers")]
    pub maximum_subscribers: u32,
    #[serde(default = "default_maximum_history_eras")]
    pub maximum_history_eras: u32,
    #[serde(default = "default_session_rate")]
    pub session_rate: u32,
    #[serde(default)]
    pub is_debug: bool,
    // matrix configuration
    #[serde(default)]
    pub matrix_public_room: String,
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
          .possible_values(&["kusama", "polkadot"])
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
      Arg::with_name("subscribers-path")
        .long("subscribers-path")
        .takes_value(true)
        .value_name("FILE")
        .help(
          "Sets a custom subscribers file path. The subscribers file contains stashes and matrix user ids that have subscribed to receive the report.",
        ),
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
        .help("Your regular matrix user. e.g. '@your-regular-matrix-account:matrix.org' this user account will receive notifications from your other 'Onet Bot' matrix account.")
      )
    .arg(
      Arg::with_name("matrix-bot-user")
        .long("matrix-bot-user")
        .takes_value(true)
        .help("Your new 'Onet Bot' matrix user. e.g. '@your-own-bot-account:matrix.org' this user account will be your 'Onet Bot' which will be responsible to send messages/notifications to your private or public 'Onet Bot' rooms.")
      )
    .arg(
      Arg::with_name("matrix-bot-password")
        .long("matrix-bot-password")
        .takes_value(true)
        .help("Password for the 'Onet Bot' matrix user sign in.")
      )
    .arg(
      Arg::with_name("disable-matrix")
        .long("disable-matrix")
        .help(
          "Disable matrix bot for 'onet'. (e.g. with this flag active 'onet' will not send messages/notifications about claimed or unclaimed staking rewards to your private or public 'Onet Bot' rooms) (https://matrix.org/)",
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
      Arg::with_name("session-rate")
            .long("session-rate")
            .takes_value(true)
            .help("The frequency at which the full report is triggered. Recommended every 6 sessions on Polkadot (24 hours) and every 24 sessions on Kusama (24 hours). [default: 6]")
    )
    .arg(
      Arg::with_name("config-path")
        .short("c")
        .long("config-path")
        .takes_value(true)
        .value_name("FILE")
        .default_value(".env")
        .help(
          "Sets a custom config file path. The config file contains 'onet' configuration variables.",
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
        Some("kusama") => {
            env::set_var("ONET_SUBSTRATE_WS_URL", "wss://kusama-rpc.polkadot.io:443");
        }
        Some("polkadot") => {
            env::set_var("ONET_SUBSTRATE_WS_URL", "wss://rpc.polkadot.io:443");
        }
        _ => {
            if env::var("ONET_SUBSTRATE_WS_URL").is_err() {
                env::set_var("ONET_SUBSTRATE_WS_URL", "ws://127.0.0.1:9944");
            };
        }
    }

    if let Some(subscribers_path) = matches.value_of("subscribers-path") {
        env::set_var("ONET_SUBSCRIBERS_PATH", subscribers_path);
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

    if matches.is_present("disable-matrix") {
        env::set_var("ONET_MATRIX_DISABLED", "true");
    }

    if matches.is_present("disable-public-matrix-room") {
        env::set_var("ONET_MATRIX_PUBLIC_ROOM_DISABLED", "true");
    }

    if let Some(matrix_public_room) = matches.value_of("matrix-public-room") {
        env::set_var("ONET_MATRIX_PUBLIC_ROOM", matrix_public_room);
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
