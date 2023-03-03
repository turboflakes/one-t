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
use crate::onet::ReportType;
use crate::records::{
    grade, AuthorityIndex, AuthorityRecord, ParaId, ParaRecord, ParaStats, Pattern, Points,
};
use log::info;
use rand::Rng;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    convert::{TryFrom, TryInto},
    result::Result,
};

use subxt::ext::sp_runtime::AccountId32;
use subxt::{OnlineClient, PolkadotConfig};

use flate2::write;
use flate2::Compression;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Validator {
    pub stash: AccountId32,
    pub controller: Option<AccountId32>,
    pub subset: Subset,
    pub name: String,
    pub is_active: bool,
    pub is_oversubscribed: bool,
    pub commission: f64,
    pub own_stake: u128,
    pub total_points: u32,
    pub total_eras: u32,
    pub maximum_history_total_points: u32,
    pub maximum_history_total_eras: u32,
    pub total_authored_blocks: u32,
    pub pattern: Pattern,
    pub authored_blocks: u32,
    pub active_epochs: u32,
    pub para_epochs: u32,
    pub avg_para_points: u32,
    pub explicit_votes: u32,
    pub implicit_votes: u32,
    pub missed_votes: u32,
    pub core_assignments: u32,
    pub missed_ratio: Option<f64>,
    pub score: f64,
    pub commission_score: f64,
    pub warnings: Vec<String>,
}

impl Validator {
    pub fn new(stash: AccountId32) -> Self {
        Self {
            stash,
            controller: None,
            subset: Subset::NONTVP,
            name: "".to_string(),
            is_active: false,
            is_oversubscribed: false,
            commission: 0.0_f64,
            own_stake: 0,
            total_points: 0,
            total_eras: 0,
            maximum_history_total_points: 0,
            maximum_history_total_eras: 0,
            total_authored_blocks: 0,
            pattern: Vec::new(),
            authored_blocks: 0,
            active_epochs: 0,
            para_epochs: 0,
            avg_para_points: 0,
            explicit_votes: 0,
            implicit_votes: 0,
            missed_votes: 0,
            core_assignments: 0,
            missed_ratio: None,
            score: 0.0_f64,
            commission_score: 0.0_f64,
            warnings: Vec::new(),
        }
    }
}

pub type Validators = Vec<Validator>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Subset {
    TVP,
    NONTVP,
    C100,
    NotDefined,
}

impl std::fmt::Display for Subset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TVP => write!(f, "TVP"),
            Self::NONTVP => write!(f, "OTH"),
            Self::C100 => write!(f, "100C"),
            Self::NotDefined => write!(f, "NotDefined"),
        }
    }
}

impl Default for Subset {
    fn default() -> Subset {
        Subset::NONTVP
    }
}

#[derive(Debug, Clone)]
pub struct Network {
    pub name: String,
    pub token_symbol: String,
    pub token_decimals: u8,
    pub ss58_format: u8,
}

impl Network {
    pub async fn load(api: &OnlineClient<PolkadotConfig>) -> Result<Network, OnetError> {
        let properties = api.rpc().system_properties().await?;

        // Get Network name
        let chain_name = api.rpc().system_chain().await?;

        // Get Token symbol
        let token_symbol: String = if let Some(token_symbol) = properties.get("tokenSymbol") {
            token_symbol.as_str().unwrap_or_default().to_string()
        } else {
            "ND".to_string()
        };

        // Get Token decimals
        let token_decimals: u8 = if let Some(value) = properties.get("tokenDecimals") {
            value.as_u64().unwrap_or_default().try_into().unwrap()
        } else {
            12
        };

        // Get ss58 format
        let ss58_format: u8 = if let Some(value) = properties.get("ss58Format") {
            value.as_u64().unwrap_or_default().try_into().unwrap()
        } else {
            42
        };

        Ok(Network {
            name: chain_name,
            token_symbol,
            token_decimals,
            ss58_format,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Metadata {
    pub active_era_index: u32,
    pub active_era_total_stake: u128,
    pub current_session_index: u32,
    pub blocks_interval: Option<(u64, u64)>,
    pub interval: Option<((u32, u32), (u32, u32))>,
}

#[derive(Debug, Clone)]
pub struct RawData {
    pub network: Network,
    pub meta: Metadata,
    pub validators: Validators,
    pub records_total_full_epochs: u32,
}

#[derive(Debug, Clone)]
pub struct RawDataRank {
    pub network: Network,
    pub meta: Metadata,
    pub report_type: ReportType,
    pub validators: Validators,
    pub records_total_full_epochs: u32,
}

#[derive(Debug)]
pub struct RawDataPara {
    pub network: Network,
    pub meta: Metadata,
    pub report_type: ReportType,
    pub is_first_record: bool,
    pub validator: Validator,
    pub peers: Vec<(String, AuthorityRecord, ParaRecord)>,
    pub authority_record: Option<AuthorityRecord>,
    pub para_record: Option<ParaRecord>,
    pub parachains: Vec<ParaId>,
    pub para_validator_rank: Option<(usize, usize)>, // Option<(rank, total)>
    pub group_rank: Option<(usize, usize)>,          // Option<(rank, total)>
}

#[derive(Debug)]
pub struct RawDataGroup {
    pub network: Network,
    pub meta: Metadata,
    pub report_type: ReportType,
    pub is_first_record: bool,
    pub groups: Vec<(u32, Vec<(AuthorityRecord, ParaRecord, String)>)>,
}

#[derive(Debug)]
pub struct RawDataParachains {
    pub network: Network,
    pub meta: Metadata,
    pub report_type: ReportType,
    pub is_first_record: bool,
    pub parachains: Vec<(ParaId, ParaStats)>,
}

#[derive(Debug)]
pub struct RawDataPools {
    pub network: Network,
    pub meta: Metadata,
    pub report_type: ReportType,
    pub onet_pools: Vec<(u32, String, f64)>,
    pub pools_avg_apr: f64,
}

type Body = Vec<String>;

pub struct Report {
    body: Body,
}

impl Report {
    pub fn new() -> Report {
        Report { body: Vec::new() }
    }

    pub fn add_raw_text(&mut self, t: String) {
        self.body.push(t);
    }

    // pub fn add_text(&mut self, t: String) {
    //     if !self.is_short {
    //         self.add_raw_text(t);
    //     }
    // }

    pub fn add_break(&mut self) {
        self.add_raw_text("".into());
    }

    pub fn message(&self) -> String {
        self.body.join("\n")
    }

    pub fn formatted_message(&self) -> String {
        self.body.join("<br>")
    }

    pub fn save(&self, filename: &str) -> Result<(), OnetError> {
        let config = CONFIG.clone();
        let filename = format!("{}{}", config.data_path, filename.to_string());
        let path = Path::new(&filename);
        let file = File::create(&path)?;
        if path.extension() == Some(OsStr::new("gz")) {
            let mut buf = BufWriter::with_capacity(
                128 * 1024,
                write::GzEncoder::new(file, Compression::default()),
            );
            buf.write_all(self.message().as_bytes())?;
        } else {
            let mut buf = BufWriter::with_capacity(128 * 1024, file);
            buf.write_all(self.message().as_bytes())?;
        };

        Ok(())
    }

    pub fn log(&self) {
        info!("__START__");
        for t in &self.body {
            info!("{}", t);
        }
        info!("__END__");
    }
}

pub trait Callout<T>: Sized {
    fn callout(_: T) -> Self;
}

impl From<RawDataRank> for Report {
    /// Converts a ONE-T `RawDataRank` into a [`Report`].
    fn from(data: RawDataRank) -> Report {
        let mut report = Report::new();

        let mut validators = data
            .validators
            .iter()
            .filter(|v| v.para_epochs >= 1 && v.missed_ratio.is_some())
            .collect::<Vec<&Validator>>();

        // Sort by Score in descending
        validators.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        // Report title
        if let Some((start, end)) = data.meta.interval {
            // ONE-T Validator Performance Insights for Kusama from 3659 // 21251 to 3662 // 21266
            report.add_raw_text(format!(
                "\t📮 {} for {} from {} // {} to {} // {}",
                data.report_type.name(),
                data.network.name,
                start.0,
                start.1,
                end.0,
                end.1
            ));
        }

        if let Some(blocks_interval) = data.meta.blocks_interval {
            report.add_raw_text(format!(
                "\t{} blocks recorded from #{} to #{}",
                blocks_interval.1 - blocks_interval.0,
                blocks_interval.0,
                blocks_interval.1
            ));
        }
        report.add_break();

        report.add_raw_text(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            "#",
            "Validator",
            "Stash",
            "Subset",
            "Active Sessions",
            "P/V Sessions",
            "❒",
            "↻",
            "✓i",
            "✓e",
            "✗",
            "Grade",
            "MVR",
            "Avg. PPTS",
            "Score",
            "Commission (%)",
            "Commission Score",
            "Timeline"
        ));

        for (i, validator) in validators.iter().enumerate() {
            if let Some(mvr) = validator.missed_ratio {
                report.add_raw_text(format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    i + 1,
                    replace_crln(&validator.name, ""),
                    validator.stash,
                    validator.subset.to_string(),
                    validator.active_epochs,
                    validator.para_epochs,
                    validator.authored_blocks,
                    validator.core_assignments,
                    validator.implicit_votes,
                    validator.explicit_votes,
                    validator.missed_votes,
                    grade(1.0_f64 - mvr),
                    (mvr * 10000.0).round() / 10000.0,
                    validator.avg_para_points,
                    (validator.score * 10000.0).round() / 10000.0,
                    (validator.commission * 10000.0).round() / 100.0,
                    (validator.commission_score * 10000.0).round() / 10000.0,
                    validator
                        .pattern
                        .iter()
                        .map(|g| g.to_string())
                        .collect::<String>()
                ));
            } else {
                report.add_raw_text(format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    i + 1,
                    validator.name,
                    validator.stash,
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                ));
            }
        }

        report.add_break();
        report.add_break();
        report.add_break();
        report.add_raw_text("\t——".into());
        report.add_raw_text(format!(
            "\t{} v{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ));

        report.add_break();

        // Log report
        report.log();

        report
    }
}

impl From<RawDataGroup> for Report {
    /// Converts a ONE-T `RawData` into a [`Report`].
    fn from(data: RawDataGroup) -> Report {
        let mut report = Report::new();

        // Skip the full report if it's the initial record since the epoch is not fully recorded
        if data.is_first_record {
            report.add_raw_text(format!(
                "💤 Skipping {} for {} // {} // {} due to epoch not being fully recorded.",
                data.report_type.name(),
                data.network.name,
                data.meta.active_era_index,
                data.meta.current_session_index
            ));
            // Log report
            report.log();

            return report;
        }

        // Network info
        report.add_break();
        report.add_raw_text(format!(
            "📮 {} → <b>{} // {} // {}</b>",
            data.report_type.name(),
            data.network.name,
            data.meta.active_era_index,
            data.meta.current_session_index
        ));
        if let Some(blocks_interval) = data.meta.blocks_interval {
            report.add_raw_text(format!(
                "<i>{} blocks recorded from #{} to #{}</i>",
                blocks_interval.1 - blocks_interval.0,
                blocks_interval.0,
                blocks_interval.1
            ));
        }
        report.add_break();

        // Groups info
        let mut clode_block = String::from("<pre><code>");

        for (i, group) in data.groups.iter().enumerate() {
            clode_block.push_str(&format!(
                "{:<24}{:>4}{:>5}{:>5}{:>5}{:>5}{:>5}{:>8}{:>6}{:>6}\n",
                format!("{}. VAL_GROUP_{}", i + 1, group.0),
                "❒",
                "↻",
                "✓i",
                "✓e",
                "✗",
                "GRD",
                "MVR",
                "PPTS",
                "TPTS",
            ));
            for (authority_record, para_record, val_name) in group.1.iter() {
                if let Some(mvr) = para_record.missed_votes_ratio() {
                    clode_block.push_str(&format!(
                        "{:<24}{:>4}{:>5}{:>5}{:>5}{:>5}{:>5}{:>8}{:>6}{:>6}\n",
                        slice(&replace_emoji(&val_name, "_"), 24),
                        authority_record.total_authored_blocks(),
                        para_record.total_core_assignments(),
                        para_record.total_implicit_votes(),
                        para_record.total_explicit_votes(),
                        para_record.total_missed_votes(),
                        grade(1.0_f64 - mvr),
                        (mvr * 10000.0).round() / 10000.0,
                        authority_record.para_points(),
                        authority_record.points(),
                    ));
                } else {
                    clode_block.push_str(&format!(
                        "{:<24}{:>4}{:>5}{:>5}{:>5}{:>5}{:>5}{:>8}{:>6}{:>6}\n",
                        slice(&replace_emoji(&val_name, "_"), 24),
                        "-",
                        "-",
                        "-",
                        "-",
                        "-",
                        "-",
                        "-",
                        "-",
                        "-"
                    ));
                }
            }
            clode_block.push_str("\n");
        }

        clode_block.push_str("\n</code></pre>");
        report.add_raw_text(clode_block);

        report.add_raw_text("——".into());
        report.add_raw_text(format!(
            "<code>{} v{}</code>",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ));

        report.add_break();

        // Log report
        report.log();

        report
    }
}

impl From<RawDataParachains> for Report {
    /// Converts a ONE-T `RawData` into a [`Report`].
    fn from(data: RawDataParachains) -> Report {
        let mut report = Report::new();

        // Skip the full report if it's the initial record since the epoch is not fully recorded
        if data.is_first_record {
            report.add_raw_text(format!(
                "💤 Skipping {} for {} // {} // {} due to epoch not being fully recorded.",
                data.report_type.name(),
                data.network.name,
                data.meta.active_era_index,
                data.meta.current_session_index
            ));
            // Log report
            report.log();

            return report;
        }

        // Network info
        report.add_break();
        report.add_raw_text(format!(
            "📮 {} → <b>{} // {} // {}</b>",
            data.report_type.name(),
            data.network.name,
            data.meta.active_era_index,
            data.meta.current_session_index
        ));
        if let Some(blocks_interval) = data.meta.blocks_interval {
            report.add_raw_text(format!(
                "<i>{} blocks recorded from #{} to #{}</i>",
                blocks_interval.1 - blocks_interval.0,
                blocks_interval.0,
                blocks_interval.1
            ));
        }
        report.add_break();

        // Parachains info
        let mut clode_block = String::from("<pre><code>");

        clode_block.push_str(&format!(
            "{:<5}{:<10}{:>4}{:>6}{:>6}{:>6}{:>6}{:>8}{:>8}\n",
            "", "PARACHAIN", "❒", "↻", "✓i", "✓e", "✗", "PPTS", "TPTS"
        ));

        for (i, (para_id, stats)) in data.parachains.iter().enumerate() {
            clode_block.push_str(&format!(
                "{:<5}{:<10}{:>4}{:>6}{:>6}{:>6}{:>6}{:>8}{:>8}\n",
                format!("{}.", i + 1),
                para_id,
                stats.authored_blocks(),
                stats.core_assignments() / 5,
                stats.implicit_votes(),
                stats.explicit_votes(),
                stats.missed_votes(),
                stats.para_points(),
                stats.points()
            ));
        }
        clode_block.push_str("\n</code></pre>");
        report.add_raw_text(clode_block);

        report.add_raw_text("——".into());
        report.add_raw_text(format!(
            "<code>{} v{}</code>",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ));
        report.add_break();

        // Log report
        report.log();

        report
    }
}

impl From<RawDataPara> for Report {
    /// Converts a ONE-T `RawData` into a [`Report`].
    fn from(data: RawDataPara) -> Report {
        let mut report = Report::new();

        // Skip the full report if it's the initial record since the epoch is not fully recorded
        if data.is_first_record {
            report.add_raw_text(format!(
                "💤 Skipping {} for {} // {} // {} due to epoch not being fully recorded.",
                data.report_type.name(),
                data.network.name,
                data.meta.active_era_index,
                data.meta.current_session_index
            ));
            // Log report
            report.log();

            return report;
        }

        // Network info
        report.add_break();
        report.add_raw_text(format!(
            "📮 {} → <b>{} // {} // {}</b>",
            data.report_type.name(),
            data.network.name,
            data.meta.active_era_index,
            data.meta.current_session_index
        ));
        if let Some(blocks_interval) = data.meta.blocks_interval {
            report.add_raw_text(format!(
                "<i>{} blocks recorded from #{} to #{}</i>",
                blocks_interval.1 - blocks_interval.0,
                blocks_interval.0,
                blocks_interval.1
            ));
        }
        report.add_break();

        // Validator info
        // --- Specific parachains report here [START] -->
        if let Some(authority_record) = data.authority_record {
            if let Some(authority_index) = authority_record.authority_index() {
                report.add_raw_text(format!(
                    "<b><a href=\"https://{}.subscan.io/validator/{}\">{}</a></b>",
                    data.network.name.to_lowercase(),
                    data.validator.stash,
                    data.validator.name
                ));

                if let Some(para_record) = data.para_record {
                    // Find position rank
                    let mut v = Vec::<(AuthorityIndex, Points)>::new();

                    v.push((authority_index, authority_record.points()));
                    for peer in data.peers.iter() {
                        if let Some(peer_authority_index) = peer.1.authority_index() {
                            v.push((peer_authority_index, peer.1.points()));
                        }
                    }

                    // Print Grade
                    if let Some(mvr) = para_record.missed_votes_ratio() {
                        report.add_raw_text(format!(
                            "🎓 Session {} Grade: <b>{}</b>",
                            data.meta.current_session_index,
                            grade(1.0_f64 - mvr)
                        ));
                    }
                    report.add_break();
                    // Print Rankings
                    report.add_raw_text(format!("<i>Rankings</i>"));
                    if let Some((para_validator_rank, total)) = data.para_validator_rank {
                        report.add_raw_text(format!(
                            "✨ All Stars: {} // {} {}",
                            para_validator_rank + 1,
                            total,
                            position_emoji(para_validator_rank)
                        ));
                    }
                    if let Some((group_rank, total)) = data.group_rank {
                        report.add_raw_text(format!(
                            "🏀 Groups: {} // {} {}",
                            group_rank + 1,
                            total,
                            position_emoji(group_rank)
                        ));
                    }

                    let para_validator_group_rank =
                        position(authority_index, group_by_points(v.clone()));

                    let emoji = if authority_record.is_flagged() {
                        Random::HealthCheck
                    } else {
                        position_emoji(para_validator_group_rank.unwrap_or_default())
                    };
                    report.add_raw_text(format!(
                        "⛹️ Sole: {} // {} {}",
                        para_validator_group_rank.unwrap_or_default() + 1,
                        v.iter().count(),
                        emoji
                    ));

                    report.add_break();

                    // Print breakdown points
                    let mut clode_block = String::from("<pre><code>");

                    // val. group validator names
                    clode_block.push_str(&format!(
                        "{:<3}{:<24}{:>4}{:>4}{:>4}{:>4}{:>4}{:>4}{:>8}{:>6}{:>6}\n",
                        "#",
                        format!("VAL_GROUP_{}", para_record.group().unwrap_or_default()),
                        "❒",
                        "↻",
                        "✓i",
                        "✓e",
                        "✗",
                        "GRD",
                        "MVR",
                        "PPTS",
                        "TPTS",
                    ));

                    if let Some(mvr) = para_record.missed_votes_ratio() {
                        clode_block.push_str(&format!(
                            "{:<3}{:<24}{:>4}{:>4}{:>4}{:>4}{:>4}{:>4}{:>8}{:>6}{:>6}\n",
                            "*",
                            slice(&replace_emoji(&data.validator.name, "_"), 24),
                            authority_record.total_authored_blocks(),
                            para_record.total_core_assignments(),
                            para_record.total_implicit_votes(),
                            para_record.total_explicit_votes(),
                            para_record.total_missed_votes(),
                            grade(1.0_f64 - mvr),
                            (mvr * 10000.0).round() / 10000.0,
                            authority_record.para_points(),
                            authority_record.points(),
                        ));
                    } else {
                        clode_block.push_str(&format!(
                            "{:<3}{:<24}{:>4}{:>4}{:>4}{:>4}{:>4}{:>4}{:>8}{:>6}{:>6}\n",
                            "*",
                            slice(&replace_emoji(&data.validator.name, "_"), 24),
                            "-",
                            "-",
                            "-",
                            "-",
                            "-",
                            "-",
                            "-",
                            "-",
                            "-"
                        ));
                    }
                    // Print out peers names
                    let peers_letters = vec!["A", "B", "C", "D", "E", "F", "G", "H"];
                    for (i, peer) in data.peers.iter().enumerate() {
                        if let Some(mvr) = peer.2.missed_votes_ratio() {
                            clode_block.push_str(&format!(
                                "{:<3}{:<24}{:>4}{:>4}{:>4}{:>4}{:>4}{:>4}{:>8}{:>6}{:>6}\n",
                                peers_letters[i],
                                slice(&replace_emoji(&peer.0.clone(), "_"), 24),
                                peer.1.total_authored_blocks(),
                                peer.2.total_core_assignments(),
                                peer.2.total_implicit_votes(),
                                peer.2.total_explicit_votes(),
                                peer.2.total_missed_votes(),
                                grade(1.0_f64 - mvr),
                                (mvr * 10000.0).round() / 10000.0,
                                peer.1.para_points(),
                                peer.1.points()
                            ));
                        } else {
                            clode_block.push_str(&format!(
                                "{:<3}{:<24}{:>4}{:>4}{:>4}{:>4}{:>4}{:>4}{:>8}{:>6}{:>6}\n",
                                peers_letters[i],
                                slice(&replace_emoji(&peer.0.clone(), "_"), 24),
                                "-",
                                "-",
                                "-",
                                "-",
                                "-",
                                "-",
                                "-",
                                "-",
                                "-"
                            ));
                        }
                    }

                    // NOTE: By default print the full report
                    match data.report_type {
                        ReportType::Validator(param) => match param {
                            None => {
                                // default print the full report
                                // Print out parachains breakdown
                                clode_block.push_str("\nPARACHAINS BREAKDOWN\n");
                                // Print title line based on the number of peers
                                let mut line = String::from("            ┌──── * ────┐");
                                for (i, _) in data.peers.iter().enumerate() {
                                    line.push_str(&format!(
                                        "{:>13}",
                                        format!("┌──── {} ────┐", peers_letters[i])
                                    ));
                                }
                                clode_block.push_str(&format!("{line}\n"));

                                // Print subtitle line based on the number of peers
                                let mut line: String = format!(
                                    "{:<6}{:^3}{:^3}{:>4}{:>4}{:>5}",
                                    "#", "❒", "↻", "✓", "✗", "p"
                                );
                                for _ in data.peers.iter() {
                                    line.push_str(&format!("{:>4}{:>4}{:>5}", "✓", "✗", "p"));
                                }
                                clode_block.push_str(&format!("{line}\n"));

                                // Print parachains data
                                for para_id in data.parachains.iter() {
                                    // Print out votes per para id
                                    if let Some(stats) = para_record.get_para_id_stats(*para_id) {
                                        let mut line: String = format!(
                                            "{:<6}{:^3}{:^3}{:>4}{:>4}{:>5}",
                                            para_id,
                                            stats.authored_blocks(),
                                            stats.core_assignments(),
                                            stats.total_votes(),
                                            stats.missed_votes(),
                                            stats.para_points(),
                                        );
                                        for peer in data.peers.iter() {
                                            if let Some(peer_stats) =
                                                peer.2.get_para_id_stats(*para_id)
                                            {
                                                line.push_str(&format!(
                                                    "{:>4}{:>4}{:>5}",
                                                    peer_stats.total_votes(),
                                                    peer_stats.missed_votes(),
                                                    peer_stats.para_points()
                                                ));
                                            }
                                        }
                                        clode_block.push_str(&format!("{line}\n"));
                                    }
                                }
                            }
                            Some(_) => {
                                // Note: in the current version there is only one value possible 'short' -> do nothing here
                            }
                        },
                        _ => unreachable!(),
                    }
                    clode_block.push_str("\n</code></pre>");
                    report.add_raw_text(clode_block);
                }
            }
        } else {
            report.add_raw_text(format!(
                "🔴 <b><a href=\"https://{}.subscan.io/validator/{}\">{}</a></b>",
                data.network.name.to_lowercase(),
                data.validator.stash,
                data.validator.name
            ));
        }
        // --- Specific parachains report here [END] ---|

        report.add_raw_text("——".into());
        report.add_raw_text(format!(
            "<code>{} v{}</code>",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ));
        report.add_break();

        // Log report
        report.log();

        report
    }
}

impl From<RawData> for Report {
    /// Converts a ONE-T `RawData` into a [`Report`].
    fn from(data: RawData) -> Report {
        let mut report = Report::new();

        // Network info
        report.add_break();
        report.add_raw_text(format!(
            "📒 Network Report → <b>{} // {}</b>",
            data.network.name, data.meta.active_era_index,
        ));
        report.add_raw_text(format!(
            "<i>Valid <a href=\"https://wiki.polkadot.network/docs/thousand-validators\">TVP validators</a> are shown in bold (100% Commission • Others • <b>TVP</b>).</i>",
        ));

        // report.add_raw_text(format!(
        //     "<i>e.g. The first position is always related to the sub set of 100% commission validators, followed by the stat of the sub set of validators not included in the Thousand Validator Programme (non-tvp) and next in bold is the stat of the sub set of validators that participate in the TVP.</i>",
        // ));
        // --- Specific report sections here [START] -->

        total_validators_report(&mut report, &data);
        active_validators_report(&mut report, &data, false);
        own_stake_validators_report(&mut report, &data);
        oversubscribed_validators_report(&mut report, &data);
        inclusion_validators_report(&mut report, &data);
        avg_points_collected_report(&mut report, &data);
        flagged_and_exceptional_validators_report(&mut report, &data, false);
        top_performers_report(&mut report, &data, false);

        // --- Specific report sections here [END] ---|

        report.add_raw_text("——".into());
        report.add_raw_text(format!(
            "<code>{} v{}</code>",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ));
        report.add_break();

        // Log report
        report.log();

        report
    }
}

impl From<RawDataPools> for Report {
    /// Converts a ONE-T `RawData` into a [`Report`].
    fn from(data: RawDataPools) -> Report {
        // let config = CONFIG.clone();
        let mut report = Report::new();

        // --- Specific report here [START] -->

        // Network info
        report.add_break();
        report.add_raw_text(format!(
            "🎱 Nomination Pools Report → <b>{} // {}</b>",
            data.network.name, data.meta.active_era_index,
        ));
        report.add_raw_text(format!(
            "<i>At the present era the average APR¹ from all nomination pools is {:.2}%</i>",
            ((data.pools_avg_apr * 10000.0).round() / 10000.0) * 100.0,
        ));
        report.add_break();

        // Calculate onet pools average APR
        let total = data.onet_pools.iter().count();
        let aprs: Vec<f64> = data
            .onet_pools
            .iter()
            .map(|(_, _, apr)| apr.clone())
            .collect();
        let onet_pools_avg_apr = aprs.iter().sum::<f64>() / total as f64;

        report.add_raw_text(format!(
            "For the current set of nominees, ONE-T Nomination pools, present {:.2}% APR:",
            ((onet_pools_avg_apr * 10000.0).round() / 10000.0) * 100.0,
        ));
        for (pool_id, pool_metadata, pool_apr) in data.onet_pools.iter() {
            report.add_raw_text(format!(
                "‣ {} (Pool {}): <b>{} {:.2}% APR</b>",
                pool_metadata,
                pool_id,
                trend(*pool_apr, data.pools_avg_apr),
                ((pool_apr * 10000.0).round() / 10000.0) * 100.0,
            ));
        }

        report.add_break();
        // report.add_raw_text(format!(
        //     "<i>¹ Nomination pool APR is based on the average APR of all the pool nominees from the last {} eras, minus the respective validators commission.</i>",
        //     config.maximum_history_eras,
        // ));
        report.add_raw_text(format!(
            "<i>¹ Nomination pool APR is based on the average APR of all the pool nominees from the last 84 eras, minus the respective validators commission.</i>",
        ));

        report.add_break();
        report.add_raw_text(format!(
            "➕ Join ONE-T Nomination Pools here → <a href=\"https://one-t.turboflakes.io\">one-t.turboflakes.io</a>",
        ));

        // --- Specific report sections here [END] ---|
        report.add_break();
        report.add_raw_text("——".into());
        report.add_raw_text(format!(
            "<code>{} v{}</code>",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ));
        report.add_break();

        // Log report
        report.log();

        report
    }
}

impl Callout<RawData> for Report {
    fn callout(data: RawData) -> Report {
        let config = CONFIG.clone();
        let mut report = Report::new();

        report.add_raw_text(format!(
            "📣 <b>{} // {}</b>",
            data.network.name, data.meta.active_era_index,
        ));

        active_validators_report(&mut report, &data, true);

        flagged_and_exceptional_validators_report(&mut report, &data, true);

        top_performers_report(&mut report, &data, true);

        report.add_raw_text(format!(
            "<i>Lookout and !subscribe for validator reports here</i> → #{} 👀",
            config.matrix_public_room
        ));

        // Log report
        report.log();

        report
    }
}

fn descnd(n: usize, d: usize) -> String {
    if d > 0 {
        format!("{} ({:.2}%)", n, (n as f64 / d as f64) * 100.0)
    } else {
        "-".to_string()
    }
}

fn total_validators_report<'a>(report: &'a mut Report, data: &'a RawData) -> &'a Report {
    report.add_break();

    let total = data.validators.len();
    let total_tvp = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::TVP)
        .count();
    let total_non_tvp = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP)
        .count();
    let total_c100 = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::C100)
        .count();

    report.add_raw_text(format!("{} total {} validators:", total, data.network.name,));
    report.add_raw_text(format!(
        "‣ {} • {} • <b>{}</b>",
        descnd(total_c100, total),
        descnd(total_non_tvp, total),
        descnd(total_tvp, total),
    ));
    report.add_break();

    report
}

fn active_validators_report<'a>(
    report: &'a mut Report,
    data: &'a RawData,
    is_verbose: bool,
) -> &'a Report {
    let total_active = data.validators.iter().filter(|v| v.is_active).count();

    let total_tvp = data
        .validators
        .iter()
        .filter(|v| v.is_active && v.subset == Subset::TVP)
        .count();
    let total_non_tvp = data
        .validators
        .iter()
        .filter(|v| v.is_active && v.subset == Subset::NONTVP)
        .count();
    let total_c100 = data
        .validators
        .iter()
        .filter(|v| v.is_active && v.subset == Subset::C100)
        .count();

    if is_verbose {
        report.add_raw_text(format!(
            "For era {} there are {} active validators:",
            data.meta.active_era_index, total_active,
        ));
        report.add_raw_text(format!(
            "‣ {} are 100% commission validators, {} are valid <a href=\"https://wiki.polkadot.network/docs/thousand-validators\">TVP validators</a> and the remainder {} other validators.",
            descnd(total_c100, total_active),
            descnd(total_tvp, total_active),
            descnd(total_non_tvp, total_active),
        ));
    } else {
        report.add_raw_text(format!("{} active validators:", total_active));
        report.add_raw_text(format!(
            "‣ {} • {} • <b>{}</b>",
            descnd(total_c100, total_active),
            descnd(total_non_tvp, total_active),
            descnd(total_tvp, total_active),
        ));
    }
    report.add_break();

    report
}

fn own_stake_validators_report<'a>(report: &'a mut Report, data: &'a RawData) -> &'a Report {
    let total = data.meta.active_era_total_stake;

    let tvp: Vec<u128> = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::TVP)
        .map(|v| v.own_stake)
        .collect();

    let non_tvp: Vec<u128> = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP)
        .map(|v| v.own_stake)
        .collect();

    let c100: Vec<u128> = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::C100)
        .map(|v| v.own_stake)
        .collect();

    fn desc(v: Vec<u128>, decimals: u128) -> String {
        if v.len() > 0 {
            let avg = v.iter().sum::<u128>() / v.len() as u128;
            let min = *v.iter().min().unwrap_or_else(|| &0);
            let max = *v.iter().max().unwrap_or_else(|| &0);

            format!(
                "{} ({:.2}, {:.0})",
                avg / decimals,
                min as f64 / decimals as f64,
                max as f64 / decimals as f64
            )
        } else {
            "-".to_string()
        }
    }

    report.add_raw_text(format!(
        "Average (Min, Max) validator self stake in {}:",
        data.network.token_symbol,
    ));
    report.add_raw_text(format!(
        "‣ {} • {} • <b>{}</b>",
        desc(c100.clone(), 10u128.pow(data.network.token_decimals as u32)),
        desc(
            non_tvp.clone(),
            10u128.pow(data.network.token_decimals as u32)
        ),
        desc(tvp.clone(), 10u128.pow(data.network.token_decimals as u32)),
    ));
    report.add_break();

    report.add_raw_text(format!(
        "Validator self stake contributions for network security:"
    ));
    if total > 0 {
        report.add_raw_text(format!(
            "‣ {:.2}% • {:.2}% • <b>{:.2}%</b>",
            (c100.iter().sum::<u128>() as f64 / total as f64) * 100.0,
            (non_tvp.iter().sum::<u128>() as f64 / total as f64) * 100.0,
            (tvp.iter().sum::<u128>() as f64 / total as f64) * 100.0,
        ));
    }
    report.add_break();

    report
}

fn oversubscribed_validators_report<'a>(report: &'a mut Report, data: &'a RawData) -> &'a Report {
    let total = data.validators.len();

    let total_over = data
        .validators
        .iter()
        .filter(|v| v.is_oversubscribed)
        .count();

    if total_over == 0 {
        return report;
    }

    let total_tvp = data
        .validators
        .iter()
        .filter(|v| v.is_oversubscribed && v.subset == Subset::TVP)
        .count();
    let total_non_tvp = data
        .validators
        .iter()
        .filter(|v| v.is_oversubscribed && v.subset == Subset::NONTVP)
        .count();
    let total_c100 = data
        .validators
        .iter()
        .filter(|v| v.is_oversubscribed && v.subset == Subset::C100)
        .count();

    report.add_raw_text(format!("Oversubscribed {}:", descnd(total_over, total)));
    report.add_raw_text(format!(
        "‣ {} • {} • <b>{}</b>",
        descnd(total_c100, total_over),
        descnd(total_non_tvp, total_over),
        descnd(total_tvp, total_over),
    ));
    report.add_break();

    report
}

fn avg_points_collected_report<'a>(report: &'a mut Report, data: &'a RawData) -> &'a Report {
    let config = CONFIG.clone();

    let total_eras_points: (u32, u32) = data
        .validators
        .iter()
        .map(|v| (v.maximum_history_total_eras, v.maximum_history_total_points))
        .reduce(|a, b| (a.0 + b.0, a.1 + b.1))
        .unwrap_or_default();

    let total_eras_points_tvp: (u32, u32) = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::TVP)
        .map(|v| (v.maximum_history_total_eras, v.maximum_history_total_points))
        .reduce(|a, b| (a.0 + b.0, a.1 + b.1))
        .unwrap_or_default();

    let total_eras_points_non_tvp: (u32, u32) = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP)
        .map(|v| (v.maximum_history_total_eras, v.maximum_history_total_points))
        .reduce(|a, b| (a.0 + b.0, a.1 + b.1))
        .unwrap_or_default();

    let total_eras_points_c100: (u32, u32) = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::C100)
        .map(|v| (v.maximum_history_total_eras, v.maximum_history_total_points))
        .reduce(|a, b| (a.0 + b.0, a.1 + b.1))
        .unwrap_or_default();

    report.add_raw_text(format!(
        "On average {} points per validator per era were collected in the last {} eras:",
        total_eras_points.1 / total_eras_points.0,
        config.maximum_history_eras,
    ));

    fn desc(subset: (u32, u32), total: (u32, u32)) -> String {
        if subset.0 > 0 && total.0 > 0 {
            format!(
                "{} {}",
                trend((subset.1 / subset.0).into(), (total.1 / total.0).into()),
                subset.1 / subset.0
            )
        } else {
            "-".to_string()
        }
    }

    report.add_raw_text(format!(
        "‣ {} • {} • <b>{}</b>",
        desc(total_eras_points_c100, total_eras_points),
        desc(total_eras_points_non_tvp, total_eras_points),
        desc(total_eras_points_tvp, total_eras_points),
    ));
    report.add_break();

    report
}

fn inclusion_validators_report<'a>(report: &'a mut Report, data: &'a RawData) -> &'a Report {
    let config = CONFIG.clone();

    let total_tvp = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::TVP)
        .count();

    let total_tvp_with_points = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::TVP && v.maximum_history_total_points != 0)
        .count();

    let total_non_tvp = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP)
        .count();

    let total_non_tvp_with_points = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP && v.maximum_history_total_points != 0)
        .count();

    let total_c100 = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::C100)
        .count();

    let total_c100_with_points = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::C100 && v.maximum_history_total_points != 0)
        .count();

    report.add_raw_text(format!(
        "Participation in the last {} eras:",
        config.maximum_history_eras,
    ));

    fn desc(n: usize, d: usize) -> String {
        if d > 0 {
            format!("{:.2}%", (n as f64 / d as f64) * 100.0)
        } else {
            "-".to_string()
        }
    }

    report.add_raw_text(format!(
        "‣ {} • {} • <b>{}</b>",
        desc(total_c100_with_points, total_c100),
        desc(total_non_tvp_with_points, total_non_tvp),
        desc(total_tvp_with_points, total_tvp),
    ));
    report.add_break();

    report
}

fn flagged_and_exceptional_validators_report<'a>(
    report: &'a mut Report,
    data: &'a RawData,
    is_short: bool,
) -> &'a Report {
    let para_validators = data
        .validators
        .iter()
        .filter(|v| v.para_epochs >= 2 && v.missed_ratio.is_some())
        .collect::<Vec<&Validator>>();

    let total_tvp = para_validators
        .iter()
        .filter(|v| v.subset == Subset::TVP)
        .count();
    let total_tvp_exceptional = para_validators
        .iter()
        .filter(|v| v.subset == Subset::TVP && grade(1.0 - v.missed_ratio.unwrap()) == "A+")
        .count();
    let total_tvp_flagged = para_validators
        .iter()
        .filter(|v| v.subset == Subset::TVP && grade(1.0 - v.missed_ratio.unwrap()) == "F")
        .count();

    let total_non_tvp = para_validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP)
        .count();
    let total_non_tvp_exceptional = para_validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP && grade(1.0 - v.missed_ratio.unwrap()) == "A+")
        .count();
    let total_non_tvp_flagged = para_validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP && grade(1.0 - v.missed_ratio.unwrap()) == "F")
        .count();

    let total_c100 = para_validators
        .iter()
        .filter(|v| v.subset == Subset::C100)
        .count();
    let total_c100_exceptional = para_validators
        .iter()
        .filter(|v| v.subset == Subset::C100 && grade(1.0 - v.missed_ratio.unwrap()) == "A+")
        .count();
    let total_c100_flagged = para_validators
        .iter()
        .filter(|v| v.subset == Subset::C100 && grade(1.0 - v.missed_ratio.unwrap()) == "F")
        .count();

    let total_flagged = total_c100_flagged + total_non_tvp_flagged + total_tvp_flagged;
    let total_exceptional =
        total_c100_exceptional + total_non_tvp_exceptional + total_tvp_exceptional;

    let mvr_exceptional: Vec<f64> = para_validators
        .iter()
        .filter(|v| grade(1.0 - v.missed_ratio.unwrap()) == "A+")
        .map(|v| v.missed_ratio.unwrap())
        .collect();

    let mvr_flagged: Vec<f64> = para_validators
        .iter()
        .filter(|v| grade(1.0 - v.missed_ratio.unwrap()) == "F")
        .map(|v| v.missed_ratio.unwrap())
        .collect();

    if para_validators.len() > 0 {
        // set a warning flag
        let warning = if (total_flagged as f64 / para_validators.len() as f64) > 0.20 {
            "⚠️ "
        } else {
            ""
        };

        let avg_mvr_exceptional: String = if mvr_exceptional.len() > 0 {
            format!(
                "{}",
                ((mvr_exceptional.iter().sum::<f64>() / mvr_exceptional.len() as f64) * 10000.0)
                    .round()
                    / 10000.0
            )
        } else {
            "-".to_string()
        };

        let avg_mvr_flagged: String = if mvr_flagged.len() > 0 {
            format!(
                "{}",
                ((mvr_flagged.iter().sum::<f64>() / mvr_flagged.len() as f64) * 10000.0).round()
                    / 10000.0
            )
        } else {
            "-".to_string()
        };

        report.add_raw_text(format!(
            "In the last {} sessions {} validators were selected to para-validate:",
            data.records_total_full_epochs,
            para_validators.len()
        ));

        if total_exceptional > 0 {
            report.add_raw_text(format!(
                    "‣ {} consistently had an exceptional performance (A+) with an average missed vote ratio of {}.",
                    descnd(total_exceptional, para_validators.len()),
                    avg_mvr_exceptional
                ));
            // Show subsets
            if !is_short {
                report.add_raw_text(format!(
                    "‣‣ {} • {} • <b>{}</b>",
                    descnd(total_c100_exceptional, total_c100),
                    descnd(total_non_tvp_exceptional, total_non_tvp),
                    descnd(total_tvp_exceptional, total_tvp),
                ));
            }
        }

        if total_flagged > 0 {
            report.add_raw_text(format!(
                    "‣ {}{} consistently had a low performance (F) with an average missed vote ratio of {}.",
                    warning,
                    descnd(total_flagged, para_validators.len()),
                    avg_mvr_flagged
                ));
            if !is_short {
                report.add_raw_text(format!(
                    "‣‣ {} • {} • <b>{}</b>",
                    descnd(total_c100_flagged, total_c100),
                    descnd(total_non_tvp_flagged, total_c100),
                    descnd(total_tvp_flagged, total_c100),
                ));
            }
        }

        // extremely low-performance
        let total_elp = para_validators
            .iter()
            .filter(|v| v.missed_ratio.unwrap() > 0.80_f64)
            .count();
        if total_elp > 0 {
            report.add_raw_text(format!("‣ 🚨 {} had a very low performance.", total_elp));
        }
    }

    report.add_break();

    report
}

#[allow(dead_code)]
fn top_validators_report<'a>(
    report: &'a mut Report,
    data: &'a RawData,
    is_short: bool,
) -> &'a Report {
    let config = CONFIG.clone();

    // Sort TVP by avg points for validators that had at least 1/3 of max eras
    let mut tvp_sorted = data
        .validators
        .iter()
        .filter(|v| {
            v.subset == Subset::TVP
                && v.maximum_history_total_eras >= config.maximum_history_eras / 2
        })
        .collect::<Vec<&Validator>>();

    tvp_sorted.sort_by(|a, b| {
        (b.maximum_history_total_points / b.maximum_history_total_eras)
            .cmp(&(&a.maximum_history_total_points / &a.maximum_history_total_eras))
    });

    let max: usize = if tvp_sorted.len() as u32 > config.maximum_top_ranking_callout && is_short {
        usize::try_from(config.maximum_top_ranking_callout).unwrap()
    } else if tvp_sorted.len() as u32 > config.maximum_top_ranking && !is_short {
        usize::try_from(config.maximum_top_ranking).unwrap()
    } else {
        tvp_sorted.len()
    };

    if max > 0 {
        if is_short {
            report.add_raw_text(format!("Top {} TVP Validators with most average points earned in the last {} eras (minimum inclusion {} eras).",
                max,
                config.maximum_history_eras,
                config.maximum_history_eras / 2));
        } else {
            report.add_raw_text(format!("🏆 <b>Top {} TVP Validators</b> with most average points earned in the last {} eras (minimum inclusion {} eras)", max, config.maximum_history_eras, config.maximum_history_eras / 2));
            report.add_raw_text(format!("<i>Legend: validator (avg. points)</i>"));
        }
        report.add_break();
        for v in &tvp_sorted[..max] {
            report.add_raw_text(format!(
                "* {} ({})",
                v.name,
                v.maximum_history_total_points / v.maximum_history_total_eras
            ));
        }
    }
    report.add_break();
    report
}

fn top_performers_report<'a>(
    report: &'a mut Report,
    data: &'a RawData,
    is_short: bool,
) -> &'a Report {
    // If no full sessions than just show rank based on avg. points
    if data.records_total_full_epochs == 0 {
        return top_validators_report(report, &data, is_short);
    }

    let config = CONFIG.clone();

    // Min para epochs to be considered in the rank:
    // min_para_epochs = 1 if total_full_epochs < 12;
    // min_para_epochs = 2 if total_full_epochs < 24;
    // min_para_epochs = 3 if total_full_epochs < 36;
    // min_para_epochs = 4 if total_full_epochs < 48;
    // min_para_epochs = 5 if total_full_epochs = 48;
    let min_para_epochs = (data.records_total_full_epochs / 12) + 1;

    // Filter TVP validators
    let mut validators = data
        .validators
        .iter()
        .filter(|v| {
            v.subset == Subset::TVP && v.para_epochs >= min_para_epochs && v.missed_ratio.is_some()
        })
        .collect::<Vec<&Validator>>();

    if validators.len() > 0 {
        // Sort by Score in descending
        validators.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        let max: usize = if validators.len() as u32 > config.maximum_top_ranking_callout && is_short
        {
            usize::try_from(config.maximum_top_ranking_callout).unwrap()
        } else if validators.len() as u32 > config.maximum_top_ranking && !is_short {
            usize::try_from(config.maximum_top_ranking).unwrap()
        } else {
            validators.len()
        };

        if max > 0 {
            if is_short {
                report.add_raw_text(format!(
                    "Top {} Best TVP Validators performances of the last {} sessions:",
                    max, data.records_total_full_epochs
                ));
            } else {
                report.add_raw_text(format!(
                    "🏆 <b>Top {} Best TVP Validators performances</b> of the last {} sessions:",
                    max, data.records_total_full_epochs
                ));
            }

            report.add_break();

            for v in &validators[..max] {
                report.add_raw_text(format!(
                    "* {} ({:.2}%, {}, {}, {}x)",
                    v.name,
                    v.score * 100.0,
                    (v.missed_ratio.unwrap() * 10000.0).round() / 10000.0,
                    v.avg_para_points,
                    v.para_epochs,
                ));
            }

            if !is_short {
                report.add_break();
                report.add_raw_text(format!("<i>Legend: Val. identity (Score, Missed votes ratio, Average p/v points, Number of sessions as p/v)</i>"));
                report.add_raw_text(format!("<i>Score: Backing votes ratio (1-MVR) make up 75% of the score, average p/v points make up 18% and number of sessions as p/v the remaining 7%</i>"));
                report.add_raw_text(format!(
                    "<i>Sorting: Validators are sorted by Score in descending order</i>"
                ));
                report.add_raw_text(format!("<i>Inclusion: To be considered for the ranking, validators must have been p/v for at least {} times in the last {} sessions.</i>", min_para_epochs, data.records_total_full_epochs));
            }
        }

        report.add_break();
    } else {
        top_validators_report(report, &data, is_short);
    }
    report
}

// DEPRECATED
// #[allow(dead_code)]
// fn low_performers_report<'a>(report: &'a mut Report, data: &'a RawData) -> &'a Report {
//     // Sort validators by missed ratio higher than 0.75 that were p/v at least 2 times in the last era
//     let mut tvp_sorted = data
//         .validators
//         .iter()
//         .filter(|v| {
//             v.flagged_epochs.len() >= 1
//                 && v.para_epochs.len() >= 2
//                 && v.missed_ratio.unwrap() > 0.75_f64
//                 && v.total_eras >= 1
//         })
//         .collect::<Vec<&Validator>>();

//     // Descending order
//     tvp_sorted.sort_by(|a, b| {
//         b.missed_ratio
//             .unwrap()
//             .partial_cmp(&a.missed_ratio.unwrap())
//             .unwrap()
//     });

//     if tvp_sorted.len() > 0 {
//         report.add_raw_text(format!("🚨 Validators that missed more than 75% of votes in the previous era when selected as para-validator for at least 2 epochs:"));
//         report.add_raw_text(format!("<i>legend: validator (avg. points, number of epochs selected as para-validator, missed votes percentage)</i>"));
//         report.add_break();
//         for v in tvp_sorted.iter() {
//             report.add_raw_text(format!(
//                 "* <del>{}</del> ({}, {}x, {:.2}%)",
//                 v.name,
//                 v.total_points / v.total_eras,
//                 v.para_epochs.len(),
//                 v.missed_ratio.unwrap() * 100.0,
//             ));
//         }

//         report.add_break();
//     }
//     report
// }

fn trend(a: f64, b: f64) -> String {
    if a > b {
        String::from("↑")
    } else if a < b {
        String::from("↓")
    } else {
        String::from("")
    }
}

pub fn replace_emoji(text: &str, replacer: &str) -> String {
    let r = Regex::new(concat!(
        "[",
        "\u{01F600}-\u{01F64F}",
        "\u{01F300}-\u{01F5FF}",
        "\u{01F680}-\u{01F6FF}",
        "\u{01F1E0}-\u{01F1FF}",
        "\u{002702}-\u{0027B0}",
        "\u{0024C2}-\u{01F251}",
        "\u{002500}-\u{002BEF}",
        "\u{01f926}-\u{01f937}",
        "\u{010000}-\u{10ffff}",
        "\u{2640}-\u{2642}",
        "\u{2600}-\u{2B55}",
        "\u{200d}",
        "\u{23cf}",
        "\u{23e9}",
        "\u{231a}",
        "\u{fe0f}",
        "\u{3030}",
        "\u{20e3}",
        "\u{0020}",
        "\u{000D}",
        "\u{000A}",
        "]+",
    ))
    .unwrap();

    r.replace_all(text, replacer).to_string()
}

#[allow(dead_code)]
pub fn replace_crln(text: &str, replacer: &str) -> String {
    let r = Regex::new(concat!("[", "\u{000D}", "\u{000A}", "]+",)).unwrap();

    r.replace_all(text, replacer).to_string()
}

pub fn group_by_points(v: Vec<(u32, u32)>) -> Vec<Vec<(u32, u32)>> {
    let mut sorted = v.clone();
    sorted.sort_by(|(_, a), (_, b)| b.cmp(a));

    let mut out: Vec<Vec<(u32, u32)>> = Vec::new();
    for (id, points) in sorted.into_iter() {
        if let Some(mut last) = out.pop() {
            if last[last.len() - 1].1 != points {
                out.push(last);
                out.push(vec![(id, points)]);
            } else {
                last.push((id, points));
                out.push(last);
            }
        } else {
            out.push(vec![(id, points)]);
        }
    }
    out
}

pub fn position(a: u32, v: Vec<Vec<(u32, u32)>>) -> Option<usize> {
    for (i, z) in v.into_iter().enumerate() {
        for (b, _) in z.into_iter() {
            if a == b {
                return Some(i);
            }
        }
    }
    None
}

fn position_emoji(r: usize) -> Random {
    match r {
        0 => Random::First,
        1 => Random::Second,
        2 => Random::Third,
        _ => Random::Other,
    }
}

enum Random {
    First,
    Second,
    Third,
    Other,
    HealthCheck,
}

impl std::fmt::Display for Random {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::First => {
                let v = vec!["😁", "😆", "🤯", "😝", "😜", "😎", "🤩", "🥳", "😏", "😬"];
                write!(f, "🥇 {} 🚀", v[random_index(v.len())])
            }
            Self::Second => {
                let v = vec!["😃", "😅", "😉", "😀", "😉"];
                write!(f, "🥈 {}", v[random_index(v.len())])
            }
            Self::Third => {
                let v = vec!["😊", "🙂", "🤔", "🙄", "🤨", "😐", "😑"];
                write!(f, "🥉 {}", v[random_index(v.len())])
            }
            Self::Other => {
                let v = vec!["😞", "😔", "😟", "😕", "🙁", "😣", "😖", "😢", "🥺"];
                write!(f, "{}", v[random_index(v.len())])
            }
            Self::HealthCheck => {
                let v = vec!["😫", "😩", "😭", "😤", "😡", "🤬", "😱", "😰"];
                write!(f, "{} 🩺 🚑", v[random_index(v.len())])
            }
        }
    }
}

fn random_index(len: usize) -> usize {
    let mut rng = rand::thread_rng();
    rng.gen_range(0..len - 1)
}

fn slice(name: &str, maximum_length: usize) -> String {
    let cut = if name.len() <= maximum_length {
        name.len()
    } else {
        maximum_length
    };
    String::from(&name[..cut])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_by_points() {
        let a = vec![(1, 10), (2, 10), (3, 10), (4, 10), (5, 10)];
        assert_eq!(
            group_by_points(a),
            vec![vec![(1, 10), (2, 10), (3, 10), (4, 10), (5, 10)]]
        );
        let a = vec![(1, 10), (2, 10), (3, 20), (4, 20), (5, 30)];
        assert_eq!(
            group_by_points(a),
            vec![
                vec![(5, 30)],
                vec![(3, 20), (4, 20)],
                vec![(1, 10), (2, 10)],
            ]
        );
        let a = vec![(3, 20), (4, 20), (1, 10), (25, 10), (15, 30)];
        assert_eq!(
            group_by_points(a),
            vec![
                vec![(15, 30)],
                vec![(3, 20), (4, 20)],
                vec![(1, 10), (25, 10)],
            ]
        );
    }

    #[test]
    fn test_rank() {
        let a = vec![(1, 10), (2, 10), (3, 20), (4, 20), (5, 30)];
        let groups = group_by_points(a);
        assert_eq!(position(3, groups), Some(1));
    }

    #[test]
    fn test_name() {
        let val_name = r"1️⃣ 1️⃣6️⃣1️⃣1️⃣6️⃣1️⃣1️⃣6️⃣1️⃣1️⃣6️⃣1️⃣1️⃣6️⃣1️⃣1️⃣6️⃣";
        assert_eq!(
            r"1_1_6_1_1_6_1_1_6_",
            slice(&replace_emoji(&val_name, "_"), 18)
        );
    }
}
