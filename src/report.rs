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
    AuthorityIndex, AuthorityRecord, EpochIndex, ParaId, ParaRecord, ParaStats, Pattern,
    Points,
};
use log::info;
use rand::Rng;
use regex::Regex;
use std::{convert::TryInto, result::Result};
use subxt::sp_runtime::AccountId32;
use subxt::{Client, DefaultConfig};

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
    pub own_stake: u128,
    pub total_points: u32,
    pub total_eras: u32,
    pub maximum_history_total_points: u32,
    pub maximum_history_total_eras: u32,
    pub total_authored_blocks: u32,
    pub active_last_era: bool,
    pub flagged_epochs: Vec<EpochIndex>,
    pub pattern: Pattern,
    pub authored_blocks: u32,
    pub epochs: u32,
    pub avg_points: u32,
    pub para_epochs: u32,
    pub avg_para_points: u32,
    pub explicit_votes: u32,
    pub implicit_votes: u32,
    pub missed_votes: u32,
    pub core_assignments: u32,
    pub missed_ratio: Option<f64>,
    pub last_missed_ratio: Option<f64>,
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
            own_stake: 0,
            total_points: 0,
            total_eras: 0,
            maximum_history_total_points: 0,
            maximum_history_total_eras: 0,
            total_authored_blocks: 0,
            active_last_era: false,
            flagged_epochs: Vec::new(),
            epochs: 0,
            avg_points: 0,
            para_epochs: 0,
            pattern: Vec::new(),
            authored_blocks: 0,
            avg_para_points: 0,
            explicit_votes: 0,
            implicit_votes: 0,
            missed_votes: 0,
            core_assignments: 0,
            missed_ratio: None,
            last_missed_ratio: None,
            warnings: Vec::new(),
        }
    }
}

pub type Validators = Vec<Validator>;

#[derive(Debug, Clone, PartialEq)]
pub enum Subset {
    TVP,
    NONTVP,
    C100,
}

impl std::fmt::Display for Subset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TVP => write!(f, "TVP"),
            Self::NONTVP => write!(f, "OTH"),
            Self::C100 => write!(f, "100"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Network {
    pub name: String,
    pub token_symbol: String,
    pub token_decimals: u8,
}

impl Network {
    pub async fn load(client: &Client<DefaultConfig>) -> Result<Network, OnetError> {
        let properties = client.properties();

        // Get Network name
        let chain_name = client.rpc().system_chain().await?;

        // Get Token symbol
        let token_symbol: String = if let Some(token_symbol) = properties.get("tokenSymbol") {
            token_symbol.as_str().unwrap_or_default().to_string()
        } else {
            "ND".to_string()
        };

        // Get Token decimals
        let token_decimals: u8 = if let Some(token_decimals) = properties.get("tokenDecimals") {
            token_decimals
                .as_u64()
                .unwrap_or_default()
                .try_into()
                .unwrap()
        } else {
            12
        };

        Ok(Network {
            name: chain_name,
            token_symbol,
            token_decimals,
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
    pub records_total_full_eras: u32,
}

#[derive(Debug, Clone)]
pub struct RawDataRank {
    pub network: Network,
    pub meta: Metadata,
    pub report_type: ReportType,
    pub validators: Validators,
    pub records_total_full_eras: u32,
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
    pub para_validator_rank: Option<usize>,
    pub group_rank: Option<usize>,
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

        // Filter validators that were assigned at least once as p/v
        let mut validators_sorted = data
            .validators
            .iter()
            .filter(|v| v.para_epochs >= 1 && v.missed_ratio.is_some())
            .collect::<Vec<&Validator>>();

        validators_sorted.sort_by(|a, b| {
            if a.avg_para_points == b.avg_para_points {
                if a.missed_ratio.unwrap() == b.missed_ratio.unwrap() {
                    // p/v times in descending order
                    b.para_epochs.partial_cmp(&a.para_epochs).unwrap()
                } else {
                    // missed ratio in ascending order
                    a.missed_ratio
                        .unwrap()
                        .partial_cmp(&b.missed_ratio.unwrap())
                        .unwrap()
                }
            } else {
                // session avg. points in descending order
                b.avg_para_points.partial_cmp(&a.avg_para_points).unwrap()
            }
        });

        report.add_raw_text(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            "#",
            "Validator",
            "Group",
            "Act Sessions",
            "P/V Sessions",
            "❒",
            "↻",
            "✓i",
            "✓e",
            "✗",
            "Grade",
            "Missed Votes Ratio",
            "Avg. P/V Points",
            "Avg. Total Points",
            "Pattern"
        ));

        for (i, validator) in validators_sorted.iter().enumerate() {
            if let Some(mvr) = validator.missed_ratio {
                report.add_raw_text(format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    i + 1,
                    validator.name,
                    validator.subset.to_string(),
                    validator.epochs,
                    validator.para_epochs,
                    validator.authored_blocks,
                    validator.core_assignments,
                    validator.implicit_votes,
                    validator.explicit_votes,
                    validator.missed_votes,
                    grade(1.0_f64 - mvr),
                    (mvr * 10000.0).round() / 10000.0,
                    validator.avg_para_points,
                    validator.avg_points,
                    validator
                        .pattern
                        .iter()
                        .map(|g| g.to_string())
                        .collect::<String>()
                ));
            } else {
                report.add_raw_text(format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    i + 1,
                    validator.name,
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
        if let Some((start, end)) = data.meta.interval {
            report.add_raw_text(format!(
                "\t📮 {} → {} // from {} // {} to {} // {}",
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
                "{:<24}{:>4}{:>4}{:>4}{:>4}{:>3}{:>8}{:>6}{:>4}{:>6}\n",
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
                    let total_implicit_votes = para_record.total_implicit_votes();
                    let total_explicit_votes = para_record.total_explicit_votes();
                    let para_points = (total_implicit_votes + total_explicit_votes) * 20;
                    let total_points = (authority_record.authored_blocks() * 20) + para_points;

                    clode_block.push_str(&format!(
                        "{:<24}{:>4}{:>4}{:>4}{:>4}{:>4}{:>8}{:>6}{:>4}{:>6}\n",
                        slice(&replace_emoji(&val_name, "_"), 24),
                        authority_record.authored_blocks(),
                        para_record.total_core_assignments(),
                        total_implicit_votes,
                        total_explicit_votes,
                        para_record.total_missed_votes(),
                        grade(1.0_f64 - mvr),
                        (mvr * 10000.0).round() / 10000.0,
                        para_points,
                        total_points,
                    ));
                } else {
                    clode_block.push_str(&format!(
                        "{:<24}{:>4}{:>4}{:>4}{:>4}{:>4}{:>8}{:>6}{:>4}{:>6}\n",
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
                stats.total_points()
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
            report.add_raw_text(format!(
                "<b><a href=\"https://{}.subscan.io/validator/{}\">{}</a></b>",
                data.network.name.to_lowercase(),
                data.validator.stash,
                data.validator.name
            ));
            // report.add_raw_text(format!(
            //     "‣ 📦 Authored blocks: {}",
            //     authority_record.authored_blocks(),
            // ));
            // report.add_raw_text(format!("‣ 🎲 Points: {}", authority_record.points()));
            if let Some(para_record) = data.para_record {
                // Find position rank
                let mut v = Vec::<(AuthorityIndex, Points)>::new();
                v.push((
                    *authority_record.authority_index(),
                    authority_record.points(),
                ));
                for peer in data.peers.iter() {
                    v.push((*peer.1.authority_index(), peer.1.points()));
                }

                // Print Ranks
                report.add_raw_text(format!(
                    "‣ 🪂 Para Val. Rank: {}//200 {}",
                    data.para_validator_rank.unwrap_or_default() + 1,
                    position_emoji(data.para_validator_rank.unwrap_or_default())
                ));
                report.add_raw_text(format!(
                    "‣ 🤝 Val. Group {} Rank: {}//40 {}",
                    para_record.group().unwrap_or_default(),
                    data.group_rank.unwrap_or_default() + 1,
                    position_emoji(data.group_rank.unwrap_or_default())
                ));

                let para_validator_group_rank = position(
                    *authority_record.authority_index(),
                    group_by_points(v.clone()),
                );

                let emoji = if authority_record.is_flagged() {
                    Random::HealthCheck
                } else {
                    position_emoji(para_validator_group_rank.unwrap_or_default())
                };
                report.add_raw_text(format!(
                    "‣ 🎓 Para Val. Group Rank: {}//5 {}",
                    para_validator_group_rank.unwrap_or_default() + 1,
                    emoji
                ));

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
                    let total_implicit_votes = para_record.total_implicit_votes();
                    let total_explicit_votes = para_record.total_explicit_votes();
                    let para_points = (total_implicit_votes + total_explicit_votes) * 20;
                    let total_points = (authority_record.authored_blocks() * 20) + para_points;

                    clode_block.push_str(&format!(
                        "{:<3}{:<24}{:>4}{:>4}{:>4}{:>4}{:>4}{:>4}{:>8}{:>6}{:>6}\n",
                        "*",
                        slice(&replace_emoji(&data.validator.name, "_"), 24),
                        authority_record.authored_blocks(),
                        para_record.total_core_assignments(),
                        total_implicit_votes,
                        total_explicit_votes,
                        para_record.total_missed_votes(),
                        grade(1.0_f64 - mvr),
                        (mvr * 10000.0).round() / 10000.0,
                        para_points,
                        total_points
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
                let peers_letters = vec!["A", "B", "C", "D"];
                for (i, peer) in data.peers.iter().enumerate() {
                    if let Some(mvr) = peer.2.missed_votes_ratio() {
                        let total_implicit_votes = peer.2.total_implicit_votes();
                        let total_explicit_votes = peer.2.total_explicit_votes();
                        let para_points = (total_implicit_votes + total_explicit_votes) * 20;
                        let total_points = (authority_record.authored_blocks() * 20) + para_points;

                        clode_block.push_str(&format!(
                            "{:<3}{:<24}{:>4}{:>4}{:>4}{:>4}{:>4}{:>4}{:>8}{:>6}{:>6}\n",
                            peers_letters[i],
                            slice(&replace_emoji(&peer.0.clone(), "_"), 24),
                            peer.1.authored_blocks(),
                            peer.2.total_core_assignments(),
                            total_implicit_votes,
                            total_explicit_votes,
                            peer.2.total_missed_votes(),
                            grade(1.0_f64 - mvr),
                            (mvr * 10000.0).round() / 10000.0,
                            para_points,
                            total_points
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

                clode_block.push_str("\nPARACHAINS VOTES BREAKDOWN\n");
                // Print out parachains breakdown
                clode_block.push_str(&format!(
                    "{:<9}{:^12}{:^12}{:^12}{:^12}{:^12}\n",
                    "", "*", "A", "B", "C", "D",
                ));
                clode_block.push_str(&format!(
                    "{:<6}{:^3}{:>5}{:>5}{:>5}{:>5}{:>5}{:>5}{:>5}{:>5}{:>5}{:>5}\n",
                    "#", "↻", "✓", "✗", "✓", "✗", "✓", "✗", "✓", "✗", "✓", "✗",
                ));
                for para_id in data.parachains.iter() {
                    // Print out votes per para id
                    if let Some(stats) = para_record.get_para_id_stats(*para_id) {
                        let mut line: String = format!(
                            "{:<6}{:^3}{:>5}{:>5}",
                            para_id,
                            stats.core_assignments(),
                            stats.total_votes(),
                            stats.missed_votes(),
                        );
                        for peer in data.peers.iter() {
                            if let Some(peer_stats) = peer.2.get_para_id_stats(*para_id) {
                                line.push_str(&format!(
                                    "{:>5}{:>5}",
                                    peer_stats.total_votes(),
                                    peer_stats.missed_votes()
                                ));
                            }
                        }
                        clode_block.push_str(&format!("{line}\n"));
                    }
                }
                clode_block.push_str("\n</code></pre>");
                report.add_raw_text(clode_block);
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
        flagged_validators_report(&mut report, &data, false);
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

impl Callout<RawData> for Report {
    fn callout(data: RawData) -> Report {
        let config = CONFIG.clone();
        let mut report = Report::new();

        report.add_raw_text(format!(
            "📣 <b>{} // {}</b>",
            data.network.name, data.meta.active_era_index,
        ));

        active_validators_report(&mut report, &data, true);

        flagged_validators_report(&mut report, &data, true);

        top_performers_report(&mut report, &data, true);

        report.add_raw_text(format!(
            "<i>Lookout for the full report here</i> → #{} 👀",
            config.matrix_public_room
        ));

        // Log report
        report.log();

        report
    }
}

fn total_validators_report<'a>(report: &'a mut Report, data: &'a RawData) -> &'a Report {
    report.add_break();

    let total = data.validators.len();
    let total_tvp = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::TVP)
        .collect::<Vec<&Validator>>()
        .len();
    let total_non_tvp = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP)
        .collect::<Vec<&Validator>>()
        .len();
    let total_c100 = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::C100)
        .collect::<Vec<&Validator>>()
        .len();

    report.add_raw_text(format!("{} total {} validators:", total, data.network.name,));
    report.add_raw_text(format!(
        "‣ {} ({:.2}%) • {} ({:.2}%) • <b>{} ({:.2}%)</b>",
        total_c100,
        (total_c100 as f32 / total as f32) * 100.0,
        total_non_tvp,
        (total_non_tvp as f32 / total as f32) * 100.0,
        total_tvp,
        (total_tvp as f32 / total as f32) * 100.0,
    ));
    report.add_break();

    report
}

fn active_validators_report<'a>(
    report: &'a mut Report,
    data: &'a RawData,
    is_verbose: bool,
) -> &'a Report {
    let total_active = data
        .validators
        .iter()
        .filter(|v| v.is_active)
        .collect::<Vec<&Validator>>()
        .len();

    let total_tvp = data
        .validators
        .iter()
        .filter(|v| v.is_active && v.subset == Subset::TVP)
        .collect::<Vec<&Validator>>()
        .len();
    let total_non_tvp = data
        .validators
        .iter()
        .filter(|v| v.is_active && v.subset == Subset::NONTVP)
        .collect::<Vec<&Validator>>()
        .len();
    let total_c100 = data
        .validators
        .iter()
        .filter(|v| v.is_active && v.subset == Subset::C100)
        .collect::<Vec<&Validator>>()
        .len();

    if is_verbose {
        report.add_raw_text(format!(
            "For era {} there are {} active validators:",
            data.meta.active_era_index, total_active,
        ));
        report.add_raw_text(format!(
            "‣ {} ({:.2}%) are 100% commission validators, {} ({:.2}%) are valid <a href=\"https://wiki.polkadot.network/docs/thousand-validators\">TVP validators</a> and the remainder {} ({:.2}%) other validators.",
            total_c100,
            (total_c100 as f32 / total_active as f32) * 100.0,
            total_tvp,
            (total_tvp as f32 / total_active as f32) * 100.0,
            total_non_tvp,
            (total_non_tvp as f32 / total_active as f32) * 100.0,
        ));
    } else {
        report.add_raw_text(format!("{} active validators:", total_active));
        report.add_raw_text(format!(
            "‣ {} ({:.2}%) • {} ({:.2}%) • <b>{} ({:.2}%)</b>",
            total_c100,
            (total_c100 as f32 / total_active as f32) * 100.0,
            total_non_tvp,
            (total_non_tvp as f32 / total_active as f32) * 100.0,
            total_tvp,
            (total_tvp as f32 / total_active as f32) * 100.0,
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

    let avg_tvp: u128 = tvp.iter().sum::<u128>() / tvp.len() as u128;

    let non_tvp: Vec<u128> = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP)
        .map(|v| v.own_stake)
        .collect();

    let avg_non_tvp: u128 = non_tvp.iter().sum::<u128>() / non_tvp.len() as u128;

    let c100: Vec<u128> = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::C100)
        .map(|v| v.own_stake)
        .collect();

    let avg_c100: u128 = c100.iter().sum::<u128>() / c100.len() as u128;

    report.add_raw_text(format!(
        "Average (Min, Max) validator self stake in {}:",
        data.network.token_symbol,
    ));
    report.add_raw_text(format!(
        "‣ {} ({:.2}, {:.0}) • {} ({:.2}, {:.0}) • <b>{} ({:.2}, {:.0})</b>",
        avg_c100 / 10u128.pow(data.network.token_decimals as u32),
        *c100.iter().min().unwrap() as f64 / 10u128.pow(data.network.token_decimals as u32) as f64,
        *c100.iter().max().unwrap() as f64 / 10u128.pow(data.network.token_decimals as u32) as f64,
        avg_non_tvp / 10u128.pow(data.network.token_decimals as u32),
        *non_tvp.iter().min().unwrap() as f64
            / 10u128.pow(data.network.token_decimals as u32) as f64,
        *non_tvp.iter().max().unwrap() as f64
            / 10u128.pow(data.network.token_decimals as u32) as f64,
        avg_tvp / 10u128.pow(data.network.token_decimals as u32),
        *tvp.iter().min().unwrap() as f64 / 10u128.pow(data.network.token_decimals as u32) as f64,
        *tvp.iter().max().unwrap() as f64 / 10u128.pow(data.network.token_decimals as u32) as f64,
    ));
    report.add_break();

    report.add_raw_text(format!(
        "Validator self stake contributions for network security:"
    ));
    report.add_raw_text(format!(
        "‣ {:.2}% • {:.2}% • <b>{:.2}%</b>",
        (c100.iter().sum::<u128>() as f64 / total as f64) * 100.0,
        (non_tvp.iter().sum::<u128>() as f64 / total as f64) * 100.0,
        (tvp.iter().sum::<u128>() as f64 / total as f64) * 100.0,
    ));
    report.add_break();

    report
}

fn oversubscribed_validators_report<'a>(report: &'a mut Report, data: &'a RawData) -> &'a Report {
    let total = data.validators.len();

    let total_over = data
        .validators
        .iter()
        .filter(|v| v.is_oversubscribed)
        .collect::<Vec<&Validator>>()
        .len();

    if total_over == 0 {
        return report;
    }

    let total_tvp = data
        .validators
        .iter()
        .filter(|v| v.is_oversubscribed && v.subset == Subset::TVP)
        .collect::<Vec<&Validator>>()
        .len();
    let total_non_tvp = data
        .validators
        .iter()
        .filter(|v| v.is_oversubscribed && v.subset == Subset::NONTVP)
        .collect::<Vec<&Validator>>()
        .len();
    let total_c100 = data
        .validators
        .iter()
        .filter(|v| v.is_oversubscribed && v.subset == Subset::C100)
        .collect::<Vec<&Validator>>()
        .len();

    report.add_raw_text(format!(
        "Oversubscribed {} ({:.2}%):",
        total_over,
        (total_over as f32 / total as f32) * 100.0
    ));
    report.add_raw_text(format!(
        "‣ {} ({:.2}%) • {} ({:.2}%) • <b>{} ({:.2}%)</b>",
        total_c100,
        (total_c100 as f32 / total_over as f32) * 100.0,
        total_non_tvp,
        (total_non_tvp as f32 / total_over as f32) * 100.0,
        total_tvp,
        (total_tvp as f32 / total_over as f32) * 100.0,
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

    let avg_total_eras_points = total_eras_points.1 / total_eras_points.0;

    let total_eras_points_tvp: (u32, u32) = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::TVP)
        .map(|v| (v.maximum_history_total_eras, v.maximum_history_total_points))
        .reduce(|a, b| (a.0 + b.0, a.1 + b.1))
        .unwrap_or_default();

    let avg_total_eras_points_tvp = total_eras_points_tvp.1 / total_eras_points_tvp.0;

    let total_eras_points_non_tvp: (u32, u32) = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP)
        .map(|v| (v.maximum_history_total_eras, v.maximum_history_total_points))
        .reduce(|a, b| (a.0 + b.0, a.1 + b.1))
        .unwrap_or_default();

    let avg_total_eras_points_non_tvp = total_eras_points_non_tvp.1 / total_eras_points_non_tvp.0;

    let total_eras_points_c100: (u32, u32) = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::C100)
        .map(|v| (v.maximum_history_total_eras, v.maximum_history_total_points))
        .reduce(|a, b| (a.0 + b.0, a.1 + b.1))
        .unwrap_or_default();

    let avg_total_eras_points_c100 = total_eras_points_c100.1 / total_eras_points_c100.0;

    report.add_raw_text(format!(
        "On average {} points per validator per era were collected in the last {} eras:",
        avg_total_eras_points, config.maximum_history_eras,
    ));
    report.add_raw_text(format!(
        "‣ {} {} • {} {} • <b>{} {}</b>",
        trend(
            avg_total_eras_points_c100.into(),
            avg_total_eras_points.into()
        ),
        avg_total_eras_points_c100,
        trend(
            avg_total_eras_points_non_tvp.into(),
            avg_total_eras_points.into()
        ),
        avg_total_eras_points_non_tvp,
        trend(
            avg_total_eras_points_tvp.into(),
            avg_total_eras_points.into()
        ),
        avg_total_eras_points_tvp,
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
        .collect::<Vec<&Validator>>()
        .len();

    let total_tvp_with_points = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::TVP && v.maximum_history_total_points != 0)
        .collect::<Vec<&Validator>>()
        .len();

    let total_non_tvp = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP)
        .collect::<Vec<&Validator>>()
        .len();

    let total_non_tvp_with_points = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP && v.maximum_history_total_points != 0)
        .collect::<Vec<&Validator>>()
        .len();

    let total_c100 = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::C100)
        .collect::<Vec<&Validator>>()
        .len();

    let total_c100_with_points = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::C100 && v.maximum_history_total_points != 0)
        .collect::<Vec<&Validator>>()
        .len();

    report.add_raw_text(format!(
        "Participation in the last {} eras:",
        config.maximum_history_eras,
    ));
    report.add_raw_text(format!(
        "‣ {:.2}% • {:.2}% • <b>{:.2}%</b>",
        (total_c100_with_points as f32 / total_c100 as f32) * 100.0,
        (total_non_tvp_with_points as f32 / total_non_tvp as f32) * 100.0,
        (total_tvp_with_points as f32 / total_tvp as f32) * 100.0,
    ));
    report.add_break();

    report
}

fn flagged_validators_report<'a>(
    report: &'a mut Report,
    data: &'a RawData,
    is_short: bool,
) -> &'a Report {
    let total_active = data
        .validators
        .iter()
        .filter(|v| v.active_last_era)
        .collect::<Vec<&Validator>>()
        .len();

    let total_tvp = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::TVP && v.active_last_era)
        .collect::<Vec<&Validator>>()
        .len();

    let total_tvp_flagged = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::TVP && v.active_last_era && v.flagged_epochs.len() >= 1)
        .collect::<Vec<&Validator>>()
        .len();

    let total_non_tvp = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP && v.active_last_era)
        .collect::<Vec<&Validator>>()
        .len();

    let total_non_tvp_flagged = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP && v.active_last_era && v.flagged_epochs.len() >= 1)
        .collect::<Vec<&Validator>>()
        .len();

    let total_c100 = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::C100 && v.active_last_era)
        .collect::<Vec<&Validator>>()
        .len();

    let total_c100_flagged = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::C100 && v.active_last_era && v.flagged_epochs.len() >= 1)
        .collect::<Vec<&Validator>>()
        .len();

    let total_flagged = total_c100_flagged + total_non_tvp_flagged + total_tvp_flagged;
    if total_flagged != 0 {
        let warning = if total_flagged as f32 / total_active as f32 > 0.1 {
            "⚠️ "
        } else {
            ""
        };
        report.add_raw_text(format!(
            "{}In the previous era, {} ({:.2}%) validators missed more than 50% of votes when selected as para-validator for at least one epoch:",
            warning,
            total_flagged,
            (total_flagged as f32 / total_active as f32) * 100.0
        ));
        if is_short {
            report.add_raw_text(format!(
                "‣ {} are 100% commission validators, {} are valid TVP validators and the remainder {} other validators.",
                total_c100_flagged,
                total_tvp_flagged,
                total_non_tvp_flagged
            ));
        } else {
            report.add_raw_text(format!(
                "‣ {} ({:.2}%) • {} ({:.2}%) • <b> {} ({:.2}%)</b>",
                total_c100_flagged,
                (total_c100_flagged as f32 / total_c100 as f32) * 100.0,
                total_non_tvp_flagged,
                (total_non_tvp_flagged as f32 / total_non_tvp as f32) * 100.0,
                total_tvp_flagged,
                (total_tvp_flagged as f32 / total_tvp as f32) * 100.0,
            ));
        }
        // extremely low-performance
        let elp = data
            .validators
            .iter()
            .filter(|v| {
                v.active_last_era
                    && v.flagged_epochs.len() >= 1
                    && v.last_missed_ratio.unwrap() > 0.75_f64
            })
            .collect::<Vec<&Validator>>();
        if elp.len() > 0 {
            report.add_raw_text(format!("‣ 🚨 {} missed more than 75% of votes.", elp.len()));
        }
        report.add_break();
    }

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

    let max = if tvp_sorted.len() > 4 && is_short {
        4
    } else if tvp_sorted.len() > 16 && !is_short {
        16
    } else {
        tvp_sorted.len()
    };

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
    report.add_break();
    report
}

fn top_performers_report<'a>(
    report: &'a mut Report,
    data: &'a RawData,
    is_short: bool,
) -> &'a Report {
    // If first era just show rank based on avg. points
    if data.records_total_full_eras == 0 {
        return top_validators_report(report, &data, is_short);
    }

    // Sort TVP by missed ratio for validators that were p/v in the last X eras
    let mut validators_sorted = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::TVP && v.para_epochs >= 1 && v.missed_ratio.is_some())
        .collect::<Vec<&Validator>>();

    if validators_sorted.len() > 0 {
        validators_sorted.sort_by(|a, b| {
            if a.avg_para_points == b.avg_para_points {
                if a.missed_ratio.unwrap() == b.missed_ratio.unwrap() {
                    // p/v times in descending order
                    b.para_epochs.partial_cmp(&a.para_epochs).unwrap()
                } else {
                    // missed ratio in ascending order
                    a.missed_ratio
                        .unwrap()
                        .partial_cmp(&b.missed_ratio.unwrap())
                        .unwrap()
                }
            } else {
                // session avg. points in descending order
                b.avg_para_points.partial_cmp(&a.avg_para_points).unwrap()
            }
        });

        let max = if validators_sorted.len() > 4 && is_short {
            4
        } else if validators_sorted.len() > 16 && !is_short {
            16
        } else {
            validators_sorted.len()
        };

        if is_short {
            report.add_raw_text(format!(
                "Top {} TVP Validators with most average para-validator points per session in the last {} eras:",
                max, data.records_total_full_eras
            ));
        } else {
            report.add_raw_text(format!("🏆 <b>Top {} TVP Validators</b> with most average para-validator points per session in the last {} eras:", max, data.records_total_full_eras));
            report.add_raw_text(format!("<i>Sorting: Validators are sorted 1st by average p/v points per session, 2nd by missed votes ratio, 3rd by number of X sessions when selected as p/v.</i>"));
            report.add_raw_text(format!("<i>Legend: val. identity (avg. p/v points per session, percentage of missed votes, number of sessions as p/v)</i>"));
        }
        report.add_break();

        for v in &validators_sorted[..max] {
            report.add_raw_text(format!(
                "* {} ({}, {:.2}%, {}x)",
                v.name,
                v.avg_para_points,
                v.missed_ratio.unwrap() * 100.0,
                v.para_epochs
            ));
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

fn group_by_points(v: Vec<(u32, u32)>) -> Vec<Vec<(u32, u32)>> {
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

fn position(a: u32, v: Vec<Vec<(u32, u32)>>) -> Option<usize> {
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

pub fn grade(ratio: f64) -> String {
    let p = (ratio * 100.0).round() as u32;
    match p {
        90..=100 => "A+".to_string(),
        80..=89 => "A".to_string(),
        70..=79 => "B+".to_string(),
        60..=69 => "B".to_string(),
        55..=59 => "C+".to_string(),
        50..=54 => "C".to_string(),
        45..=49 => "D+".to_string(),
        40..=44 => "D".to_string(),
        _ => "F".to_string(),
    }
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
