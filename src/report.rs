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
    AuthorityIndex, AuthorityRecord, EpochIndex, ParaId, ParaRecord, ParaStats, Points,
};
use crate::stats::confidence_interval_99;
use crate::stats::mean;
use log::info;
use rand::Rng;
use regex::Regex;
use std::{convert::TryInto, result::Result};
use subxt::sp_runtime::AccountId32;
use subxt::{Client, DefaultConfig};

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
    pub total_authored_blocks: u32,

    pub active_last_era: bool,
    pub flagged_epochs: Vec<EpochIndex>,
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
            total_authored_blocks: 0,
            // records: Vec::new(),
            active_last_era: false,
            flagged_epochs: Vec::new(),
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
pub struct Session {
    pub active_era_index: u32,
    pub active_era_total_stake: u128,
    pub current_session_index: u32,
    pub start_block: u64,
    pub end_block: u64,
}

#[derive(Debug, Clone)]
pub struct RawData {
    pub network: Network,
    pub validators: Validators,
    pub session: Session,
}

#[derive(Debug)]
pub struct RawDataPara {
    pub network: Network,
    pub session: Session,
    pub report_type: ReportType,
    pub is_first_record: bool,
    pub validator: Validator,
    pub peers: Vec<(String, AuthorityRecord, ParaRecord)>,
    pub authority_record: Option<AuthorityRecord>,
    pub para_record: Option<ParaRecord>,
    pub parachains: Vec<ParaId>,
    pub para_validator_rank: Option<usize>,
    pub group_rank: Option<usize>,
    pub ci_99_9: (f64, f64),
}

#[derive(Debug)]
pub struct RawDataGroup {
    pub network: Network,
    pub session: Session,
    pub report_type: ReportType,
    pub is_first_record: bool,
    pub groups: Vec<(u32, Vec<(AuthorityRecord, String, u32)>)>,
    pub ci_99_9: (f64, f64),
}

#[derive(Debug)]
pub struct RawDataParachains {
    pub network: Network,
    pub session: Session,
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
                data.session.active_era_index,
                data.session.current_session_index
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
            data.session.active_era_index,
            data.session.current_session_index
        ));
        report.add_raw_text(format!(
            "<i>{} blocks recorded from #{} to #{}</i>",
            data.session.end_block - data.session.start_block,
            data.session.start_block,
            data.session.end_block
        ));
        report.add_break();

        // Groups info
        let mut clode_block = String::from("<pre><code>");

        for (i, group) in data.groups.iter().enumerate() {
            clode_block.push_str(&format!(
                "{:<21}{:1}{:>3}{:>4}{:>7}\n",
                format!("#{} VAL. GROUP {}", i + 1, group.0),
                "!",
                "↻",
                "❒",
                "PTS"
            ));
            let sample = group
                .1
                .iter()
                .map(|(a, _, _)| a.points() as f64)
                .collect::<Vec<f64>>();
            let ci = confidence_interval_99(&sample);
            for (authority_record, val_name, core_assignments) in group.1.iter() {
                let flag = if (authority_record.points() as f64) < ci.0
                    && (authority_record.points() as f64) < data.ci_99_9.0
                {
                    "!"
                } else {
                    ""
                };
                clode_block.push_str(&format!(
                    "{:<21}{:1}{:>3}{:>4}{:>7}\n",
                    slice(&replace_emoji(&val_name, "_"), 21),
                    flag,
                    core_assignments,
                    authority_record.authored_blocks(),
                    authority_record.points()
                ));
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
                data.session.active_era_index,
                data.session.current_session_index
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
            data.session.active_era_index,
            data.session.current_session_index
        ));
        report.add_raw_text(format!(
            "<i>{} blocks recorded from #{} to #{}</i>",
            data.session.end_block - data.session.start_block,
            data.session.start_block,
            data.session.end_block
        ));
        report.add_break();

        // Parachains info
        let mut clode_block = String::from("<pre><code>");

        clode_block.push_str(&format!(
            "{:<5}{:<9}{:>6}{:>8}{:>8}\n",
            "#", "PARACHAIN", "↻", "❒", "PTS"
        ));
        for (i, (para_id, stats)) in data.parachains.iter().enumerate() {
            clode_block.push_str(&format!(
                "{:<5}{:<9}{:>6}{:>8}{:>8}\n",
                format!("#{}", i + 1),
                para_id,
                stats.core_assignments() / 5,
                stats.authored_blocks(),
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
                data.session.active_era_index,
                data.session.current_session_index
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
            data.session.active_era_index,
            data.session.current_session_index
        ));
        report.add_raw_text(format!(
            "<i>{} blocks recorded from #{} to #{}</i>",
            data.session.end_block - data.session.start_block,
            data.session.start_block,
            data.session.end_block
        ));
        report.add_break();

        // Validator info
        // --- Specific parachains report here [START] -->
        if let Some(authority_record) = data.authority_record {
            report.add_raw_text(format!(
                "🟢 <b><a href=\"https://{}.subscan.io/validator/{}\">{}</a></b>",
                data.network.name.to_lowercase(),
                data.validator.stash,
                data.validator.name
            ));
            report.add_raw_text(format!(
                "‣ 📦 Authored blocks: {}",
                authority_record.authored_blocks(),
            ));
            report.add_raw_text(format!("‣ 🎲 Points: {}", authority_record.points()));
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

                let sample = v
                    .iter()
                    .map(|(_, points)| *points as f64)
                    .collect::<Vec<f64>>();
                let ci = confidence_interval_99(&sample);
                let emoji = if (authority_record.points() as f64) < ci.0
                    && (authority_record.points() as f64) < data.ci_99_9.0
                {
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

                clode_block.push_str(&format!(
                    "{:<2}{:<21}{:>6}{:>7}\n",
                    "#",
                    format!("VAL. GROUP {}", para_record.group().unwrap_or_default()),
                    "❒",
                    "PTS"
                ));

                // verify if authority falls below ci
                let flag = if (authority_record.points() as f64) < ci.0
                    && (authority_record.points() as f64) < data.ci_99_9.0
                {
                    "!"
                } else {
                    ""
                };
                // Print out subscriber
                clode_block.push_str(&format!(
                    "{:<2}{:<21}{:>2}{:>4}{:>7}\n",
                    "*",
                    slice(&replace_emoji(&data.validator.name, "_"), 21),
                    flag,
                    authority_record.authored_blocks(),
                    authority_record.points()
                ));
                // Print out peers
                let peers_letters = vec!["A", "B", "C", "D"];
                for (i, peer) in data.peers.iter().enumerate() {
                    // verify if one of the peers is falls below ci
                    let flag = if (peer.1.points() as f64) < ci.0
                        && (peer.1.points() as f64) < data.ci_99_9.0
                    {
                        "!"
                    } else {
                        ""
                    };
                    clode_block.push_str(&format!(
                        "{:<2}{:<21}{:>2}{:>4}{:>7}\n",
                        peers_letters[i],
                        slice(&replace_emoji(&peer.0.clone(), "_"), 21),
                        flag,
                        peer.1.authored_blocks(),
                        peer.1.points()
                    ));
                }
                clode_block.push_str("\nPARACHAINS POINTS BREAKDOWN\n");
                // Print out parachains breakdown
                clode_block.push_str(&format!(
                    "{:<6}{:^5}{:>5}{:>5}{:>5}{:>5}{:>5}\n",
                    "#", "↻", "*", "A", "B", "C", "D",
                ));
                for para_id in data.parachains.iter() {
                    // Print out validator points per para id
                    if let Some(stats) = para_record.get_para_id_stats(*para_id) {
                        let peers_avg = mean(
                            &data
                                .peers
                                .iter()
                                .map(|peer| {
                                    if let Some(peer_stats) = peer.2.get_para_id_stats(*para_id) {
                                        peer_stats.points() as f64
                                    } else {
                                        0.0_f64
                                    }
                                })
                                .collect(),
                        );
                        let mut line: String = format!(
                            "{:<6}{:^5}{:>5}",
                            para_id,
                            stats.core_assignments(),
                            format!(
                                "{}{}",
                                trend(stats.points() as f64, peers_avg),
                                stats.points()
                            )
                        );
                        for peer in data.peers.iter() {
                            if let Some(peer_stats) = peer.2.get_para_id_stats(*para_id) {
                                line.push_str(&format!("{:>5}", peer_stats.points()));
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
            "📒 Network Report → <b>{}//{}</b>",
            data.network.name, data.session.active_era_index,
        ));
        report.add_raw_text(format!(
            "<i>TVP validators are shown in bold (100% Commission • Others • <b><a href=\"https://wiki.polkadot.network/docs/thousand-validators\">TVP</a></b>).</i>",
        ));

        // report.add_raw_text(format!(
        //     "<i>e.g. The first position is always related to the sub set of 100% commission validators, followed by the stat of the sub set of validators not included in the Thousand Validator Programme (non-tvp) and next in bold is the stat of the sub set of validators that participate in the TVP.</i>",
        // ));
        // --- Specific report sections here [START] -->

        total_validators_report(&mut report, &data);
        active_validators_report(&mut report, &data, false);
        flagged_validators_report(&mut report, &data);
        own_stake_validators_report(&mut report, &data);
        oversubscribed_validators_report(&mut report, &data);
        avg_points_collected_report(&mut report, &data);
        inclusion_validators_report(&mut report, &data);
        top_validators_report(&mut report, &data, false);

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
            data.network.name, data.session.active_era_index,
        ));

        active_validators_report(&mut report, &data, true);

        top_validators_report(&mut report, &data, true);

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
            data.session.active_era_index, total_active,
        ));
        report.add_raw_text(format!(
            "‣ {} ({:.2}%) are 100% commission validators, {} ({:.2}%) are <a href=\"https://wiki.polkadot.network/docs/thousand-validators\">TVP validators</a> and the remainder {} ({:.2}%) other validators.",
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
    let total = data.session.active_era_total_stake;

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
        "‣ {} ({:.2}%) + {} ({:.2}%) + <b>{} ({:.2}%)</b>",
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
        .map(|v| (v.total_eras, v.total_points))
        .reduce(|a, b| (a.0 + b.0, a.1 + b.1))
        .unwrap_or_default();

    let avg_total_eras_points = total_eras_points.1 / total_eras_points.0;

    let total_eras_points_tvp: (u32, u32) = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::TVP)
        .map(|v| (v.total_eras, v.total_points))
        .reduce(|a, b| (a.0 + b.0, a.1 + b.1))
        .unwrap_or_default();

    let avg_total_eras_points_tvp = total_eras_points_tvp.1 / total_eras_points_tvp.0;

    let total_eras_points_non_tvp: (u32, u32) = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::NONTVP)
        .map(|v| (v.total_eras, v.total_points))
        .reduce(|a, b| (a.0 + b.0, a.1 + b.1))
        .unwrap_or_default();

    let avg_total_eras_points_non_tvp = total_eras_points_non_tvp.1 / total_eras_points_non_tvp.0;

    let total_eras_points_c100: (u32, u32) = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::C100)
        .map(|v| (v.total_eras, v.total_points))
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
        .filter(|v| v.subset == Subset::TVP && v.total_points != 0)
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
        .filter(|v| v.subset == Subset::NONTVP && v.total_points != 0)
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
        .filter(|v| v.subset == Subset::C100 && v.total_points != 0)
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

fn flagged_validators_report<'a>(report: &'a mut Report, data: &'a RawData) -> &'a Report {
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
        .filter(|v| v.subset == Subset::TVP && v.active_last_era && v.flagged_epochs.len() >= 2)
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
        .filter(|v| v.subset == Subset::NONTVP && v.active_last_era && v.flagged_epochs.len() >= 2)
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
        .filter(|v| v.subset == Subset::C100 && v.active_last_era && v.flagged_epochs.len() >= 2)
        .collect::<Vec<&Validator>>()
        .len();

    let total_flagged = total_c100_flagged + total_non_tvp_flagged + total_tvp_flagged;
    if total_flagged != 0 {
        report.add_raw_text(format!(
            "{} ({:.2}%) validators with a poor performance last era:",
            total_flagged,
            (total_flagged as f32 / total_active as f32) * 100.0,
        ));
        report.add_raw_text(format!(
            "‣ {} ({:.2}%) • {} ({:.2}%) • <b> {} ({:.2}%)</b>",
            total_c100_flagged,
            (total_c100_flagged as f32 / total_c100 as f32) * 100.0,
            total_non_tvp_flagged,
            (total_non_tvp_flagged as f32 / total_non_tvp as f32) * 100.0,
            total_tvp_flagged,
            (total_tvp_flagged as f32 / total_tvp as f32) * 100.0,
        ));
        report.add_break();
    }

    report
}

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
        .filter(|v| v.subset == Subset::TVP && v.total_eras >= config.maximum_history_eras / 2)
        .collect::<Vec<&Validator>>();

    tvp_sorted
        .sort_by(|a, b| (b.total_points / b.total_eras).cmp(&(&a.total_points / &a.total_eras)));

    let max = if is_short { 5 } else { 10 };
    report.add_raw_text(format!(
        "Top {} TVP Validators with most average points in the last {} eras (minimum inclusion {} eras):",
        max,
        config.maximum_history_eras,
        config.maximum_history_eras / 2,
    ));
    report.add_break();
    for v in &tvp_sorted[..max] {
        report.add_raw_text(format!("* {} ({})", v.name, v.total_points / v.total_eras));
    }
    report.add_break();
    report
}

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
        "]+",
    ))
    .unwrap();

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
}
