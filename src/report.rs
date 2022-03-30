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
use crate::records::{AuthorityIndex, AuthorityRecord, ParaId, ParaRecord, Points};
use crate::stats::mean;
use log::info;
use rand::Rng;
use regex::Regex;
use std::{convert::TryInto, result::Result};
use subxt::sp_runtime::AccountId32;
use subxt::{Client, DefaultConfig};

#[derive(Debug)]
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
            warnings: Vec::new(),
        }
    }
}

pub type Validators = Vec<Validator>;

#[derive(PartialEq, Debug)]
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

#[derive(Debug)]
pub struct RawData {
    pub network: Network,
    pub validators: Validators,
    pub session: Session,
}

#[derive(Debug)]
pub struct RawDataPara {
    pub network: Network,
    pub session: Session,
    // pub validators: Validators,
    pub validator: Validator,
    pub peers: Vec<(String, AuthorityRecord, ParaRecord)>,
    pub authority_record: Option<AuthorityRecord>,
    pub para_record: Option<ParaRecord>,
    pub parachains: Vec<ParaId>,
    pub para_validator_rank: Option<usize>,
    pub group_rank: Option<usize>,
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

impl From<RawDataPara> for Report {
    /// Converts a Thor `RawData` into a [`Report`].
    fn from(data: RawDataPara) -> Report {
        let mut report = Report::new();

        // Thor package
        report.add_raw_text(format!(
            "🤖 <code>{} v{}</code>",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ));

        // Network info
        report.add_break();
        report.add_raw_text(format!(
            "📮 Validator performance report → <b>{}//{}//{}</b>",
            data.network.name, data.session.active_era_index, data.session.current_session_index
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
                    position_emoji(data.para_validator_rank.unwrap_or_default(), 199)
                ));
                report.add_raw_text(format!(
                    "‣ 🤝 Val. Group {} Rank: {}//40 {}",
                    para_record.group().unwrap_or_default(),
                    data.group_rank.unwrap_or_default() + 1,
                    position_emoji(data.group_rank.unwrap_or_default(), 39)
                ));

                let para_validator_group_rank =
                    position(*authority_record.authority_index(), group_by_points(v));
                report.add_raw_text(format!(
                    "‣ 🎓 Para Val. Group Rank: {}//5 {}",
                    para_validator_group_rank.unwrap_or_default() + 1,
                    position_emoji(para_validator_group_rank.unwrap_or_default(), 4)
                ));

                // Print breakdown points
                let mut clode_block = String::from("<pre><code>");

                clode_block.push_str(&format!(
                    "{:<2}{:<21}{:>6}{:>7}\n",
                    "#",
                    format!("VAL. GROUP {}", para_record.group().unwrap_or_default()),
                    "BLOCKS",
                    "POINTS"
                ));

                fn slice(name: &str, maximum_length: usize) -> String {
                    let cut = if name.len() <= maximum_length {
                        name.len()
                    } else {
                        maximum_length
                    };
                    String::from(&name[..cut])
                }
                // Print out subscriber
                clode_block.push_str(&format!(
                    "{:<2}{:<21}{:>6}{:>7}\n",
                    // "✸",
                    "*",
                    slice(&replace_emoji(&data.validator.name, "_"), 21),
                    authority_record.authored_blocks(),
                    authority_record.points()
                ));
                // Print out peers
                let peers_letters = vec!["A", "B", "C", "D"];
                for (i, peer) in data.peers.iter().enumerate() {
                    clode_block.push_str(&format!(
                        "{:<2}{:<21}{:>6}{:>7}\n",
                        peers_letters[i],
                        slice(&replace_emoji(&peer.0.clone(), "_"), 21),
                        peer.1.authored_blocks(),
                        peer.1.points()
                    ));
                }
                clode_block.push_str("\nPARACHAINS POINTS BREAKDOWN\n");
                // Print out parachains breakdown
                clode_block.push_str(&format!(
                    "{:<5}{:^3}{:>7}{:>7}{:>7}{:>7}{:>7}\n",
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
                            "{:<5}{:^3}{:>7}",
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
                                line.push_str(&format!("{:>7}", peer_stats.points()));
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

        report.add_raw_text("___".into());
        report.add_break();

        // Log report
        report.log();

        report
    }
}

impl From<RawData> for Report {
    /// Converts a Crunch `RawData` into a [`Report`].
    fn from(data: RawData) -> Report {
        let mut report = Report::new();

        // Thor package
        report.add_raw_text(format!(
            "🤖 <code>{} v{}</code>",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ));

        // Network info
        report.add_break();
        report.add_raw_text(format!(
            "📒 Network on-chain report → <b>{}//{}</b>",
            data.network.name, data.session.active_era_index,
        ));
        report.add_raw_text(format!(
            "<i>TVP validators are shown in bold (<b>TVP</b> • non-tvp • 100% Commission).</i>",
        ));

        // --- Specific report sections here [START] -->

        total_validators_report(&mut report, &data);
        active_validators_report(&mut report, &data);
        own_stake_validators_report(&mut report, &data);
        oversubscribed_validators_report(&mut report, &data);
        avg_points_collected_report(&mut report, &data);
        inclusion_validators_report(&mut report, &data);
        top_validators_report(&mut report, &data);

        // --- Specific report sections here [END] ---|

        report.add_raw_text("___".into());
        report.add_break();

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

    report.add_raw_text(format!(
        "{} validators in total {}: <b>{} ({:.2}%)</b> • {} ({:.2}%) • {} ({:.2}%)",
        data.network.name,
        total,
        total_tvp,
        (total_tvp as f32 / total as f32) * 100.0,
        total_non_tvp,
        (total_non_tvp as f32 / total as f32) * 100.0,
        total_c100,
        (total_c100 as f32 / total as f32) * 100.0,
    ));

    report
}

fn active_validators_report<'a>(report: &'a mut Report, data: &'a RawData) -> &'a Report {
    let total = data.validators.len();

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

    report.add_raw_text(format!(
        "Currently active {} ({:.2}%): <b>{} ({:.2}%)</b> • {} ({:.2}%) • {} ({:.2}%)",
        total_active,
        (total_active as f32 / total as f32) * 100.0,
        total_tvp,
        (total_tvp as f32 / total_active as f32) * 100.0,
        total_non_tvp,
        (total_non_tvp as f32 / total_active as f32) * 100.0,
        total_c100,
        (total_c100 as f32 / total_active as f32) * 100.0,
    ));

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
        "Average, Minimum and Maximum validator self stake in {}: <b>{} [{:.2}, {:.0}]</b> • {} [{:.2}, {:.0}] • {} [{:.2}, {:.0}]",
        data.network.token_symbol,
        avg_tvp / 10u128.pow(data.network.token_decimals as u32),
        *tvp.iter().min().unwrap() as f64 / 10u128.pow(data.network.token_decimals as u32) as f64,
        *tvp.iter().max().unwrap() as f64 / 10u128.pow(data.network.token_decimals as u32) as f64,
        avg_non_tvp / 10u128.pow(data.network.token_decimals as u32),
        *non_tvp.iter().min().unwrap() as f64 / 10u128.pow(data.network.token_decimals as u32) as f64,
        *non_tvp.iter().max().unwrap() as f64 / 10u128.pow(data.network.token_decimals as u32) as f64,
        avg_c100 / 10u128.pow(data.network.token_decimals as u32),
        *c100.iter().min().unwrap() as f64 / 10u128.pow(data.network.token_decimals as u32) as f64,
        *c100.iter().max().unwrap() as f64 / 10u128.pow(data.network.token_decimals as u32) as f64
    ));
    report.add_raw_text(format!(
        "Validator contributions for network security: <b>{:.2}%</b> • {:.2}% • {:.2}%",
        (tvp.iter().sum::<u128>() as f64 / total as f64) * 100.0,
        (non_tvp.iter().sum::<u128>() as f64 / total as f64) * 100.0,
        (c100.iter().sum::<u128>() as f64 / total as f64) * 100.0,
    ));

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
        "Oversubscribed {} ({:.2}%): <b>{} ({:.2}%)</b> • {} ({:.2}%) • {} ({:.2}%)",
        total_over,
        (total_over as f32 / total as f32) * 100.0,
        total_tvp,
        (total_tvp as f32 / total_over as f32) * 100.0,
        total_non_tvp,
        (total_non_tvp as f32 / total_over as f32) * 100.0,
        total_c100,
        (total_c100 as f32 / total_over as f32) * 100.0,
    ));

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
        "On average {} points/validator/era collected in the last {} eras: <b>{} {}</b> • {} {} • {} {}",
        avg_total_eras_points,
        config.maximum_history_eras,
        avg_total_eras_points_tvp,
        trend(avg_total_eras_points_tvp.into(), avg_total_eras_points.into()),
        avg_total_eras_points_non_tvp,
        trend(avg_total_eras_points_non_tvp.into(), avg_total_eras_points.into()),
        avg_total_eras_points_c100,
        trend(avg_total_eras_points_c100.into(), avg_total_eras_points.into())
    ));

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
        "Participation in the last {} eras: <b>{:.2}%</b> • {:.2}% • {:.2}%",
        config.maximum_history_eras,
        (total_tvp_with_points as f32 / total_tvp as f32) * 100.0,
        (total_non_tvp_with_points as f32 / total_non_tvp as f32) * 100.0,
        (total_c100_with_points as f32 / total_c100 as f32) * 100.0
    ));

    report
}

fn top_validators_report<'a>(report: &'a mut Report, data: &'a RawData) -> &'a Report {
    report.add_break();

    let config = CONFIG.clone();

    // Sort TVP by avg points for validators that had at least 1/3 of max eras
    let mut tvp_sorted = data
        .validators
        .iter()
        .filter(|v| v.subset == Subset::TVP && v.total_eras >= config.maximum_history_eras / 2)
        .collect::<Vec<&Validator>>();

    tvp_sorted
        .sort_by(|a, b| (b.total_points / b.total_eras).cmp(&(&a.total_points / &a.total_eras)));

    report.add_raw_text(format!(
        "Top 8 TVP Validators with most average points in the last {} eras (minimum inclusion {} eras):",
        config.maximum_history_eras,
        config.maximum_history_eras / 2,
    ));

    for v in &tvp_sorted[..8] {
        report.add_raw_text(format!("* {} ({})", v.name, v.total_points / v.total_eras));
    }

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

fn position_emoji(r: usize, last: usize) -> Random {
    if r == last {
        return Random::Last;
    }
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
    Last,
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
                let v = vec!["😞", "😔", "😟", "😕", "🙁", "😣", "😖", "😢"];
                write!(f, "{}", v[random_index(v.len())])
            }
            Self::Last => {
                let v = vec!["😫", "😩", "🥺", "😭", "😤", "😠", "😡", "🤬", "😱", "😰"];
                write!(f, "{} ⚠️", v[random_index(v.len())])
            }
        }
    }
}

fn random_index(len: usize) -> usize {
    let mut rng = rand::thread_rng();
    rng.gen_range(0..len - 1)
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
