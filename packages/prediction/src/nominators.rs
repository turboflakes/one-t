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

use crate::error::PredictionError;
use crate::types::{parse_account, Planck, TargetValidators};
use serde::{Deserialize, Serialize};
use std::path::Path;
use subxt::utils::AccountId32;

#[derive(Deserialize)]
struct RawAllocation {
    validator: String,
    allocated_stake: String,
}

#[derive(Deserialize)]
struct RawNominator {
    address: String,
    stake: String,
    #[serde(default)]
    active_validators: Vec<RawAllocation>,
    #[serde(default)]
    inactive_validators: Vec<String>,
    #[serde(default)]
    waiting_validators: Vec<String>,
}

#[derive(Deserialize)]
struct RawNominatorsPrediction {
    nominators: Vec<RawNominator>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NominatorAllocation {
    pub address: String,
    pub allocated_stake: Planck,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NominatorPrediction {
    pub address: String,
    pub stake: Planck,
    pub active_validators: Vec<NominatorAllocation>,
    pub inactive_validators: Vec<String>,
    pub waiting_validators: Vec<String>,
}

/// The group a nominator belongs to, in order of precedence: with at least one `Active`
/// validator, otherwise with at least one `Inactive` validator, otherwise with at least one
/// `Waiting` validator, otherwise with `NoNominations` at all. Every nominator is in one group only.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NominatorStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "inactive")]
    Inactive,
    #[serde(rename = "waiting")]
    Waiting,
    #[serde(rename = "none")]
    NoNominations,
}

impl NominatorStatus {
    pub const ALL: [NominatorStatus; 4] = [
        NominatorStatus::Active,
        NominatorStatus::Inactive,
        NominatorStatus::Waiting,
        NominatorStatus::NoNominations,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Waiting => "waiting",
            Self::NoNominations => "none",
        }
    }
}

impl std::fmt::Display for NominatorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl NominatorPrediction {
    pub fn status(&self) -> NominatorStatus {
        if !self.active_validators.is_empty() {
            NominatorStatus::Active
        } else if !self.inactive_validators.is_empty() {
            NominatorStatus::Inactive
        } else if !self.waiting_validators.is_empty() {
            NominatorStatus::Waiting
        } else {
            NominatorStatus::NoNominations
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NominatorEntry {
    pub account_id: AccountId32,
    pub nominator: NominatorPrediction,
}

/// Stats about the nominators of a prediction for a given number of target validators.
/// The nominators without any active validator are split in three mutually exclusive groups:
/// `inactive_only` (at least one inactive validator), `waiting_only` (at least one waiting
/// and no inactive validators) and `no_nominations` (none of the above).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct NominatorsMetadata {
    pub nominators_counter: u32,
    pub active_counter: u32,
    pub inactive_only_counter: u32,
    pub waiting_only_counter: u32,
    pub no_nominations_counter: u32,
    pub total_stake: Planck,
    // active_stake is the sum of the stake allocated to active validators
    pub active_stake: Planck,
    // idle_stake is the stake of the nominators without any active validator
    pub idle_stake: Planck,
    // timestamp is the unix timestamp of the prediction file
    pub timestamp: u64,
}

/// Predicted nominations for a given number of target validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NominatorsPrediction {
    pub target_validators: TargetValidators,
    pub metadata: NominatorsMetadata,
    pub entries: Vec<NominatorEntry>,
}

/// Reads the number of target validators from the file name: the digits after the last `_`
/// of the file stem, e.g. `nominators_prediction_500.json` is 500.
pub fn target_from_path(path: &Path) -> Result<TargetValidators, PredictionError> {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .and_then(|stem| stem.rsplit('_').next())
        .and_then(|target| target.parse::<TargetValidators>().ok())
        .filter(|target| *target > 0)
        .ok_or_else(|| {
            PredictionError::Other(format!(
                "could not read the target validators from file name {:?}, expected <name>_<target>.json",
                path.file_name().unwrap_or_default()
            ))
        })
}

impl NominatorsPrediction {
    /// Parses and validates a nominators prediction file. Stakes must be expressed in `symbol`
    /// and are converted to planck using `decimals`.
    pub fn from_slice(
        bytes: &[u8],
        target_validators: TargetValidators,
        timestamp: u64,
        symbol: &str,
        decimals: u32,
    ) -> Result<Self, PredictionError> {
        let raw: RawNominatorsPrediction = serde_json::from_slice(bytes)?;

        let mut entries: Vec<NominatorEntry> = Vec::with_capacity(raw.nominators.len());
        for nominator in raw.nominators {
            let account_id = parse_account(&nominator.address)?;
            let active_validators = nominator
                .active_validators
                .into_iter()
                .map(|a| {
                    Ok(NominatorAllocation {
                        address: parse_account(&a.validator)?.to_string(),
                        allocated_stake: Planck::parse(&a.allocated_stake, symbol, decimals)?,
                    })
                })
                .collect::<Result<Vec<_>, PredictionError>>()?;
            let normalize = |addresses: &[String]| {
                addresses
                    .iter()
                    .map(|v| Ok(parse_account(v)?.to_string()))
                    .collect::<Result<Vec<_>, PredictionError>>()
            };
            let inactive_validators = normalize(&nominator.inactive_validators)?;
            let waiting_validators = normalize(&nominator.waiting_validators)?;

            entries.push(NominatorEntry {
                account_id,
                nominator: NominatorPrediction {
                    address: account_id.to_string(),
                    stake: Planck::parse(&nominator.stake, symbol, decimals)?,
                    active_validators,
                    inactive_validators,
                    waiting_validators,
                },
            });
        }

        let mut metadata = NominatorsMetadata {
            nominators_counter: entries.len() as u32,
            timestamp,
            ..Default::default()
        };
        for NominatorEntry { nominator, .. } in entries.iter() {
            metadata.total_stake.0 = metadata.total_stake.0.saturating_add(nominator.stake.0);
            match nominator.status() {
                NominatorStatus::Active => {
                    metadata.active_counter += 1;
                    for a in nominator.active_validators.iter() {
                        metadata.active_stake.0 =
                            metadata.active_stake.0.saturating_add(a.allocated_stake.0);
                    }
                }
                status => {
                    metadata.idle_stake.0 = metadata.idle_stake.0.saturating_add(nominator.stake.0);
                    match status {
                        NominatorStatus::Inactive => metadata.inactive_only_counter += 1,
                        NominatorStatus::Waiting => metadata.waiting_only_counter += 1,
                        _ => metadata.no_nominations_counter += 1,
                    }
                }
            }
        }

        Ok(NominatorsPrediction {
            target_validators,
            metadata,
            entries,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const N1: &str = "14oibUJUJkPRno7v2M1LtSvsiiE4DiAG38HqfYHQhyfXiqby";
    const V1: &str = "14ghKTz5mjZPgGYvgVC9VnFw1HYZmmsnYvSSHFgFTJfMvwQS";
    const V2: &str = "14Y4s6V1PWrwBLvxW47gcYgZCGTYekmmzvFsK1kiqNH2d84t";
    const W1: &str = "14oTqhVovqnamxu2SiP79WfJMvhRRwiF4d2Hjs25d4SDQNjJ";
    // any other valid addresses
    const N2: &str = "14b3zfcuDsLrVogj62iRb3adxLsTZ3XH58BrWVUAs3v2doBc";
    const N3: &str = "1NghFPwbVjAuUaRt82b4tHD89X21CpA9da9sqeKrRrRXQNY";
    const N4: &str = "14ktrCvJgDmBGRrXymoVRQuaskj4y5Z5PDcy5D31asvbN1QX";
    const N5: &str = "14ghKTz5mjZPgGYvgVC9VnFw1HYZmmsnYvSSHFgFTJfMvwQS";
    const N6: &str = "14oTqhVovqnamxu2SiP79WfJMvhRRwiF4d2Hjs25d4SDQNjJ";

    fn sample(inactive: &str) -> String {
        format!(
            r#"{{"nominators": [{{
              "address": "{N1}",
              "stake": "243.6991826599 DOT",
              "active_validators": [{{ "validator": "{V1}", "allocated_stake": "243.6991826599 DOT" }}],
              "inactive_validators": {inactive},
              "waiting_validators": ["{W1}"]
            }}]}}"#
        )
    }

    #[test]
    fn it_reads_target_from_file_name() {
        let target = |name: &str| target_from_path(&PathBuf::from(name)).ok();
        assert_eq!(target("nominators_prediction_500.json"), Some(500));
        assert_eq!(target("/tmp/a/nominators_320.json"), Some(320));
        assert_eq!(target("500.json"), Some(500));
        assert_eq!(target("nominators_prediction.json"), None);
        assert_eq!(target("nominators_prediction_0.json"), None);
    }

    #[test]
    fn it_parses_nominators_prediction() {
        let p =
            NominatorsPrediction::from_slice(sample("[]").as_bytes(), 500, 0, "DOT", 10).unwrap();
        assert_eq!(p.target_validators, 500);
        let n = &p.entries[0].nominator;
        assert_eq!(n.stake, Planck(2_436_991_826_599));
        assert_eq!(n.active_validators.len(), 1);
        assert_eq!(
            n.active_validators[0].allocated_stake,
            Planck(2_436_991_826_599)
        );
        assert!(n.address.starts_with('5') && n.waiting_validators[0].starts_with('5'));
        assert!(n.inactive_validators.is_empty());
    }

    #[test]
    fn it_parses_inactive_validators_as_addresses() {
        let inactive = format!(r#"["{V2}"]"#);
        let p = NominatorsPrediction::from_slice(sample(&inactive).as_bytes(), 1, 0, "DOT", 10)
            .unwrap();
        let n = &p.entries[0].nominator;
        assert_eq!(n.inactive_validators.len(), 1);
        assert!(n.inactive_validators[0].starts_with('5'));
        let bad = sample(r#"["nope"]"#);
        assert!(NominatorsPrediction::from_slice(bad.as_bytes(), 1, 0, "DOT", 10).is_err());
    }

    #[test]
    fn it_computes_metadata() {
        let nominator = |n: &str, stake: &str, active: &str, inactive: &str, waiting: &str| {
            format!(
                r#"{{"address":"{n}","stake":"{stake} DOT","active_validators":{active},"inactive_validators":{inactive},"waiting_validators":{waiting}}}"#
            )
        };
        let active =
            |stake: &str| format!(r#"[{{"validator":"{V1}","allocated_stake":"{stake} DOT"}}]"#);
        let list = format!(r#"["{V2}"]"#);
        let nominators = [
            nominator(N1, "10", &active("4"), "[]", "[]"),
            nominator(N2, "20", &active("6"), &list, &list),
            nominator(N3, "1", "[]", "[]", &list),
            nominator(N4, "2", "[]", &list, &list),
            nominator(N5, "3", "[]", &list, "[]"),
            nominator(N6, "4", "[]", "[]", "[]"),
        ];
        let json = format!(r#"{{"nominators":[{}]}}"#, nominators.join(","));
        let p = NominatorsPrediction::from_slice(json.as_bytes(), 500, 77, "DOT", 10).unwrap();
        let m = p.metadata;
        let dot = |v: u128| Planck(v * 10_000_000_000);
        assert_eq!(p.target_validators, 500);
        assert_eq!(m.timestamp, 77);
        assert_eq!(m.nominators_counter, 6);
        assert_eq!(m.active_counter, 2);
        // N4 has inactive and waiting validators, inactive takes precedence
        assert_eq!(m.inactive_only_counter, 2);
        assert_eq!(m.waiting_only_counter, 1);
        assert_eq!(m.no_nominations_counter, 1);
        assert_eq!(
            m.active_counter
                + m.waiting_only_counter
                + m.inactive_only_counter
                + m.no_nominations_counter,
            m.nominators_counter
        );
        assert_eq!(m.total_stake, dot(40));
        assert_eq!(m.active_stake, dot(10));
        assert_eq!(m.idle_stake, dot(10));
    }

    #[test]
    fn it_tells_the_status_of_a_nominator() {
        let nominator = |active: bool, inactive: bool, waiting: bool| NominatorPrediction {
            address: N1.into(),
            stake: Planck(1),
            active_validators: if active {
                vec![NominatorAllocation {
                    address: V1.into(),
                    allocated_stake: Planck(1),
                }]
            } else {
                vec![]
            },
            inactive_validators: if inactive { vec![V2.into()] } else { vec![] },
            waiting_validators: if waiting { vec![W1.into()] } else { vec![] },
        };
        assert_eq!(
            nominator(true, true, true).status(),
            NominatorStatus::Active
        );
        assert_eq!(
            nominator(false, true, true).status(),
            NominatorStatus::Inactive
        );
        assert_eq!(
            nominator(false, false, true).status(),
            NominatorStatus::Waiting
        );
        assert_eq!(
            nominator(false, false, false).status(),
            NominatorStatus::NoNominations
        );
        let names: Vec<_> = NominatorStatus::ALL.iter().map(|s| s.to_string()).collect();
        assert_eq!(names, vec!["active", "inactive", "waiting", "none"]);
        assert_eq!(
            serde_json::from_str::<NominatorStatus>("\"waiting\"").unwrap(),
            NominatorStatus::Waiting
        );
        assert!(serde_json::from_str::<NominatorStatus>("\"bogus\"").is_err());
    }

    #[test]
    fn it_rejects_invalid_account() {
        let bad = sample("[]").replace(W1, "nope");
        assert!(NominatorsPrediction::from_slice(bad.as_bytes(), 1, 0, "DOT", 10).is_err());
    }
}
