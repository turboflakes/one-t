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

/// A validator the nominator stake is (or would be) allocated to. Producers may list
/// inactive validators as bare addresses, in which case there is no allocated stake.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawAllocation {
    Detailed {
        validator: String,
        #[serde(default)]
        allocated_stake: Option<String>,
    },
    Address(String),
}

#[derive(Deserialize)]
struct RawNominator {
    address: String,
    stake: String,
    #[serde(default)]
    active_validators: Vec<RawAllocation>,
    #[serde(default)]
    inactive_validators: Vec<RawAllocation>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocated_stake: Option<Planck>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct NominatorPrediction {
    pub address: String,
    pub stake: Planck,
    pub active_validators: Vec<NominatorAllocation>,
    pub inactive_validators: Vec<NominatorAllocation>,
    pub waiting_validators: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NominatorEntry {
    pub account_id: AccountId32,
    pub nominator: NominatorPrediction,
}

/// Predicted nominations for a given number of target validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NominatorsPrediction {
    pub target_validators: TargetValidators,
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
        symbol: &str,
        decimals: u32,
    ) -> Result<Self, PredictionError> {
        let raw: RawNominatorsPrediction = serde_json::from_slice(bytes)?;

        let mut entries: Vec<NominatorEntry> = Vec::with_capacity(raw.nominators.len());
        for nominator in raw.nominators {
            let account_id = parse_account(&nominator.address)?;
            let allocations =
                |raw: Vec<RawAllocation>| -> Result<Vec<NominatorAllocation>, PredictionError> {
                    raw.into_iter()
                        .map(|a| {
                            let (validator, stake) = match a {
                                RawAllocation::Detailed {
                                    validator,
                                    allocated_stake,
                                } => (validator, allocated_stake),
                                RawAllocation::Address(validator) => (validator, None),
                            };
                            Ok(NominatorAllocation {
                                address: parse_account(&validator)?.to_string(),
                                allocated_stake: stake
                                    .map(|s| Planck::parse(&s, symbol, decimals))
                                    .transpose()?,
                            })
                        })
                        .collect()
                };
            let waiting_validators = nominator
                .waiting_validators
                .iter()
                .map(|v| Ok(parse_account(v)?.to_string()))
                .collect::<Result<Vec<_>, PredictionError>>()?;

            entries.push(NominatorEntry {
                account_id,
                nominator: NominatorPrediction {
                    address: account_id.to_string(),
                    stake: Planck::parse(&nominator.stake, symbol, decimals)?,
                    active_validators: allocations(nominator.active_validators)?,
                    inactive_validators: allocations(nominator.inactive_validators)?,
                    waiting_validators,
                },
            });
        }

        Ok(NominatorsPrediction {
            target_validators,
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
        let p = NominatorsPrediction::from_slice(sample("[]").as_bytes(), 500, "DOT", 10).unwrap();
        assert_eq!(p.target_validators, 500);
        let n = &p.entries[0].nominator;
        assert_eq!(n.stake, Planck(2_436_991_826_599));
        assert_eq!(n.active_validators.len(), 1);
        assert_eq!(
            n.active_validators[0].allocated_stake,
            Some(Planck(2_436_991_826_599))
        );
        assert!(n.address.starts_with('5') && n.waiting_validators[0].starts_with('5'));
        assert!(n.inactive_validators.is_empty());
    }

    #[test]
    fn it_accepts_both_inactive_validator_shapes() {
        let detailed = format!(r#"[{{"validator":"{V2}","allocated_stake":"1 DOT"}}]"#);
        let bare = format!(r#"["{V2}"]"#);
        let a =
            NominatorsPrediction::from_slice(sample(&detailed).as_bytes(), 1, "DOT", 10).unwrap();
        let b = NominatorsPrediction::from_slice(sample(&bare).as_bytes(), 1, "DOT", 10).unwrap();
        assert_eq!(
            a.entries[0].nominator.inactive_validators[0].allocated_stake,
            Some(Planck(10_000_000_000))
        );
        assert_eq!(
            b.entries[0].nominator.inactive_validators[0].allocated_stake,
            None
        );
    }

    #[test]
    fn it_rejects_invalid_account() {
        let bad = sample("[]").replace(W1, "nope");
        assert!(NominatorsPrediction::from_slice(bad.as_bytes(), 1, "DOT", 10).is_err());
    }
}
