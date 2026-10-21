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
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, path::Path, str::FromStr};
use subxt::utils::AccountId32;

pub type TargetValidators = u32;

/// Amount expressed in the smallest chain unit (planck).
///
/// Serialized as a decimal string so that clients with limited integer
/// precision (e.g. JavaScript) can safely handle values above 2^53.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Planck(pub u128);

impl Planck {
    /// Parses an amount like `"2700000 DOT"` or `"1234.5678 DOT"` into planck.
    pub fn parse(value: &str, symbol: &str, decimals: u32) -> Result<Self, PredictionError> {
        let invalid = |reason: &str| PredictionError::InvalidStake(value.into(), reason.into());
        let mut parts = value.split_whitespace();
        let (amount, unit) = match (parts.next(), parts.next(), parts.next()) {
            (Some(amount), Some(unit), None) => (amount, unit),
            _ => return Err(invalid("expected '<amount> <unit>'")),
        };
        if !unit.eq_ignore_ascii_case(symbol) {
            return Err(invalid(&format!("expected unit {}", symbol)));
        }
        let (int_part, frac_part) = amount.split_once('.').unwrap_or((amount, ""));
        if int_part.is_empty()
            || !int_part.bytes().all(|b| b.is_ascii_digit())
            || !frac_part.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(invalid("amount is not a decimal number"));
        }
        if frac_part.len() > decimals as usize {
            return Err(invalid("too many decimal places"));
        }
        let scale = 10u128
            .checked_pow(decimals)
            .ok_or_else(|| invalid("decimals out of range"))?;
        let int_planck = int_part
            .parse::<u128>()
            .ok()
            .and_then(|v| v.checked_mul(scale))
            .ok_or_else(|| invalid("amount overflow"))?;
        let frac_planck = if frac_part.is_empty() {
            0
        } else {
            let padded = format!("{:0<width$}", frac_part, width = decimals as usize);
            padded
                .parse::<u128>()
                .map_err(|_| invalid("invalid fraction"))?
        };
        int_planck
            .checked_add(frac_planck)
            .map(Planck)
            .ok_or_else(|| invalid("amount overflow"))
    }
}

impl fmt::Display for Planck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for Planck {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for Planck {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PlanckVisitor;
        impl<'de> de::Visitor<'de> for PlanckVisitor {
            type Value = Planck;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a planck amount as string or unsigned integer")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Planck, E> {
                Ok(Planck(v as u128))
            }
            fn visit_u128<E: de::Error>(self, v: u128) -> Result<Planck, E> {
                Ok(Planck(v))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Planck, E> {
                v.parse::<u128>().map(Planck).map_err(E::custom)
            }
        }
        deserializer.deserialize_any(PlanckVisitor)
    }
}

/// Reads a raw JSON number as u128. `deserialize_any` would turn integers
/// above u64::MAX into lossy floats, so ask for u128 explicitly.
fn deserialize_json_u128<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
    struct U128Visitor;
    impl<'de> de::Visitor<'de> for U128Visitor {
        type Value = u128;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("an unsigned integer")
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<u128, E> {
            Ok(v as u128)
        }
        fn visit_u128<E: de::Error>(self, v: u128) -> Result<u128, E> {
            Ok(v)
        }
    }
    deserializer.deserialize_u128(U128Visitor)
}

fn deserialize_timestamp<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumOrStr {
        Num(u64),
        Str(String),
    }
    match NumOrStr::deserialize(deserializer)? {
        NumOrStr::Num(v) => Ok(v),
        NumOrStr::Str(v) => v.trim().parse().map_err(de::Error::custom),
    }
}

#[derive(Deserialize)]
struct RawSolutionScore {
    #[serde(deserialize_with = "deserialize_json_u128")]
    minimal_stake: u128,
    #[serde(deserialize_with = "deserialize_json_u128")]
    sum_stake: u128,
    #[serde(deserialize_with = "deserialize_json_u128")]
    sum_stake_squared: u128,
}

#[derive(Deserialize)]
struct RawMetadata {
    #[serde(deserialize_with = "deserialize_timestamp")]
    timestamp: u64,
    #[serde(rename = "desired_validators")]
    target_validators: TargetValidators,
    round: u32,
    block_number: u32,
    solution_score: RawSolutionScore,
    #[serde(default)]
    data_source: String,
}

#[derive(Deserialize)]
struct RawNominator {
    address: String,
    allocated_stake: String,
}

#[derive(Deserialize)]
struct RawResult {
    account: String,
    total_stake: String,
    self_stake: String,
    nominator_count: u32,
    #[serde(default)]
    nominators: Vec<RawNominator>,
}

#[derive(Deserialize)]
struct RawPrediction {
    metadata: RawMetadata,
    results: Vec<RawResult>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct SolutionScore {
    pub minimal_stake: Planck,
    pub sum_stake: Planck,
    pub sum_stake_squared: Planck,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Default)]
pub struct PredictionMetadata {
    pub timestamp: u64,
    pub target_validators: TargetValidators,
    pub round: u32,
    pub block_number: u32,
    pub solution_score: SolutionScore,
    pub data_source: String,
    pub validators_count: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PredictionValidator {
    pub address: String,
    pub total_stake: Planck,
    pub own_stake: Planck,
    pub nominators_counter: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PredictionNominator {
    pub address: String,
    pub allocated_stake: Planck,
}

/// A validator prediction along with its (potentially large) nominator list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredictionEntry {
    pub account_id: AccountId32,
    pub validator: PredictionValidator,
    pub nominators: Vec<PredictionNominator>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prediction {
    pub metadata: PredictionMetadata,
    pub entries: Vec<PredictionEntry>,
}

impl Prediction {
    /// Parses and validates a prediction file. Stakes must be expressed in `symbol`
    /// and are converted to planck using `decimals`.
    pub fn from_slice(bytes: &[u8], symbol: &str, decimals: u32) -> Result<Self, PredictionError> {
        let raw: RawPrediction = serde_json::from_slice(bytes)?;
        if raw.metadata.target_validators == 0 {
            return Err(PredictionError::Other(
                "target_validators must be greater than zero".into(),
            ));
        }

        let mut entries: Vec<PredictionEntry> = Vec::with_capacity(raw.results.len());
        for result in raw.results {
            let account_id = parse_account(&result.account)?;
            let mut nominators = Vec::with_capacity(result.nominators.len());
            for n in result.nominators {
                let nominator_id = parse_account(&n.address)?;
                nominators.push(PredictionNominator {
                    address: nominator_id.to_string(),
                    allocated_stake: Planck::parse(&n.allocated_stake, symbol, decimals)?,
                });
            }
            entries.push(PredictionEntry {
                account_id,
                validator: PredictionValidator {
                    address: account_id.to_string(),
                    total_stake: Planck::parse(&result.total_stake, symbol, decimals)?,
                    own_stake: Planck::parse(&result.self_stake, symbol, decimals)?,
                    nominators_counter: result.nominator_count,
                },
                nominators,
            });
        }

        let score = raw.metadata.solution_score;
        Ok(Prediction {
            metadata: PredictionMetadata {
                timestamp: raw.metadata.timestamp,
                target_validators: raw.metadata.target_validators,
                round: raw.metadata.round,
                block_number: raw.metadata.block_number,
                solution_score: SolutionScore {
                    minimal_stake: Planck(score.minimal_stake),
                    sum_stake: Planck(score.sum_stake),
                    sum_stake_squared: Planck(score.sum_stake_squared),
                },
                data_source: raw.metadata.data_source,
                validators_count: entries.len() as u32,
            },
            entries,
        })
    }

    pub fn from_path(path: &Path, symbol: &str, decimals: u32) -> Result<Self, PredictionError> {
        Self::from_slice(&std::fs::read(path)?, symbol, decimals)
    }
}

fn parse_account(value: &str) -> Result<AccountId32, PredictionError> {
    AccountId32::from_str(value).map_err(|_| PredictionError::InvalidAccount(value.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACC_A: &str = "1NghFPwbVjAuUaRt82b4tHD89X21CpA9da9sqeKrRrRXQNY";
    const ACC_B: &str = "14ktrCvJgDmBGRrXymoVRQuaskj4y5Z5PDcy5D31asvbN1QX";

    fn sample() -> String {
        format!(
            r#"{{
              "metadata": {{
                "timestamp": "1792496043",
                "desired_validators": 500,
                "round": 348,
                "block_number": 22064642,
                "solution_score": {{
                  "minimal_stake": 16025026056650933,
                  "sum_stake": 9004684937804830028,
                  "sum_stake_squared": 162962392842216677225535599941316522
                }},
                "data_source": "staking"
              }},
              "results": [{{
                "account": "{ACC_A}",
                "total_stake": "2700000 DOT",
                "self_stake": "100000.5 DOT",
                "nominator_count": 1,
                "nominators": [{{ "address": "{ACC_B}", "allocated_stake": "100000 DOT" }}]
              }}]
            }}"#
        )
    }

    #[test]
    fn it_parses_planck() {
        assert_eq!(
            Planck::parse("1 DOT", "DOT", 10).unwrap(),
            Planck(10_000_000_000)
        );
        assert_eq!(
            Planck::parse("0.0000000001 DOT", "DOT", 10).unwrap(),
            Planck(1)
        );
        assert_eq!(
            Planck::parse("2700000 DOT", "DOT", 10).unwrap(),
            Planck(27_000_000_000_000_000)
        );
        assert!(Planck::parse("1 KSM", "DOT", 10).is_err());
        assert!(Planck::parse("1.00000000001 DOT", "DOT", 10).is_err());
        assert!(Planck::parse("-1 DOT", "DOT", 10).is_err());
        assert!(Planck::parse("DOT", "DOT", 10).is_err());
    }

    #[test]
    fn it_parses_prediction_file() {
        let p = Prediction::from_slice(sample().as_bytes(), "DOT", 10).unwrap();
        assert_eq!(p.metadata.timestamp, 1792496043);
        assert_eq!(p.metadata.target_validators, 500);
        assert_eq!(p.metadata.validators_count, 1);
        assert_eq!(
            p.metadata.solution_score.sum_stake_squared,
            Planck(162962392842216677225535599941316522)
        );
        assert_eq!(
            p.entries[0].validator.own_stake,
            Planck(1_000_005_000_000_000)
        );
        assert_eq!(p.entries[0].nominators.len(), 1);
        // addresses are normalized to the same format served by the other endpoints
        assert_eq!(
            p.entries[0].validator.address,
            p.entries[0].account_id.to_string()
        );
        assert!(p.entries[0].validator.address.starts_with('5'));
        assert!(p.entries[0].nominators[0].address.starts_with('5'));
    }

    #[test]
    fn it_round_trips_planck_as_string() {
        let json = serde_json::to_string(&Planck(u128::MAX)).unwrap();
        assert_eq!(json, format!("\"{}\"", u128::MAX));
        assert_eq!(
            serde_json::from_str::<Planck>(&json).unwrap(),
            Planck(u128::MAX)
        );
    }

    #[test]
    fn it_rejects_invalid_account() {
        let bad = sample().replace(ACC_A, "not-an-account");
        assert!(Prediction::from_slice(bad.as_bytes(), "DOT", 10).is_err());
    }
}
