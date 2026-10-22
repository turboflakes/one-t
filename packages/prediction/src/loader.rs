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
use crate::nominators::{target_from_path, NominatorsPrediction};
use crate::types::Prediction;
use serde::{de::IgnoredAny, Deserialize};
use std::path::Path;

/// A parsed prediction file. The kind is told by the file's top-level key, so the
/// file name only matters for the target of a nominators file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredictionFile {
    Validators(Prediction),
    Nominators(NominatorsPrediction),
}

#[derive(Deserialize)]
struct Probe {
    #[serde(default)]
    results: Option<IgnoredAny>,
    #[serde(default)]
    nominators: Option<IgnoredAny>,
}

impl PredictionFile {
    pub fn from_path(path: &Path, symbol: &str, decimals: u32) -> Result<Self, PredictionError> {
        let bytes = std::fs::read(path)?;
        let probe: Probe = serde_json::from_slice(&bytes)?;
        match (probe.results, probe.nominators) {
            (Some(_), None) => Ok(Self::Validators(Prediction::from_slice(
                &bytes, symbol, decimals,
            )?)),
            (None, Some(_)) => Ok(Self::Nominators(NominatorsPrediction::from_slice(
                &bytes,
                target_from_path(path)?,
                symbol,
                decimals,
            )?)),
            _ => Err(PredictionError::Other(
                "expected exactly one of the top-level keys `results` or `nominators`".into(),
            )),
        }
    }
}
