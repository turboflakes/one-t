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
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

#[derive(Debug, Clone)]
pub struct PendingFile {
    pub path: PathBuf,
    pub modified: SystemTime,
}

/// Lists the `*.json` files in `dir` ordered from oldest to newest, so that when two
/// files share the same `desired_validators` the newest one is cached last and wins.
/// Files modified less than `min_age` ago are skipped since the producer may still
/// be writing them.
pub fn read_pending_files(
    dir: &Path,
    min_age: Duration,
) -> Result<Vec<PendingFile>, PredictionError> {
    let now = SystemTime::now();
    let mut files: Vec<PendingFile> = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let modified = fs::metadata(&path)?.modified()?;
        if now.duration_since(modified).unwrap_or_default() < min_age {
            continue;
        }
        files.push(PendingFile { path, modified });
    }
    files.sort_by_key(|f| f.modified);
    Ok(files)
}

/// Deletes a file after it has been successfully cached.
pub fn remove_file(path: &Path) -> Result<(), PredictionError> {
    fs::remove_file(path)?;
    Ok(())
}

/// Renames an unparseable file to `<name>.failed` so it is neither retried forever nor lost.
pub fn discard_failed_file(path: &Path) -> Result<PathBuf, PredictionError> {
    let mut name = path.as_os_str().to_owned();
    name.push(".failed");
    let target = PathBuf::from(name);
    fs::rename(path, &target)?;
    Ok(target)
}
