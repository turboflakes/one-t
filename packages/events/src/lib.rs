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

use onet_records::{BlockNumber, Validity};
use serde::{Deserialize, Serialize};

pub type EventIndex = u32;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EventId(BlockNumber, EventIndex);

impl std::fmt::Display for EventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.0, self.1)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Topics {
    AsyncStaking,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Event {
    pub id: EventId,
    pub block_number: BlockNumber,
    pub index: EventIndex,
    pub pallet: String,
    pub name: String,
    pub data: Vec<u8>,
    pub topics: Vec<Topics>,
}

impl Event {
    pub fn new(block_number: BlockNumber, index: EventIndex, pallet: String, name: String) -> Self {
        Self {
            id: EventId(block_number, index),
            pallet,
            name,
            block_number,
            index,
            data: Vec::new(),
            topics: Vec::new(),
        }
    }
}

impl Validity for Event {
    fn is_empty(&self) -> bool {
        self.block_number == 0
    }
}
