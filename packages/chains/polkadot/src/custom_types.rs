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

use codec::{Decode, Encode};

#[derive(Decode, Encode, Debug)]
pub enum PreDigest {
    #[codec(index = 1)]
    Primary(PrimaryPreDigest),
    #[codec(index = 2)]
    SecondaryPlain(SecondaryPlainPreDigest),
    #[codec(index = 3)]
    SecondaryVRF(SecondaryVRFPreDigest),
}

#[derive(Decode, Encode, Debug)]
pub struct PrimaryPreDigest {
    pub authority_index: ::core::primitive::u32,
    pub slot: Slot,
    pub vrf_signature: VrfSignature,
}

#[derive(Decode, Encode, Debug)]
pub struct SecondaryPlainPreDigest {
    pub authority_index: ::core::primitive::u32,
    pub slot: Slot,
}

#[derive(Decode, Encode, Debug)]
pub struct SecondaryVRFPreDigest {
    pub authority_index: ::core::primitive::u32,
    pub slot: Slot,
    pub vrf_signature: VrfSignature,
}

#[derive(Decode, Encode, Debug)]
pub struct Slot(pub ::core::primitive::u64);

#[derive(Decode, Encode, Debug)]
pub struct VrfSignature {
    pub pre_output: [::core::primitive::u8; 32usize],
    pub proof: [::core::primitive::u8; 64usize],
}
