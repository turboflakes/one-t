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
use scale_decode::DecodeAsType;
use scale_encode::EncodeAsType;

#[derive(Decode, Encode, DecodeAsType, EncodeAsType, Clone, PartialEq, Debug)]
pub struct ExposurePage<_0, _1> {
    pub page_total: _1,
    pub others: Vec<IndividualExposure<_0, _1>>,
}

#[derive(Decode, Encode, DecodeAsType, EncodeAsType, Clone, PartialEq, Debug)]
pub struct IndividualExposure<_0, _1> {
    pub who: _0,
    pub value: _1,
}

#[derive(Decode, Encode, DecodeAsType, EncodeAsType, Clone, PartialEq, Debug)]
pub struct PagedExposureMetadata<_0> {
    pub total: _0,
    pub own: _0,
    pub nominator_count: ::core::primitive::u32,
    pub page_count: ::core::primitive::u32,
}
