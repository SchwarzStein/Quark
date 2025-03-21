// Copyright (c) 2021 Quark Container Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use GLOBAL_ALLOCATOR;
use crate::drivers::tee::attestation::AttestationDriverT;
use crate::drivers::tee::attestation::{Challenge, Report};
use crate::qlib::addr;
use crate::qlib::linux_def::SysErr;
use crate::{Result, Error};

use alloc::vec::Vec;
use tdx_tdcall;
use tdx_tdcall::tdx::PAGE_SIZE_4K;

#[derive(Default, Serialize)]
pub struct TdxAttestation;

#[repr(C, packed)]
#[derive(Debug, Clone)]
struct TdxQuoteBuffer {
    version: u64,
    status: u64,
    input_len: u32,
    output_len: u32,
    report_buf: [u8; TdxQuoteBuffer::QUOTE_BODY_SIZE],
}

impl TdxQuoteBuffer {
    const REPORT_LENGTH: u32 = 1024u32;
    const QUOTE_SIZE: usize = 2 * PAGE_SIZE_4K as usize ;
    const QUOTE_HDR_SIZE: usize = (2 * 8) +(2 * 4);
    const QUOTE_BODY_SIZE: usize = TdxQuoteBuffer::QUOTE_SIZE - TdxQuoteBuffer::QUOTE_HDR_SIZE;
    const GET_QUOTE_CMD_VERS: u64 = 1u64;
    const GET_QUOTE_STATUS_SUCCESS: u64 = 0u64;
    const GET_QUOTE_STATUS_IN_FLIGHT: u64 = 0xFFFF_FFFF_FFFF_FFFF;

    fn alloc_quote_buffer(report_buf: Vec<u8>) -> Result<&'static mut TdxQuoteBuffer> {
        let shared_buf_addr: *mut u8 = unsafe {
            GLOBAL_ALLOCATOR.AllocSharedBuf(TdxQuoteBuffer::QUOTE_SIZE, PAGE_SIZE_4K as usize)
        };
        let _self = unsafe {
           &mut *(shared_buf_addr as *mut TdxQuoteBuffer)
        };
        if addr::Addr(shared_buf_addr as u64).IsPageAligned() == false {
            _self.drop_me();
            error!("VM: buffer is not page alligned for tdx-quote");
            return Err(Error::SystemErr(SysErr::ENOMEM));
        }

        _self.version = Self::GET_QUOTE_CMD_VERS;
        _self.status = Self::GET_QUOTE_STATUS_IN_FLIGHT;
        _self.input_len = Self::REPORT_LENGTH;
        _self.output_len = 0u32;
        assert_eq!(report_buf.len(), Self::REPORT_LENGTH as usize, "Report length not as expected");
        unsafe {
            core::ptr::copy_nonoverlapping(report_buf.as_ptr(),
                _self.report_buf.as_mut_ptr(), Self::REPORT_LENGTH as usize);
        }
        let _pad = [0u8; Self::QUOTE_SIZE - (Self::QUOTE_HDR_SIZE + Self::REPORT_LENGTH as usize)];
        _self.report_buf[(Self::REPORT_LENGTH as usize)..].copy_from_slice(&_pad);

        Ok(_self)
    }

    fn as_mut_slice(&mut self) -> & mut [u8] {
        let ptr = self as *mut _ as *mut u8;
        unsafe {
            core::slice::from_raw_parts_mut(ptr, Self::QUOTE_SIZE)
        }
    }

    fn drop_me(&mut self) {
        debug!("Drop Quote Page");
        let ptr = self as *mut _ as *mut u8;
        unsafe {
            GLOBAL_ALLOCATOR.DeallocShareBuf(ptr, Self::QUOTE_SIZE as usize, PAGE_SIZE_4K as usize);
        }
    }
}

impl TdxAttestation {
    const CHALLENGE_LENGTH: usize = 64;
}

impl AttestationDriverT for TdxAttestation {
    fn get_report(&mut self, _challenge: &Challenge) -> Result<Report> {
        let mut challenge: [u8; Self::CHALLENGE_LENGTH] = [0u8; Self::CHALLENGE_LENGTH];
        challenge.copy_from_slice(&_challenge);

        let _res: Vec<u8> = tdx_tdcall::tdreport::tdcall_report(&challenge)
            .expect("report from tdcall")
            .as_bytes()
            .to_vec();

        debug!("Received Report:{:?}", _res);
        let mut quote_buffer = TdxQuoteBuffer::alloc_quote_buffer(_res)
            .expect("VM: Failed to create quote buffer for attestation.");
        let mut buffer_as_slice = quote_buffer.as_mut_slice();
        let _ = tdx_tdcall::tdx::tdvmcall_get_quote(&mut buffer_as_slice)
            .map_err(|e| panic!("VM: tdx quote request failed with {:?}", e));
        let _quote = quote_buffer.report_buf.as_mut_slice();
        let _quote: Vec<u8> = Vec::from(_quote);
        if quote_buffer.status != TdxQuoteBuffer::GET_QUOTE_STATUS_SUCCESS {
            panic!("VM: Received quote with bad status: {:?}", quote_buffer);
        }
        quote_buffer.drop_me();
        debug!("Quote_Vec:{:?}", _quote);
        Ok(_quote)
    }
}
