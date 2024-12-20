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

use core::alloc::Layout;
use alloc::vec::Vec;

use crate::qlib::mem::cc_allocator::GuestHostSharedAllocator;
use crate::PRIVATE_VCPU_ALLOCATOR;
use crate::qlib::linux_def::SysErr;
use crate::{drivers::attestation::AttestationDriverT, GUEST_HOST_SHARED_ALLOCATOR};
use crate::qlib::common::{Result, Error};
use crate::qlib::kernel::arch::tee;
use super::{Responce, Challenge};

#[derive(Default)]
pub(super) struct ArmCcaHwAttester;

pub(super) type TeeAttester = ArmCcaHwAttester;

impl AttestationDriverT for ArmCcaHwAttester {
    fn valid_challenge(challenge: &mut Challenge) -> bool {
        let challenge_len = challenge.len();
        if Self::__out_of_range(challenge_len) {
            return false;
        }
        if Self::__needs_padding(challenge_len) {
            debug!("VM: padd challenge to valid length");
            challenge.resize(Self::CHALLENGE_SIZE, 0);
        }
        true
    }

    fn get_report(&self, challenge: &Challenge) -> Result<Responce> {
        let attestation_token_max_size = tee::get_attestation(challenge)
            .expect("Failed to attest challenge.");
        debug!("VM: Token expected size:{:#0x}", attestation_token_max_size);

        let mut token: Vec<u8, GuestHostSharedAllocator> = Vec::with_capacity_in(attestation_token_max_size,
            GUEST_HOST_SHARED_ALLOCATOR);
        if token.capacity() < attestation_token_max_size {
            return Err(Error::SystemErr(SysErr::ENOMEM));
        }
        let granule_layout = Layout::from_size_align(0x1000, 0x1000)
            .expect("VM: Failed to get layout for granule.");
        let buff_granule_addr = PRIVATE_VCPU_ALLOCATOR.AllocatorMut().alloc(granule_layout) as u64;
        debug!("VM: Alloced buffer granule :{:#0x}", buff_granule_addr);
        if crate::qlib::addr::Addr(buff_granule_addr).IsPageAligned() == false {
            error!("VM: buffer granule is not page alligned:{:#0x}", buff_granule_addr);
            return Err(Error::SystemErr(SysErr::ENOMEM));
        }

        let res = tee::get_attestation_continue(&mut token, buff_granule_addr)?;
        PRIVATE_VCPU_ALLOCATOR.AllocatorMut().dealloc(buff_granule_addr as *mut u8, granule_layout);
        if res == false {
            panic!("VM: Attestation faild - no token retrived");
        }
        Ok(token)
    }
}

impl ArmCcaHwAttester {
    const CHALLENGE_SIZE: usize = 64;
    const MIN_CHALLENGE_SIZE: usize = 32;

    #[inline(always)]
    pub(self) fn __out_of_range(len: usize) -> bool {
        if len < Self::MIN_CHALLENGE_SIZE
        || len > Self::CHALLENGE_SIZE {
            return true;
        }
        false
    }

    #[inline(always)]
    pub(self) fn __needs_padding(len: usize) -> bool {
        if len >= Self::MIN_CHALLENGE_SIZE 
        && len < Self::CHALLENGE_SIZE {
            return true;
        }
        false
    }
}
