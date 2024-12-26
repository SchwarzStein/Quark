// Copyright (c) 2021 Quark Container Authors / 2018 The gVisor Authors.
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

#[cfg(target_arch = "x86_64")]
#[cfg(feature = "snp")]
#[path = "./x86_64/tee/sev_snp/mod.rs"]
pub mod sev_snp;
#[cfg(target_arch = "aarch64")]
#[path = "./aarch64/tee/realm.rs"]
pub mod realm;

//NOTE: When x86 comes with its own implementation, we will
//      remove the arch-guards inside the functions.
#[cfg(target_arch = "aarch64")]
use self::realm as _tee;

use core::sync::atomic::{AtomicU8, Ordering};
use lazy_static::lazy_static;
use crate::qlib::linux_def::MemoryDef;
use crate::qlib::config::CCMode;
use crate::qlib::common::{Result, Error};
use crate::qlib::SysErr;
use crate::qlib::QRwLock;
use crate::qlib::range::Range;
use alloc::vec::Vec;

lazy_static! {
    //TODO: It should be only set once
    static ref TEE_TYPE: AtomicU8 = AtomicU8::new(CCMode::None as u8);
}

/// Sets TEE_TYPE to a valid TEE CCMode, if not previously set.
pub fn set_tee_type(mode: CCMode) {
    static mut SET: bool = false;
    match mode {
        CCMode::None => return,
        _ => {
            // We care only for the first write by vCPU0
            unsafe {
                if SET == false {
                    TEE_TYPE.store(mode as u8, Ordering::Relaxed);
                    SET = true;
                }
            }
        }
    }
}

/// It return the CC-mode the kernel is running.
pub fn get_tee_type() -> CCMode {
    let mode = TEE_TYPE.load(Ordering::Relaxed);
    CCMode::from(mode as u64)
}

/// It returns true only if the CC-mode is backed by real HW
pub fn is_hw_tee() -> bool {
    let mode = TEE_TYPE.load(Ordering::Relaxed) as u64;
    CCMode::tee_backedup(mode)
}

pub fn is_cc_active() -> bool {
    let mode = CCMode::from(TEE_TYPE.load(Ordering::Acquire) as u64);
    match mode {
        CCMode::None => { return false; }
        _ => { return true; }
    }
}

/// Depending on TEE architecture, the guest physical address should be
/// marked as shared("untrusted")/private("trusted"). The actual set/unset
/// bit(s) on the GPA is implementation defined by the particular TEE.
pub fn gpa_adjust_shared_bit(_address: &mut u64, _protect: bool) {
    if is_hw_tee() {
        match get_tee_type() {
            #[cfg(all(target_arch = "x86_64", feature = "tdx"))]
            CCMode::TDX => {
                let shared_bit_mask = crate::qlib::cc::tdx::get_sbit_mask();
                if _protect == false {
                    *_address |= shared_bit_mask;
                } else {
                    *_address &= !shared_bit_mask;
                }
            },
            #[cfg(all(target_arch = "x86_64", feature = "snp"))]
            CCMode::SevSnp => {
                let encrypt_bit_mask = sev_snp::C_BIT_MASK.load(Ordering::Acquire);
                if _protect == true {
                    *_address |= encrypt_bit_mask;
                } else {
                    *_address &= encrypt_bit_mask - 1;
                }
            },
            #[cfg(target_arch = "aarch64")]
            CCMode::Cca => {
                _tee::ipa_adjust(_address, _protect);
            },
            _ => {
                todo!("Unhandled");
            }
        };
    }
}

/// Before the guest can reason on a GPA, the information on the IPA that
/// regards the TEE should be removed.
pub fn guest_physical_address(ipa_address: u64) -> u64 {
    #![allow(unused_mut)]
    let mut address_guest = ipa_address;
    if is_hw_tee() {
        match get_tee_type() {
            #[cfg(all(target_arch = "x86_64", feature = "tdx"))]
            CCMode::TDX => {
                let shared_bit_mask = crate::qlib::cc::tdx::get_sbit_mask();
                address_guest &= !shared_bit_mask;
            },
            #[cfg(all(target_arch = "x86_64", feature = "snp"))]
            CCMode::SevSnp => {
                let encrypt_bit_mask = sev_snp::C_BIT_MASK.load(Ordering::Acquire);
                address_guest &= encrypt_bit_mask - 1;
            },
            #[cfg(target_arch = "aarch64")]
            CCMode::Cca => {
                _tee::unset_shared_bit(&mut address_guest);
            },
            _ => {
                todo!("Unhandled");
            }
        };
    }
    address_guest
}

/// For Guest Physical Address
pub fn is_protected_address(gpa: u64) -> bool {
    let mut res = true;
    #[cfg(target_arch = "aarch64")]
    if gpa == MemoryDef::HYPERCALL_MMIO_BASE {
        res = false;
    }
    if (gpa >= MemoryDef::FILE_MAP_OFFSET &&
        gpa < MemoryDef::FILE_MAP_OFFSET + MemoryDef::FILE_MAP_SIZE)
        || (gpa >= MemoryDef::GUEST_HOST_SHARED_HEAP_OFFSET &&
        gpa < MemoryDef::GUEST_HOST_SHARED_HEAP_END  + MemoryDef::IO_HEAP_SIZE) {
            res = false;
    }
    res
}

/// Usage: On aarch64-Realm - invoke Hypercall
/// NOTE: Unstable signature - may change in the future.
pub fn call_host(_hcall_type: u64, _arg1: u64, _arg2: u64, _arg3: u64, _arg4: u64) {
    #[cfg(target_arch = "aarch64")]
    _tee::rsi::RsiHostCall::rsi_host_call(_hcall_type, _arg1, _arg2, _arg3, _arg4);
}

/// Entry call to the booting flow of other vCPUS.
/// Internals are architecture depended.
pub fn boot_others(_boot_help_data: u64, _vcpu_count: u64, _pc: u64) {
    #[cfg(target_arch = "aarch64")]
    _tee::psci::cpu_on(_boot_help_data as *const u64, _vcpu_count, _pc);
}

lazy_static! {
    //
    //NOTE: The ranges may differ between Snp / TDX / CCA
    //

    //
    // Only Snp / TDX
    //
    static ref FMAP_ACCESSED: [QRwLock<u128>; 6] = [QRwLock::new(0), QRwLock::new(0),
        QRwLock::new(0), QRwLock::new(0), QRwLock::new(0),
        QRwLock::new(0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_7000)];
    //
    //NOTE: The lower half represents the guest private heap - the upper half the host shared.
    //  Access to guest allocator is synchronized.
    // TDX | SevSnp
    // a) The first 1200MB of guest heap are initialized.
    // b) The first 192MB of host shared heap are initialized.
   // // CCA
   // // a) The first 256MB of guest heap are initialized.
   // // The IOHeap is fully initialized and not represented here.
    static ref HEAP_ACCESSED: [QRwLock<u64>; 10] = [
        #[cfg(target_arch = "x86_64")]
        QRwLock::new(0xFFFF_FFFF_FFFF_FFFF), // 1GB
        #[cfg(target_arch = "x86_64")]
        QRwLock::new(0xFFE0_0000_0000_0000),
        #[cfg(target_arch = "aarch64")]
        QRwLock::new(0xF000_0000_0000_0000), // 64MB
        #[cfg(target_arch = "aarch64")]
        QRwLock::new(0x0000_0000_0000_0000),
        QRwLock::new(0x0000_0000_0000_0000),
        QRwLock::new(0x0000_0000_0000_0000),
        QRwLock::new(0x0000_0000_0000_0000), //End of guest heap
        QRwLock::new(0xFFF0_0000_0000_0000),
        QRwLock::new(0x0000_0000_0000_0000),
        QRwLock::new(0x0000_0000_0000_0000),
        QRwLock::new(0x0000_0000_0000_0000),
        QRwLock::new(0x0000_0000_0000_0000)];
}

#[cfg(target_arch = "aarch64")]
pub const RUNTIME_ACCEPTED_PHEAP: u64 = 16 * MemoryDef::ONE_MB;
#[cfg(target_arch = "x86_64")]
pub const RUNTIME_ACCEPTED_PHEAP: u64 = 176 * MemoryDef::ONE_MB;
#[cfg(target_arch = "x86_64")]
pub const RUNTIME_ACCEPTED_SHEAP: u64 = 192 * MemoryDef::ONE_MB;


const CONVERT_GPA_AREAS: [GpaArea; 3] = [
    GpaArea::FlMap(MemoryDef::FILE_MAP_OFFSET, MemoryDef::FILE_MAP_SIZE),
    GpaArea::PrvHeap(MemoryDef::GUEST_PRIVATE_INIT_HEAP_OFFSET,
    MemoryDef::GUEST_PRIVATE_HEAP_SIZE),
    GpaArea::ShrdHeap(MemoryDef::GUEST_HOST_SHARED_HEAP_OFFSET,
    MemoryDef::GUEST_HOST_SHARED_HEAP_SIZE)];

enum GpaArea {
    FlMap(u64, u64),
    PrvHeap(u64, u64),
    ShrdHeap(u64, u64),
}

impl GpaArea {
    fn contains_gpa(&self, gpa: u64) -> bool {
        let res = match self {
            Self::FlMap(s, l) | Self::PrvHeap(s, l) | Self::ShrdHeap(s, l) => {
                let range = Range::New(*s, *l);
                range.Contains(gpa)
            }
        };
        res
    }
}


fn _try_gpa_range_set_fmap(entry: usize, mask: u128, _gpa_address: u64, _npages: u64)
    -> Result<bool> {
    let try_set = {
        let bucket = FMAP_ACCESSED[entry].read();
        (*bucket & mask) == 0u128
    };

    if try_set {
        let mut bucket = FMAP_ACCESSED[entry].write();
        if (*bucket & mask) != 0u128 {
            return Ok(false);
        } else {
            let res = match get_tee_type() {
                #[cfg(all(target_arch = "x86_64", feature = "snp"))]
                CCMode::SevSnp => {
                    sev_snp::tee_try_gpa_range_set(_gpa_address, _npages as usize, true)
                },
                #[cfg(all(target_arch = "x86_64", feature = "tdx"))]
                CCMode::TDX => {
                    use crate::qlib::cc::tdx;
                    tdx::tee_try_gpa_range_set(_gpa_address, _npages, false)
                },
                _ => {
                    Err(Error::SysError(SysErr::EFAULT))
                }
            };
            if res.is_ok() {
                *bucket |= mask;
            }
            return res;
        }
    }
    Ok(false)
}

fn _try_gpa_range_set_heap(entry: usize, mask: u64, _gpa_address: u64, _npages: u64, _to_prv: bool)
    -> Result<bool> {
    let try_set = {
        let bucket = HEAP_ACCESSED[entry].read();
        (*bucket & mask) == 0u64
    };
    if try_set {
        let mut bucket = HEAP_ACCESSED[entry].write();
        if (*bucket & mask) != 0u64 {
            return Ok(false);
        } else {
            let res = match get_tee_type() {
                #[cfg(all(target_arch = "x86_64", feature = "snp"))]
                CCMode::SevSnp => {
                    sev_snp::tee_try_gpa_range_set(_gpa_address, _npages as usize, !_to_prv)
                },
                #[cfg(all(target_arch = "x86_64", feature = "tdx"))]
                CCMode::TDX => {
                    use crate::qlib::cc::tdx;
                    tdx::tee_try_gpa_range_set(_gpa_address, _npages, _to_prv)
                },
                #[cfg(all(target_arch = "aarch64", feature = "qk"))]
                CCMode::Cca => {
                    _tee::rsi::RipasStateReq::set(_gpa_address, _npages, _to_prv)
                },
                _ => {
                    Err(Error::SysError(SysErr::EFAULT))
                },
            };
            if res.is_ok() {
                *bucket |= mask;
            }
            return res;
        }
    }
    Ok(false)
}


fn _set_gpa_range_status(addr: u64, gpa_area: &GpaArea) -> Result<bool> {
    let (npages, bucket_range, bucket_offset, bucket_size, area_start, _to_prv) = match gpa_area {
        GpaArea::FlMap(start, _) => {
            (9, 128 * 9 * MemoryDef::TWO_MB, 0u64, FMAP_ACCESSED.len(), start, false)
        },
        GpaArea::PrvHeap(start, _) => {
            (8, 64 * 8 * MemoryDef::TWO_MB, 0u64, HEAP_ACCESSED.len() / 2, start, true)
        },
        GpaArea::ShrdHeap(start, _) => {
            (8, 64 * 8 * MemoryDef::TWO_MB, (HEAP_ACCESSED.len() / 2) as u64,
                HEAP_ACCESSED.len(), start, false)
        },
    };

    let mut entry = 0;
    let mut mask: u128 = 0x0;
    let mut gpa_address: u64 = 0;
    let range_size = npages * MemoryDef::TWO_MB;
    for i in bucket_offset..bucket_size as u64 {
        let level = i as u64 + 1u64;
        if addr < area_start + (level * bucket_range) {
            entry = i;
            let offset = entry * bucket_range;
            let bit = (addr - (area_start + offset))
                / range_size;
            mask = 1 << bit;
            gpa_address = area_start + offset
                + (bit * range_size);
            debug!("VM: set gpa range: Addr:{:#0x} - BaseAddr:{:#0x} - Entry:{:#0x} - Mask:{:#0x}",
                addr, gpa_address, entry, mask);
            break;
        }
    }

    let res = match gpa_area {
        GpaArea::FlMap(_, _) => {
            if cfg!(target_arch = "x86_64") {
                _try_gpa_range_set_fmap(entry as usize, mask, gpa_address, npages)
            } else {
                Ok(true)
            }
        },
        GpaArea::PrvHeap(_, _) => {
            _try_gpa_range_set_heap(entry as usize, mask as u64, gpa_address, npages, true)
        },
        GpaArea::ShrdHeap(_, _) => {
            if cfg!(target_arch = "x86_64") {
                _try_gpa_range_set_heap(entry as usize, mask as u64, gpa_address, npages, false)
            } else {
                Ok(true)
            }
        }
    };
    res

}

// Request the change of a gpa state for memory area.
pub fn set_gpa_status(addr: u64, as_host_shared: bool) -> Result<bool> {
    if is_protected_address(addr) && as_host_shared {
        error!("VM: Addr:{:#0x} is in predifined protected area - not shareble.", addr);
        return Err(Error::SysError(SysErr::EINVAL));
    }
    for i in 0..CONVERT_GPA_AREAS.len() {
        if CONVERT_GPA_AREAS[i].contains_gpa(addr) {
            return _set_gpa_range_status(addr, &CONVERT_GPA_AREAS[i]);
        }
    }
    error!("VM: Addr:{:#0x} is not in the convertable mem-areas.", addr);

    return Err(Error::SysError(SysErr::EINVAL));
}

pub fn get_attestation(_challenge: &Vec<u8>) -> Result<usize> {
    #[cfg(target_arch = "aarch64")] {
        return _tee::attestation::init_attestation(_challenge);
    }
    #[cfg(not(target_arch = "aarch64"))] {
        todo!();
    }
}

#[cfg(target_arch = "aarch64")]
pub fn get_attestation_continue(_token: &mut Vec<u8>, _buff_addr: u64)
    -> Result<bool> {
    _tee::attestation::attestation_cont(_token, _buff_addr)
}
