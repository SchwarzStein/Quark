// Copyright (c) 2021 Quark Container Authors / 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,x
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    os::fd::FromRawFd,
    sync::{atomic::Ordering, Arc},
};

use kvm_bindings::*;
use kvm_ioctls::{Cap, Kvm, VmFd};

use super::{resources::*, VmType};
use crate::arch::VirtCpu;
use crate::qlib::kernel::arch::tee::sev_snp::cpuid_page::*;
use crate::qlib::kernel::arch::tee::sev_snp::*;
use crate::qlib::kernel::arch::tee::*;
use crate::qlib::kernel::Kernel::ENABLE_CC;
use crate::{
    arch::{
        tee::util::{adjust_addr_to_guest, adjust_addr_to_host, get_offset},
        vm::vcpu::ArchVirtCpu,
    },
    elf_loader::KernelELF,
    kvm_vcpu::KVMVcpu,
    print::LOG,
    qlib::{
        addr::{Addr, PageOpts},
        common::Error,
        kernel::{
            kernel::{futex, timer},
            vcpu::CPU_LOCAL,
            SHARESPACE,
        },
        linux_def::MemoryDef,
        pagetable::PageTables,
        ShareSpace,
    },
    runc::runtime::{
        loader::Args,
        vm::{self, VirtualMachine},
    },
    tsot_agent::TSOT_AGENT,
    CCMode, VMSpace, KERNEL_IO_THREAD, PMA_KEEPER, QUARK_CONFIG, ROOT_CONTAINER_ID, SHARE_SPACE,
    URING_MGR, VMS,
};

#[derive(Debug)]
pub struct VmSevSnp {
    vm_resources: VmResources,
    entry_address: u64,
    vdso_address: u64,
}

impl VmType for VmSevSnp {
    fn init(args: Option<&Args>) -> Result<(Box<dyn VmType>, KernelELF), Error> {
        if !check_amd() || !check_snp_support() {
            return Err(Error::CCModeError);
        }
        ENABLE_CC.store(true, Ordering::Release);
        set_tee_type(CCMode::SevSnp);
        set_cbit_mask();
        todo!()
    }

    fn create_vm(
        self: Box<VmSevSnp>,
        kernel_elf: KernelELF,
        args: Args,
    ) -> Result<VirtualMachine, Error> {
        todo!()
    }

    fn vm_space_initialize(&self, vcpu_count: usize, args: Args) -> Result<(), Error> {
        todo!()
    }

    fn vm_memory_initialize(&mut self, vm_fd: &VmFd) -> Result<(), Error> {
        todo!()
    }

    fn create_kvm_vm(&mut self, kvm_fd: i32) -> Result<(Kvm, VmFd), Error> {
        todo!()
    }

    fn init_share_space(
        vcpu_count: usize,
        control_sock: i32,
        rdma_svc_cli_sock: i32,
        pod_id: [u8; 64],
        share_space_addr: Option<u64>,
        _has_global_mem_barrier: Option<bool>,
    ) -> Result<(), Error> {
        todo!()
    }

    fn vm_vcpu_initialize(
        &self,
        kvm: &Kvm,
        vm_fd: &VmFd,
        total_vcpus: usize,
        entry_addr: u64,
        auto_start: bool,
        page_allocator_addr: Option<u64>,
        share_space_addr: Option<u64>,
    ) -> Result<Vec<Arc<ArchVirtCpu>>, Error> {
        todo!()
    }

    fn post_vm_initialize(&mut self, _vm_fd: &mut VmFd) -> Result<(), Error> {
        todo!()
    }

    fn post_init_update(&mut self, _vm_fd: &mut VmFd) -> Result<(), Error> {
        todo!()
    }

    fn get_type(&self) -> CCMode {
        todo!()
    }
}

impl CpuidPage {
    pub fn FillCpuidPage(&mut self, kvm_cpuid_entries: &CpuId) -> Result<(), Error> {
        let mut has_entries = false;

        for kvm_entry in kvm_cpuid_entries.as_slice() {
            if kvm_entry.function == 0 && kvm_entry.index == 0 && has_entries {
                break;
            }

            if kvm_entry.function == 0xFFFFFFFF {
                break;
            }

            // range check, see:
            // SEV Secure Nested Paging Firmware ABI Specification
            // 8.17.2.6 PAGE_TYPE_CPUID
            if !((0x0000_0000..=0x0000_FFFF).contains(&kvm_entry.function)
                || (0x8000_0000..=0x8000_FFFF).contains(&kvm_entry.function))
            {
                continue;
            }
            has_entries = true;

            let mut snp_cpuid_entry = SnpCpuidFunc {
                eax_in: kvm_entry.function,
                ecx_in: {
                    if (kvm_entry.flags & KVM_CPUID_FLAG_SIGNIFCANT_INDEX) != 0 {
                        kvm_entry.index
                    } else {
                        0
                    }
                },
                xcr0_in: 0,
                xss_in: 0,
                eax: kvm_entry.eax,
                ebx: kvm_entry.ebx,
                ecx: kvm_entry.ecx,
                edx: kvm_entry.edx,
                ..Default::default()
            };
            if snp_cpuid_entry.eax_in == 0xD
                && (snp_cpuid_entry.ecx_in == 0x0 || snp_cpuid_entry.ecx_in == 0x1)
            {
                /*
                 * Guest kernels will calculate EBX themselves using the 0xD
                 * subfunctions corresponding to the individual XSAVE areas, so only
                 * encode the base XSAVE size in the initial leaves, corresponding
                 * to the initial XCR0=1 state.
                 */
                snp_cpuid_entry.ebx = 0x240;
                snp_cpuid_entry.xcr0_in = 1;
                snp_cpuid_entry.xss_in = 0;
            }

            self.AddEntry(&snp_cpuid_entry)
                .expect("Failed to add CPUID entry to the CPUID page");
        }
        Ok(())
    }
}

