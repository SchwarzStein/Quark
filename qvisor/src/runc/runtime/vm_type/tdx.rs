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

use kvm_bindings::kvm_enable_cap;
use kvm_ioctls::{Cap, Kvm, VmFd};

use super::{
    resources::{GuestPrivateMemLayout, MemArea, MemLayoutConfig, VmResources},
    VmType,
};
use crate::arch::VirtCpu;
use crate::qlib::cc::tdx::*;
use crate::qlib::kernel::Kernel::ENABLE_CC;
use crate::qlib::kernel::Kernel::TDX_ENABLED;
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
pub struct TDX {
    vm_resources: VmResources,
    entry_address: u64,
    vdso_address: u64,
}

impl VmType for TDX {
    fn init(args: Option<&Args>) -> Result<(Box<dyn VmType>, KernelELF), Error> {
        if !check_intel() {
            return Err(Error::CCModeError);
        }
        ENABLE_CC.store(true, Ordering::Release);
        TDX_ENABLED.store(true, Ordering::Release);
        todo!()
    }

    fn create_vm(
        self: Box<TDX>,
        kernel_elf: KernelELF,
        args: Args,
    ) -> Result<VirtualMachine, Error> {
        todo!()
    }

    fn vm_space_initialize(&self, vcpu_count: usize, args: Args) -> Result<(), Error> {
        todo!()
    }

    fn vm_memory_initialize(&self, vm_fd: &VmFd) -> Result<(), Error> {
        todo!()
    }

    fn create_kvm_vm(&self, kvm_fd: i32) -> Result<(Kvm, VmFd), Error> {
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

    fn post_memory_initialize(&mut self) -> Result<(), Error> {
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

    fn post_vm_initialize(&mut self) -> Result<(), Error> {
        todo!()
    }

    fn post_init_upadate(&mut self) -> Result<(), Error> {
        todo!()
    }
}
