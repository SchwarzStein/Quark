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

pub mod emulcc;
pub mod tdx;

use kvm_ioctls::{VcpuExit, VcpuFd, VmFd, Kvm};

use super::ConfCompExtension;
use crate::{qlib::common::Error, CCMode};
use std::os::fd::AsRawFd;

pub struct NonConf<'a> {
    kvm_exits_list: Option<[VcpuExit<'a>; 0]>,
    hypercalls_list: Option<[u16; 0]>,
    pub cc_mode: CCMode,
    pub share_space_table_addr: u64,
    pub page_allocator_addr: u64,
    pub kvm_fd: i32,
    pub vm_fd: i32,
}

impl ConfCompExtension for NonConf<'_> {
    fn initialize_conf_extension(
        _share_space_table_addr: Option<u64>,
        _page_allocator_base_addr: Option<u64>,
        kvm_fd: &Kvm,
        vm_fd: &VmFd,
    ) -> Result<Box<dyn ConfCompExtension>, crate::qlib::common::Error>
        where Self: Sized {
        let _self: Box<dyn ConfCompExtension> = Box::new(NonConf{
            kvm_exits_list: None,
            hypercalls_list: None,
            share_space_table_addr: _share_space_table_addr
                .expect("Exptected base address of the share space - found None"),
            page_allocator_addr: _page_allocator_base_addr
                .expect("Exptected address of the page allocator - found None"),
            cc_mode: CCMode::None,
            kvm_fd: kvm_fd.as_raw_fd(),
            vm_fd: vm_fd.as_raw_fd(),
        });
        Ok(_self)
    }

    fn should_handle_hypercall(&self, _hypercall: u16) -> bool {
        self.hypercalls_list.is_some()
    }

    fn should_handle_kvm_exit(&self, _kvm_exit: &VcpuExit) -> bool {
        self.kvm_exits_list.is_some()
    }

    fn set_sys_registers(&self, _vcpu_fd: &VcpuFd) -> Result<(), Error> { Ok(()) }

    fn set_cpu_registers(&self, vcpu_fd: &VcpuFd, _vcpu_id: usize) -> Result<(), Error> {
        self._set_cpu_registers(&vcpu_fd)
    }

    fn get_hypercall_arguments(&self, vcpu_fd: &VcpuFd, _vcpu_id: usize)
        -> Result<(u64, u64, u64, u64), Error> {
        self._get_hypercall_arguments(&vcpu_fd, _vcpu_id)
    }

    fn handle_kvm_exit(&self, _kvm_exit: &mut VcpuExit, _vcpu_id: usize, _vm_fd: &VmFd,)
        -> Result<bool, Error> { Ok(false) }

    fn handle_hypercall(&self, _hypercall: u16, _data: &[u8],  _arg0: u64, _arg1: u64, _arg2: u64,
        _arg3: u64, _vcpu_id: usize) -> Result<bool, Error> { Ok(false) }

    fn confidentiality_type(&self) -> CCMode {
        return self.cc_mode;
    }

    fn get_kvm_fd(&self) -> i32 {
        return self.kvm_fd;
    }
    
    fn get_vm_fd(&self) -> i32 {
        return self.vm_fd;
    }
}

pub mod util {
    use crate::{arch::vm::vcpu::ArchVirtCpu, qlib::linux_def::MemoryDef, CCMode};

    #[inline]
    pub fn get_offset(confidentiality_type: CCMode) -> u64 {
        let offset = match confidentiality_type {
            CCMode::None | CCMode::Normal | CCMode::TDX=>
                0,
            #[cfg(feature = "cc")]
            CCMode::NormalEmu =>
                MemoryDef::UNIDENTICAL_MAPPING_OFFSET,
            _ => panic!(""),
        };
        offset
    }

    #[inline]
    pub fn adjust_addr_to_guest(host_addr: u64, confidentiality_type: CCMode) -> u64 {
        host_addr - get_offset(confidentiality_type)
    }

    #[inline]
    pub fn adjust_addr_to_host(addr: u64, confidentiality_type: CCMode) -> u64 {
        addr + get_offset(confidentiality_type)
    }

    #[inline]
    pub fn confidentiality_type(vcpu: &ArchVirtCpu) -> CCMode {
        vcpu.conf_comp_extension
        .confidentiality_type()
    }
}
