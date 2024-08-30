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

use core::sync::atomic::Ordering;
use std::os::fd::AsRawFd;

use crate::qlib::linux_def::MemoryDef;
use crate::runc::runtime::vm::VirtualMachine;
use crate::runc::runtime::vm_type::emulcc::VmCcEmul;
use crate::runc::runtime::vm_type::VmType;
//#[cfg(feature = "cc")]
use crate::sharepara::ShareParaPage;
use crate::VMS;
use crate::{arch::ConfCompExtension, qlib, QUARK_CONFIG};
use kvm_ioctls::{Kvm, VcpuExit, VmFd};
use qlib::common::Error;
use qlib::config::CCMode;
static mut DUMMY_U64: u64 = 0u64;
use kvm_bindings::kvm_memory_attributes;
use kvm_ioctls::TDXExit;
const KVM_MEMORY_ATTRIBUTE_PRIVATE: u64 = 1 << 3;

pub struct Tdx<'a> {
    kvm_exits_list: [VcpuExit<'a>; 2],
    hypercalls_list: [u16; 3],
    pub cc_mode: CCMode,
    pub share_space_table_addr: Option<u64>,
    pub page_allocator_addr: u64,
    pub kvm_fd: i32,
    pub vm_fd: i32,
}

#[cfg(feature = "tdx")]
impl ConfCompExtension for Tdx<'_> {
    fn initialize_conf_extension(
        _share_space_table_addr: Option<u64>,
        _page_allocator_base_addr: Option<u64>,
        kvm_fd: &Kvm,
        vm_fd: &VmFd,
    ) -> Result<Box<dyn ConfCompExtension>, crate::qlib::common::Error>
    where
        Self: Sized,
    {
        let _self: Box<dyn ConfCompExtension> = Box::new(Tdx {
            kvm_exits_list: [
                VcpuExit::TDXExit(kvm_ioctls::TDXExit::MapGpa(0, 0, unsafe { &mut DUMMY_U64 })),
                VcpuExit::MemoryFault(0, 0, true),
            ],
            hypercalls_list: [
                qlib::HYPERCALL_SHARESPACE_INIT,
                qlib::HYPERCALL_DEBUG_OUTPUT,
                qlib::HYPERCALL_WAIT_BSP_INIT,
            ],
            cc_mode: CCMode::TDX,
            share_space_table_addr: None,
            page_allocator_addr: _page_allocator_base_addr
                .expect("Exptected address of the page allocator - found None"),
            kvm_fd: kvm_fd.as_raw_fd(),
            vm_fd: vm_fd.as_raw_fd(),
        });
        Ok(_self)
    }

    fn set_sys_registers(
        &self,
        vcpu_fd: &kvm_ioctls::VcpuFd,
    ) -> Result<(), crate::qlib::common::Error> {
        Ok(())
    }

    fn set_cpu_registers(
        &self,
        vcpu_fd: &kvm_ioctls::VcpuFd,
        vcpu_id: usize,
    ) -> Result<(), crate::qlib::common::Error> {
        self._set_cpu_registers(&vcpu_fd, vcpu_id)
    }

    fn get_hypercall_arguments(
        &self,
        vcpu_fd: &kvm_ioctls::VcpuFd,
        vcpu_id: usize,
    ) -> Result<(u64, u64, u64, u64), crate::qlib::common::Error> {
        self._get_hypercall_arguments(vcpu_fd, vcpu_id)
    }

    fn should_handle_kvm_exit(&self, kvm_exit: &kvm_ioctls::VcpuExit) -> bool {
        self.kvm_exits_list.contains(kvm_exit)
    }

    fn should_handle_hypercall(&self, hypercall: u16) -> bool {
        self.hypercalls_list.contains(&hypercall)
    }

    fn handle_kvm_exit(
        &self,
        kvm_exit: &mut kvm_ioctls::VcpuExit,
        vcpu_id: usize,
        vm_fd: &VmFd,
    ) -> Result<bool, crate::qlib::common::Error> {
        let mut _exit = false;
        _exit = match kvm_exit {
            VcpuExit::TDXExit(exit) => self._handle_tdx_exit(exit, vm_fd)?,
            VcpuExit::MemoryFault(gpa, size, private) => {
                self._handle_memory_fault(*gpa, *size, *private, vm_fd)?
            }
            _ => false,
        };
        Ok(_exit)
    }

    fn handle_hypercall(
        &self,
        hypercall: u16,
        data: &[u8],
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        vcpu_id: usize,
    ) -> Result<bool, crate::qlib::common::Error> {
        let mut _exit = false;
        _exit = match hypercall {
            qlib::HYPERCALL_SHARESPACE_INIT => {
                self._handle_hcall_shared_space_init(data, arg0, arg1, arg2, arg3, vcpu_id)?
            }
            qlib::HYPERCALL_DEBUG_OUTPUT => {
                self._handle_debug_output(data, arg0, arg1, arg2, arg3, vcpu_id)?
            }
            qlib::HYPERCALL_WAIT_BSP_INIT => {
                self._handle_wait_bsp_init(data, arg0, arg1, arg2, arg3, vcpu_id)?
            }
            _ => false,
        };

        Ok(_exit)
    }

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

#[cfg(feature = "cc")]
impl Tdx<'_> {
    fn _confidentiality_type(&self) -> CCMode {
        self.cc_mode
    }

    fn _get_hypercall_arguments(
        &self,
        _vcpu_fd: &kvm_ioctls::VcpuFd,
        vcpu_id: usize,
    ) -> Result<(u64, u64, u64, u64), Error> {
        let shared_param_buffer =
            unsafe { *(MemoryDef::HYPERCALL_PARA_PAGE_OFFSET as *const ShareParaPage) };
        let passed_params = shared_param_buffer.SharePara[vcpu_id];
        let _arg0 = passed_params.para1;
        let _arg1 = passed_params.para2;
        let _arg2 = passed_params.para3;
        let _arg3 = passed_params.para4;

        Ok((_arg0, _arg1, _arg2, _arg3))
    }

    pub(self) fn _handle_hcall_shared_space_init(
        &self,
        data: &[u8],
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        vcpu_id: usize,
    ) -> Result<bool, Error> {
        let ctrl_sock: i32;
        let vcpu_count: usize;
        let rdma_svc_cli_sock: i32;
        let mut pod_id = [0u8; 64]; //TODO: Hardcoded length of ID set it as cost to check on
        {
            let mut vms = VMS.lock();
            ctrl_sock = vms.controlSock;
            vcpu_count = vms.vcpuCount;
            rdma_svc_cli_sock = vms.args.as_ref().unwrap().RDMASvcCliSock;
            pod_id.copy_from_slice(vms.args.as_ref().unwrap().ID.clone().as_bytes());
        }
        if let Err(e) = VmCcEmul::init_share_space(
            vcpu_count,
            ctrl_sock,
            rdma_svc_cli_sock,
            pod_id,
            Some(arg0),
            None,
        ) {
            error!("Vcpu: hypercall failed on shared-space initialization.");
            return Err(e);
        } else {
            info!("Vcpu: finished shared-space initialization.");
        }

        Ok(false)
    }

    pub(self) fn _handle_debug_output(
        &self,
        data: &[u8],
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        vcpu_id: usize,
    ) -> Result<bool, Error> {
        let len = data.len();
        match len {
            1 => info!("{:x}", data[0]),
            2 => info!("{:x}", unsafe { *(&data[0] as *const _ as *const u16) }),
            4 => info!("{:x}", unsafe { *(&data[0] as *const _ as *const u32) }),
            _ => (),
        }
        Ok(false)
    }

    pub(self) fn _handle_wait_bsp_init(
        &self,
        data: &[u8],
        arg0: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        vcpu_id: usize,
    ) -> Result<bool, Error> {
        info!("cpu {:x} is waiting for the bsp", vcpu_id);
        crate::syncmgr::SyncMgr::WaitShareSpaceReady();
        info!("cpu {:x} returns to the guest", vcpu_id);
        Ok(false)
    }

    pub(self) fn _handle_tdx_exit(&self, exit: &mut TDXExit, vm_fd: &VmFd) -> Result<bool, Error> {
        use crate::qlib::cc::tdx::S_BIT_MASK;
        const TDG_VP_VMCALL_SUCCESS: u64 = 0x0000000000000000;
        const TDG_VP_VMCALL_RETRY: u64 = 0x0000000000000001;
        const TDG_VP_VMCALL_INVALID_OPERAND: u64 = 0x8000000000000000;
        const TDG_VP_VMCALL_ALIGN_ERROR: u64 = 0x8000000000000002;
        match exit {
            TDXExit::MapGpa(in_r12, in_r13, status_code) => {
                let in_r12 = *in_r12;
                let in_r13 = *in_r13;
                info!("TDXExit::MapGpa");
                let shared_bit = S_BIT_MASK.load(Ordering::Acquire);
                let addr_mask = (shared_bit << 1) - 1;
                let gpa = in_r12 & !shared_bit;
                let private = (in_r12 & shared_bit) == 0;
                let size = in_r13;
                **status_code = TDG_VP_VMCALL_INVALID_OPERAND;

                let mut attr = Some(kvm_memory_attributes {
                    address: gpa,
                    size: size,
                    attributes: if private {
                        KVM_MEMORY_ATTRIBUTE_PRIVATE
                    } else {
                        0
                    },
                    flags: 0,
                });

                if gpa & !addr_mask > 0 {
                    error!("Invalid gpa!");
                    attr = None;
                }

                if !(gpa % 4096 == 0) || !(size % 4096 == 0) {
                    **status_code = TDG_VP_VMCALL_ALIGN_ERROR;
                    error!("gpa alignment error!");
                    attr = None;
                }

                if size > 0 && attr.is_some() {
                    let attr_inner = attr.unwrap();
                    info!(
                        "Converting memory: gpa:0x{:x}, size:0x{:x}, from shared to private:{:?}",
                        attr_inner.address,
                        attr_inner.size,
                        attr_inner.attributes > 0
                    );
                    vm_fd
                        .set_memory_attributes(&attr_inner)
                        .expect("Unable to convert memory to private");
                    **status_code = TDG_VP_VMCALL_SUCCESS;
                }
            }
        }
        Ok(false)
    }

    pub(self) fn _handle_memory_fault(
        &self,
        gpa: u64,
        size: u64,
        private: bool,
        vm_fd: &VmFd,
    ) -> Result<bool, Error> {
        info!(
            "VcpuExit::MemoryFault gpa:{:x}, size:{:x}, private:{}",
            gpa, size, private
        );
        let attr = kvm_memory_attributes {
            address: gpa,
            size: size,
            attributes: if private {
                KVM_MEMORY_ATTRIBUTE_PRIVATE
            } else {
                0
            },
            flags: 0,
        };
        vm_fd
            .set_memory_attributes(&attr)
            .expect("Unable to convert memory to private");
        Ok(false)
    }
}
