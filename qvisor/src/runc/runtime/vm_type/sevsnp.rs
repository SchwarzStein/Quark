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
    os::fd::{AsRawFd, FromRawFd},
    sync::{atomic::Ordering, Arc},
};

use kvm_bindings::*;
use kvm_ioctls::{Cap, Kvm, VmFd};

use super::{
    resources::{GuestPrivateMemLayout, MemArea, MemLayoutConfig, VmResources},
    VmType,
};
use crate::arch::VirtCpu;
use crate::qlib::cc::sev_snp::cpuid_page::*;
use crate::qlib::cc::sev_snp::*;
use crate::qlib::kernel::Kernel::ENABLE_CC;
use crate::qlib::kernel::Kernel::IS_SEV_SNP;
use crate::qlib::mem::list_allocator::MAXIMUM_PAGE_START;
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
use sev::firmware::host::Firmware;
use sev::launch::snp::*;

#[derive(Debug)]
pub struct VmSevSnp {
    vm_resources: VmResources,
    entry_address: u64,
    vdso_address: u64,
    sev: Option<Firmware>,
    launcher: Option<Launcher<Started, VmFd, Firmware>>,
    vm_fd: Option<VmFd>,
    kvm_fd: Option<Kvm>,
}

impl VmType for VmSevSnp {
    fn init(args: Option<&Args>) -> Result<(Box<dyn VmType>, KernelELF), Error> {
        if !check_amd() || !check_snp_support() {
            return Err(Error::CCModeError);
        }
        ENABLE_CC.store(true, Ordering::Release);
        IS_SEV_SNP.store(true, Ordering::Release);
        set_cbit_mask();
        let _pod_id = args.expect("VM creation expects arguments").ID.clone();
        let default_min_vcpus = 3;

        let guest_priv_mem_layout = GuestPrivateMemLayout {
            private_heap_mem_base_host: MemoryDef::GUEST_PRIVATE_HEAP_OFFSET,
            private_heap_mem_base_guest: MemoryDef::GUEST_PRIVATE_HEAP_OFFSET,
            private_heap_init_mem_size: MemoryDef::GUEST_PRIVATE_INIT_HEAP_SIZE,
            private_heap_total_mem_size: MemoryDef::GUEST_PRIVATE_HEAP_SIZE,
        };

        let mem_layout_config = MemLayoutConfig {
            guest_private_mem_layout: Some(guest_priv_mem_layout),
            shared_heap_mem_base_guest: MemoryDef::GUEST_HOST_SHARED_HEAP_OFFSET,
            shared_heap_mem_base_host: MemoryDef::GUEST_HOST_SHARED_HEAP_OFFSET,
            shared_heap_mem_size: MemoryDef::GUEST_HOST_SHARED_HEAP_SIZE + MemoryDef::IO_HEAP_SIZE,
            kernel_base_guest: MemoryDef::PHY_LOWER_ADDR,
            kernel_base_host: MemoryDef::PHY_LOWER_ADDR,
            kernel_init_region_size: MemoryDef::KERNEL_MEM_INIT_REGION_SIZE * MemoryDef::ONE_GB,
            file_map_area_base_host: MemoryDef::FILE_MAP_OFFSET,
            file_map_area_base_guest: MemoryDef::FILE_MAP_OFFSET,
            file_map_area_size: MemoryDef::FILE_MAP_SIZE,
            //NOTE: Not backed by the host
            #[cfg(target_arch = "aarch64")]
            hypercall_mmio_base: MemoryDef::HYPERCALL_MMIO_BASE,
            #[cfg(target_arch = "aarch64")]
            hypercall_mmio_size: MemoryDef::HYPERCALL_MMIO_SIZE,
            stack_size: MemoryDef::DEFAULT_STACK_SIZE as usize,
        };
        let default_mem_layout = mem_layout_config;
        let _kernel_bin_path = VirtualMachine::KERNEL_IMAGE.to_string();
        let _vdso_bin_path = VirtualMachine::VDSO_PATH.to_string();
        let _sbox_uid_name = vm::SANDBOX_UID_NAME.to_string();

        let mut elf = KernelELF::New().expect("Failed to create elf object.");
        let _kernel_entry = elf
            .LoadKernel(_kernel_bin_path.as_str())
            .expect("Failed to load kernel from given path.");
        elf.LoadVDSO(_vdso_bin_path.as_str())
            .expect("Failed to load vdso from given path.");
        let _vdso_address = elf.vdsoStart;

        let vm_sevsnp = Self {
            vm_resources: VmResources {
                min_vcpu_amount: default_min_vcpus,
                kernel_bin_path: _kernel_bin_path,
                vdso_bin_path: _vdso_bin_path,
                sandbox_uid_name: _sbox_uid_name,
                pod_id: _pod_id,
                mem_layout: default_mem_layout,
            },
            entry_address: _kernel_entry,
            vdso_address: _vdso_address,
            sev: None,
            launcher: None,
            vm_fd: None,
            kvm_fd: None,
        };
        let box_type: Box<dyn VmType> = Box::new(vm_sevsnp);

        Ok((box_type, elf))
    }

    fn create_vm(
        mut self: Box<VmSevSnp>,
        kernel_elf: KernelELF,
        args: Args,
    ) -> Result<VirtualMachine, Error> {
        crate::GLOBAL_ALLOCATOR.InitPrivateAllocator();
        crate::GLOBAL_ALLOCATOR.MapSevSnpSpecialPages();
        *ROOT_CONTAINER_ID.lock() = args.ID.clone();
        if QUARK_CONFIG.lock().PerSandboxLog {
            let sandbox_name = match args
                .Spec
                .annotations
                .get(self.vm_resources.sandbox_uid_name.as_str())
            {
                None => args.ID[0..12].to_owned(),
                Some(name) => name.clone(),
            };
            LOG.Reset(&sandbox_name);
        }

        let cpu_count = args.GetCpuCount();
        let reserve_cpu_count = QUARK_CONFIG.lock().ReserveCpuCount;
        let cpu_count = if cpu_count == 0 {
            VMSpace::VCPUCount() - reserve_cpu_count
        } else {
            cpu_count.min(VMSpace::VCPUCount() - reserve_cpu_count)
        };

        if let Err(e) = self.vm_space_initialize(cpu_count, args) {
            error!("VM creation failed on VM-Space initialization.");
            return Err(e);
        } else {
            info!("VM creation - VM-Space initialization finished.");
        }

        {
            URING_MGR.lock();
        }

        let kvm: &Kvm;
        let vm_fd: &VmFd;
        let _kvm_fd = VMS.lock().args.as_ref().unwrap().KvmFd;
        match self.create_kvm_vm(_kvm_fd) {
            Ok(_) => {
                kvm = self.kvm_fd.as_ref().unwrap();
                vm_fd = self.launcher.as_ref().unwrap().as_ref();
                info!("VM cration - kvm-vm_fd initialized.");
            }
            Err(e) => {
                error!("VM creation failed on kvm-vm creation.");
                return Err(e);
            }
        };

        self.vm_memory_initialize(vm_fd)
            .expect("VM creation failed on memory initialization.");
        let (_, pheap, _) = self
            .vm_resources
            .mem_area_info(MemArea::PrivateHeapArea)
            .unwrap();
        let _vcpu_total = VMS.lock().vcpuCount;
        let _auto_start = VMS.lock().args.as_ref().unwrap().AutoStart;
        let vcpus = self
            .vm_vcpu_initialize(
                kvm,
                vm_fd,
                _vcpu_total,
                self.entry_address,
                _auto_start,
                Some(pheap),
                None,
            )
            .expect("VM creation failed on vcpu creation.");

        #[cfg(target_arch = "x86_64")]
        self.vm_vcpu_post_initialization(&vcpus)
            .expect("VM creation failed on vcpu registers setting.");
        let kvm_cpuid = kvm
            .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
            .unwrap();
        let cpuid_page_addr = MemoryDef::CPUID_PAGE;
        let cpuid_page = CpuidPage::get_ref(cpuid_page_addr);
        cpuid_page
            .FillCpuidPage(&kvm_cpuid)
            .expect("Fail to fill cpuid page");
        self.post_init_upadate().expect("Fail to update memory");
        self.post_vm_initialize().expect("Fail to finish vm");
        let vm_fd = self.vm_fd.take().unwrap();
        let kvm = self.kvm_fd.take().unwrap();
        let _vm_type: Box<dyn VmType> = self;
        let vm = VirtualMachine {
            kvm,
            vmfd: vm_fd,
            vm_type: _vm_type,
            vcpus: vcpus,
            elf: kernel_elf,
        };
        Ok(vm)
    }

    fn vm_space_initialize(&self, vcpu_count: usize, args: Args) -> Result<(), Error> {
        let vms = &mut VMS.lock();
        vms.vcpuCount = vcpu_count.max(self.vm_resources.min_vcpu_amount);
        vms.cpuAffinit = true;
        vms.RandomVcpuMapping();
        vms.controlSock = args.ControlSock;
        vms.vdsoAddr = self.vdso_address;
        vms.pivot = args.Pivot;
        if let Some(id) = args
            .Spec
            .annotations
            .get(self.vm_resources.sandbox_uid_name.as_str())
        {
            vms.podUid = id.clone();
        } else {
            info!("No sandbox id found in specification.");
        }

        let (fmap_base_host, _, fmap_size) = self
            .vm_resources
            .mem_area_info(MemArea::FileMapArea)
            .unwrap();
        PMA_KEEPER.Init(fmap_base_host, fmap_size);
        PMA_KEEPER.InitHugePages();
        vms.pageTables = PageTables::New(&vms.allocator)?;

        let mut page_opt = PageOpts::Zero();
        page_opt = PageOpts::Kernel();
        let (_, kmem_base_guest, kmem_init_region) = self
            .vm_resources
            .mem_area_info(MemArea::KernelArea)
            .unwrap();
        vms.KernelMapHugeTableSevSnp(
            Addr(kmem_base_guest),
            Addr(kmem_base_guest + kmem_init_region),
            Addr(kmem_base_guest),
            page_opt.Val(),
            get_cbit(),
        )?;
        vms.args = Some(args);

        Ok(())
    }

    fn vm_memory_initialize(&self, vm_fd: &VmFd) -> Result<(), Error> {
        let (file_map_base_host, file_map_base_guest, file_map_region) = self
            .vm_resources
            .mem_area_info(MemArea::FileMapArea)
            .unwrap();
        let (kmem_base_host, kmem_base_guest, _) = self
            .vm_resources
            .mem_area_info(MemArea::KernelArea)
            .unwrap();
        let kmem_private_region = file_map_base_guest - kmem_base_guest;

        //Set kernel region
        SetMemRegionCC(
            1,
            vm_fd,
            kmem_base_guest,
            kmem_base_host,
            kmem_private_region,
        )
        .map_err(|e| {
            Error::IOError(format!(
                "Failed to set kvm kernel memory region - error:{:?}",
                e
            ))
        })?;

        let (private_heap_base_host, private_heap_base_guest, private_heap_region) = self
            .vm_resources
            .mem_area_info(MemArea::PrivateHeapArea)
            .unwrap();

        SetMemRegionCC(
            2,
            vm_fd,
            private_heap_base_guest,
            private_heap_base_host,
            private_heap_region,
        )
        .map_err(|e| {
            Error::IOError(format!(
                "Failed to set kvm private heap memory region - error:{:?}",
                e
            ))
        })?;

        SetMemRegionCC(
            3,
            vm_fd,
            file_map_base_guest,
            file_map_base_host,
            file_map_region,
        )
        .map_err(|e| {
            Error::IOError(format!(
                "Failed to set kvm file map memory region - error:{:?}",
                e
            ))
        })?;

        let (shared_heap_base_host, shared_heap_base_guest, shared_heap_region) = self
            .vm_resources
            .mem_area_info(MemArea::SharedHeapArea)
            .unwrap();

        SetMemRegionCC(
            4,
            vm_fd,
            shared_heap_base_guest,
            shared_heap_base_host,
            shared_heap_region,
        )
        .map_err(|e| {
            Error::IOError(format!(
                "Failed to set kvm shared heap memory region - error:{:?}",
                e
            ))
        })?;

        info!(
            "KernelMemRegion - Guest-phyAddr:{:#x}, host-VA:{:#x}, page mmap-size:{} MB",
            kmem_base_guest,
            kmem_base_host,
            kmem_private_region >> 20
        );
        info!(
            "PrivateHeapMemRegion - Guest-phyAddr:{:#x}, host-VA:{:#x}, page mmap-size:{} MB",
            private_heap_base_guest,
            private_heap_base_host,
            private_heap_region >> 20
        );
        info!(
            "SharedMemRegion - Guest-phyAddr:{:#x}, host-VA:{:#x}, page mmap-size:{} MB",
            shared_heap_base_guest,
            shared_heap_base_host,
            shared_heap_region >> 20
        );
        info!(
            "FileMapMemRegion - Guest-phyAddr:{:#x}, host-VA:{:#x}, page mmap-size:{} MB",
            file_map_base_guest,
            file_map_base_host,
            file_map_region >> 20
        );

        Ok(())
    }

    fn create_kvm_vm(&mut self, kvm_fd: i32) -> Result<(), Error> {
        const VM_SEV_SNP: u64 = 3;
        let kvm = unsafe { Kvm::from_raw_fd(kvm_fd) };

        if !kvm.check_extension(Cap::ImmediateExit) {
            panic!("Can not create VM - KVM_CAP_IMMEDIATE_EXIT is not supported.");
        }

        let vm_fd = kvm
            .create_vm_with_type(VM_SEV_SNP)
            .map_err(|e| Error::IOError(format!("Failed to create a kvm-vm with error:{:?}", e)))?;
        let vm_rawfd = vm_fd.as_raw_fd();

        let mut cap: kvm_enable_cap = Default::default();
        cap.cap = kvm_bindings::KVM_CAP_X86_DISABLE_EXITS;
        //cap.args[0] = (kvm_bindings::KVM_X86_DISABLE_EXITS_HLT
        //    | kvm_bindings::KVM_X86_DISABLE_EXITS_MWAIT) as u64;
        cap.args[0] = kvm_bindings::KVM_X86_DISABLE_EXITS_MWAIT as u64;
        let sev = Firmware::open().expect("Unable to open /dev/sev");
        let launcher = Launcher::new(vm_fd, sev).unwrap();
        let start = Start::new(
            Policy {
                flags: PolicyFlags::SMT,
                ..Default::default()
            },
            [0; 16],
        );
        let launcher = launcher.start(start).unwrap();
        launcher.as_ref().enable_cap(&cap).unwrap();
        self.launcher = Some(launcher);
        self.kvm_fd = Some(kvm);
        Ok(())
    }

    fn init_share_space(
        vcpu_count: usize,
        control_sock: i32,
        rdma_svc_cli_sock: i32,
        pod_id: [u8; 64],
        share_space_addr: Option<u64>,
        _has_global_mem_barrier: Option<bool>,
    ) -> Result<(), Error> {
        use core::sync::atomic;
        crate::GLOBAL_ALLOCATOR
            .vmLaunched
            .store(true, atomic::Ordering::SeqCst);
        let shared_space_obj = unsafe {
            &mut *(share_space_addr.expect(
                "Failed to initialize shared space in host\
               - shared-space-table address is missing",
            ) as *mut ShareSpace)
        };
        let default_share_space_table = ShareSpace::New();
        let def_sh_space_tab_size = core::mem::size_of_val(&default_share_space_table);
        let sh_space_obj_size = core::mem::size_of_val(shared_space_obj);
        assert!(
            sh_space_obj_size == def_sh_space_tab_size,
            "Guest passed shared-space address does not match to a shared-space object.\
   Expected obj size:{:#x} - found:{:#x}",
            def_sh_space_tab_size,
            sh_space_obj_size
        );
        unsafe {
            core::ptr::write(
                shared_space_obj as *mut ShareSpace,
                default_share_space_table,
            );
        }

        {
            let mut vms = VMS.lock();
            let shared_copy = vms.args.as_ref().unwrap().Spec.Copy();
            vms.args.as_mut().unwrap().Spec = shared_copy;
        }

        shared_space_obj.Init(vcpu_count, control_sock, rdma_svc_cli_sock, pod_id);
        SHARE_SPACE.SetValue(share_space_addr.unwrap());
        SHARESPACE.SetValue(share_space_addr.unwrap());
        URING_MGR.lock().Addfd(crate::print::LOG.Logfd()).unwrap();
        let share_space_ptr = SHARE_SPACE.Ptr();
        URING_MGR
            .lock()
            .Addfd(share_space_ptr.HostHostEpollfd())
            .unwrap();
        URING_MGR.lock().Addfd(control_sock).unwrap();
        KERNEL_IO_THREAD.Init(share_space_ptr.scheduler.VcpuArr[0].eventfd);
        unsafe {
            CPU_LOCAL.Init(&SHARESPACE.scheduler.VcpuArr);
            futex::InitSingleton();
            timer::InitSingleton();
        }

        if SHARESPACE.config.read().EnableTsot {
            TSOT_AGENT.NextReqId();
            SHARESPACE.dnsSvc.Init().unwrap();
        }
        crate::print::SetSyncPrint(share_space_ptr.config.read().SyncPrint());

        Ok(())
    }

    fn post_memory_initialize(&mut self) -> Result<(), Error> {
        Ok(())
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
        let mut vcpus: Vec<Arc<ArchVirtCpu>> = Vec::with_capacity(total_vcpus);

        for vcpu_id in 0..total_vcpus {
            let vcpu = Arc::new(ArchVirtCpu::new_vcpu(
                vcpu_id as usize,
                total_vcpus,
                &vm_fd,
                entry_addr,
                page_allocator_addr,
                share_space_addr,
                auto_start,
                self.vm_resources.mem_layout.stack_size,
                Some(&kvm),
                CCMode::SevSnp,
            )?);

            vcpus.push(vcpu);
        }
        VMS.lock().vcpus = vcpus.clone();

        Ok(vcpus)
    }

    fn vm_vcpu_post_initialization(&self, vcpus: &Vec<Arc<ArchVirtCpu>>) -> Result<(), Error> {
        for vcpu in vcpus {
            vcpu.initialize_sys_registers()
                .expect("Can not run vcpu - failed to init sysregs");
            vcpu.initialize_cpu_registers()
                .expect("Can not run vcpu - failed to init cpu-regs");
            vcpu.conf_comp_extension
                .set_sys_registers(&vcpu.vcpu_base.vcpu_fd)?;
            vcpu.conf_comp_extension
                .set_cpu_registers(&vcpu.vcpu_base.vcpu_fd)?;
            vcpu.vcpu_base.SignalMask();
        }
        Ok(())
    }

    fn post_vm_initialize(&mut self) -> Result<(), Error> {
        let finish = Finish::new(None, None, [0u8; 32]);
        let launcher = self.launcher.take().unwrap();
        let (vm_fd, sev) = launcher.finish(finish).unwrap();
        self.vm_fd = Some(vm_fd);
        self.sev = Some(sev);
        Ok(())
    }

    fn post_init_upadate(&mut self) -> Result<(), Error> {
        use core::slice::from_raw_parts_mut;
        let cpuid_page_addr = MemoryDef::CPUID_PAGE;
        let secret_page_addr = MemoryDef::SECRET_PAGE;

        let (_, kmem_base_guest, kernelMemRegionSize) = self
            .vm_resources
            .mem_area_info(MemArea::KernelArea)
            .unwrap();

        const KVM_MEMORY_ATTRIBUTE_PRIVATE: u64 = 1 << 3;
        let memory_attributes = kvm_memory_attributes {
            address: kmem_base_guest,
            size: kernelMemRegionSize,
            attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE,
            flags: 0,
        };
        self.launcher
            .as_ref()
            .unwrap()
            .as_ref()
            .set_memory_attributes(&memory_attributes)
            .expect("Unable to convert memory to private");

        //update initial private heap including private allocator, page table, gdt etc.
        let maximum_pagetable_page = MAXIMUM_PAGE_START.load(Ordering::Acquire);
        info!("MAXIMUM_PAGE_START is 0x{:x}", maximum_pagetable_page);

        let (private_heap_base_host, _, _) = self
            .vm_resources
            .mem_area_info(MemArea::PrivateHeapArea)
            .unwrap();

        let pt_space: &mut [u8] = unsafe {
            from_raw_parts_mut(
                private_heap_base_host as *mut u8,
                (maximum_pagetable_page + MemoryDef::PAGE_SIZE - private_heap_base_host) as usize,
            )
        };
        let update_pt = Update::new(private_heap_base_host >> 12, pt_space, PageType::Normal);
        self.launcher
            .as_mut()
            .unwrap()
            .update_data(update_pt)
            .unwrap();
        // let p = entry as *const u8;
        // info!(
        //     "entry is 0x{:x}, data at entry is {:x}, heapStartAddr is {:x}",
        //     entry,
        //     unsafe { *p },
        //     heapStartAddr
        // );

        //update kernel
        let kernel_space: &mut [u8] = unsafe {
            from_raw_parts_mut(
                self.entry_address as *mut u8,
                (self.vdso_address + 3 * 4096 - self.entry_address) as usize,
            )
        };
        let update_kernel = Update::new(self.entry_address >> 12, kernel_space, PageType::Normal);
        self.launcher
            .as_mut()
            .unwrap()
            .update_data(update_kernel)
            .unwrap();

        //update cpuid_page
        let cpuid_space: &mut [u8] = unsafe {
            from_raw_parts_mut(cpuid_page_addr as *mut u8, MemoryDef::PAGE_SIZE as usize)
        };
        let update_cpuid = Update::new(cpuid_page_addr >> 12, cpuid_space, PageType::Cpuid);
        //Retry again if udpate failed
        match self.launcher.as_mut().unwrap().update_data(update_cpuid) {
            Ok(_) => (),
            Err(_) => {
                //cpuid_page.dump_cpuid();
                self.launcher
                    .as_mut()
                    .unwrap()
                    .update_data(update_cpuid)
                    .unwrap();
            }
        };
        //update secret page
        let secret_space: &mut [u8] = unsafe {
            from_raw_parts_mut(secret_page_addr as *mut u8, MemoryDef::PAGE_SIZE as usize)
        };
        let update_secret = Update::new(secret_page_addr >> 12, secret_space, PageType::Secrets);
        self.launcher
            .as_mut()
            .unwrap()
            .update_data(update_secret)
            .unwrap();
        info!("update finished");
        Ok(())
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

pub const KVM_MEM_GUEST_MEMFD: u32 = 1 << 2;

pub fn SetMemRegionCC(
    slotId: u32,
    vm_fd: &VmFd,
    phyAddr: u64,
    hostAddr: u64,
    pageMmapsize: u64,
) -> Result<(), kvm_ioctls::Error> {
    let gmem = kvm_create_guest_memfd {
        size: pageMmapsize,
        ..Default::default()
    };
    let gmem_fd = vm_fd
        .create_guest_memfd(&gmem)
        .expect("Fail to create guest memory") as u32;
    // guest_phys_addr must be <512G
    let mem_region = kvm_userspace_memory_region2 {
        slot: slotId,
        flags: KVM_MEM_GUEST_MEMFD,
        guest_phys_addr: phyAddr,
        memory_size: pageMmapsize,
        userspace_addr: hostAddr,
        gmem_offset: 0,
        gmem_fd: gmem_fd,
        ..Default::default()
    };

    unsafe {
        vm_fd.set_user_memory_region2(mem_region)?;
    }

    return Ok(());
}
