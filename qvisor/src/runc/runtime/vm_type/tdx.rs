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
        tee::util::{adjust_addr_to_host, get_offset},
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

use crate::qlib::mem::list_allocator::MAXIMUM_PAGE_START;
use kvm_bindings::{kvm_msr_entry, CpuId, Msrs};
use tdx::launch::*;
use tdx::tdvf;
use tdx::tdvf::{TdxFirmwareEntry, TdxRamEntry, TdxRamType};

#[derive(Debug)]
pub struct VmTDX {
    vm_resources: VmResources,
    entry_address: u64,
    vdso_address: u64,
    kvm: Option<Kvm>,
    tdx_vm: Option<TdxVm>,
    firmware_ptr: u64,
    sections: Option<Vec<TdxFirmwareEntry>>,
    kvm_cpuid: Option<CpuId>,
}

impl VmType for VmTDX {
    fn init(args: Option<&Args>) -> Result<(Box<dyn VmType>, KernelELF), Error> {
        if !check_intel() {
            return Err(Error::CCModeError);
        }
        ENABLE_CC.store(true, Ordering::Release);
        TDX_ENABLED.store(true, Ordering::Release);
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

        let vm_tdx = Self {
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
            kvm: None,
            tdx_vm: None,
            firmware_ptr: 0,
            sections: None,
            kvm_cpuid: None,
        };
        let box_type: Box<dyn VmType> = Box::new(vm_tdx);

        Ok((box_type, elf))
    }

    fn create_vm(
        mut self: Box<VmTDX>,
        kernel_elf: KernelELF,
        args: Args,
    ) -> Result<VirtualMachine, Error> {
        crate::GLOBAL_ALLOCATOR.InitPrivateAllocator();
        crate::GLOBAL_ALLOCATOR.MapTDXSpecialPages();
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

        let _kvm: &Kvm;
        let vm_fd: &VmFd;
        let _kvm_fd = VMS.lock().args.as_ref().unwrap().KvmFd;
        match self.create_kvm_vm(_kvm_fd) {
            Ok(_) => {
                _kvm = self.kvm.as_ref().unwrap();
                vm_fd = &self.tdx_vm.as_ref().unwrap().fd;
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
                &_kvm,
                &vm_fd,
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
        self.post_init_upadate();
        self.post_vm_initialize();
        let kvm = self.kvm.take().unwrap();
        let vm_fd = self.tdx_vm.take().unwrap().fd;
        let _vm_type: Box<dyn VmType> = self;
        let vm = VirtualMachine {
            kvm: kvm,
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
        vms.KernelMapHugeTable(
            Addr(kmem_base_guest),
            Addr(kmem_base_guest + kmem_init_region),
            Addr(kmem_base_guest),
            page_opt.Val(),
        )?;

        //Map first 8 GB for the firmware
        vms.KernelMapHugeTable(
            Addr(0),
            Addr(8 * MemoryDef::ONE_GB),
            Addr(0),
            page_opt.Val(),
        )?;
        vms.args = Some(args);

        Ok(())
    }

    fn vm_memory_initialize(&self, vm_fd: &VmFd) -> Result<(), Error> {
        let (fmap_base_host, fmap_base_guest, fmap_region) = self
            .vm_resources
            .mem_area_info(MemArea::FileMapArea)
            .unwrap();
        let (kmem_base_host, kmem_base_guest, _) = self
            .vm_resources
            .mem_area_info(MemArea::KernelArea)
            .unwrap();
        let kmem_private_region = fmap_base_guest - kmem_base_guest;

        set_user_memory_region_tdx(
            vm_fd,
            kmem_base_guest,
            kmem_base_host,
            kmem_private_region,
            1,
        );

        let (pheap_base_host, pheap_base_guest, pheap_region) = self
            .vm_resources
            .mem_area_info(MemArea::PrivateHeapArea)
            .unwrap();

        set_user_memory_region_tdx(vm_fd, pheap_base_guest, pheap_base_host, pheap_region, 2);
        set_user_memory_region_tdx(vm_fd, fmap_base_guest, fmap_base_host, fmap_region, 3);

        let (shared_heap_base_host, shared_heap_base_guest, shared_heap_region) = self
            .vm_resources
            .mem_area_info(MemArea::SharedHeapArea)
            .unwrap();

        set_user_memory_region_tdx(
            vm_fd,
            shared_heap_base_guest,
            shared_heap_base_host,
            shared_heap_region,
            4,
        );
        set_user_memory_region_tdx(
            vm_fd,
            MemoryDef::TDVF_OFFSET,
            self.firmware_ptr,
            MemoryDef::TDVF_SIZE,
            5,
        );
        let firmware_ram_hva = ram_mmap(MemoryDef::SHIM_MEMORY_SIZE, -1);
        set_user_memory_region_tdx(
            vm_fd,
            MemoryDef::SHIM_MEMORY_BASE,
            firmware_ram_hva,
            MemoryDef::SHIM_MEMORY_SIZE,
            6,
        );

        info!(
            "KernelMemRegion - Guest-phyAddr:{:#x}, host-VA:{:#x}, page mmap-size:{} MB",
            kmem_base_guest,
            kmem_base_host,
            kmem_private_region >> 20
        );
        info!(
            "PrivateHeapMemRegion - Guest-phyAddr:{:#x}, host-VA:{:#x}, page mmap-size:{} MB",
            pheap_base_guest,
            pheap_base_host,
            pheap_region >> 20
        );
        info!(
            "SharedMemRegion - Guest-phyAddr:{:#x}, host-VA:{:#x}, page mmap-size:{} MB",
            shared_heap_base_guest,
            shared_heap_base_host,
            shared_heap_region >> 20
        );
        info!(
            "FileMapMemRegion - Guest-phyAddr:{:#x}, host-VA:{:#x}, page mmap-size:{} MB",
            fmap_base_guest,
            fmap_base_host,
            fmap_region >> 20
        );
        info!(
            "FirmwareMemRegion - Guest-phyAddr:{:#x}, host-VA:{:#x}, page mmap-size:{} MB",
            MemoryDef::TDVF_OFFSET,
            self.firmware_ptr,
            MemoryDef::TDVF_SIZE >> 20
        );
        info!(
            "FirmwareRamRegion - Guest-phyAddr:{:#x}, host-VA:{:#x}, page mmap-size:{} MB",
            MemoryDef::SHIM_MEMORY_BASE,
            firmware_ram_hva,
            MemoryDef::SHIM_MEMORY_SIZE >> 20
        );
        Ok(())
    }

    fn create_kvm_vm(&mut self, kvm_fd: i32) -> Result<(), Error> {
        let kvm = unsafe { Kvm::from_raw_fd(kvm_fd) };
        let mut tdx_vm = TdxVm::new(&kvm, VMS.lock().vcpuCount as u64).unwrap();
        let caps = tdx_vm.get_capabilities().unwrap();

        let s_bit = tdx_vm.phys_bits - 1;
        assert!(s_bit == 47 || s_bit == 51, "invalid gpaw!");
        S_BIT_NUM.store(s_bit as u64, Ordering::Release);
        S_BIT_MASK.store(1 << S_BIT_NUM.load(Ordering::Acquire), Ordering::Release);
        let mut kvm_cpuid = tdx_vm.init_vm(&kvm, &caps).unwrap();
        let nent = kvm_cpuid.as_fam_struct_ref().nent as usize;
        let entries = unsafe { kvm_cpuid.as_fam_struct_ref().entries.as_slice(nent) };
        for entry in entries {
            debug!(
                "CPUID function = 0x{:x}, index = 0x{:x}, flags = 0x{:x}, eax = 0x{:x}, ebx = 0x{:x}, ecx = 0x{:x}, edx = 0x{:x}",
                entry.function,
                entry.index,
                entry.flags,
                entry.eax,
                entry.ebx,
                entry.ecx,
                entry.edx
            );
        }

        if !kvm.check_extension(Cap::ImmediateExit) {
            panic!("Can not create VM - KVM_CAP_IMMEDIATE_EXIT is not supported.");
        }

        //parse firmware
        let mut firmware = std::fs::File::open("/usr/local/bin/shim.bin").unwrap();
        let firmware_len = firmware.metadata()?.len();
        assert_eq!(firmware_len, MemoryDef::TDVF_SIZE, "Wrong firmware length!");
        let firmware_ptr = ram_mmap(firmware_len, firmware.as_raw_fd());

        let mut sections = tdvf::parse_sections(&mut firmware).unwrap();
        let mut ram_array = Vec::new();
        ram_array.push(TdxRamEntry {
            address: 0,
            length: 2 * MemoryDef::ONE_GB,
            ram_type: TdxRamType::RamUnaccepted,
        });
        tdvf::handle_firmware_entries(&mut ram_array, &mut sections, firmware_ptr)
            .expect("Unable to handle firmware entries!");
        let hob_section = tdvf::get_hob_section(&sections).unwrap();
        tdvf::hob_create(ram_array, *hob_section).expect("Failed to create hobs!");

        let mut cap: kvm_enable_cap = Default::default();
        cap.cap = kvm_bindings::KVM_CAP_X86_DISABLE_EXITS;
        cap.args[0] = (kvm_bindings::KVM_X86_DISABLE_EXITS_HLT
            | kvm_bindings::KVM_X86_DISABLE_EXITS_MWAIT) as u64;
        tdx_vm.fd.enable_cap(&cap).unwrap();
        self.kvm = Some(kvm);
        self.tdx_vm = Some(tdx_vm);
        self.firmware_ptr = firmware_ptr;
        self.sections = Some(sections);
        self.kvm_cpuid = Some(kvm_cpuid);
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
                CCMode::TDX,
            )?);

            vcpus.push(vcpu);
        }
        VMS.lock().vcpus = vcpus.clone();

        Ok(vcpus)
    }

    fn post_vm_initialize(&mut self) -> Result<(), Error> {
        // finalize measurement
        self.tdx_vm.as_ref().unwrap().finalize().unwrap();
        info!("vm finialized");
        Ok(())
    }

    fn post_init_upadate(&mut self) -> Result<(), Error> {
        let maximum_pagetable_page = MAXIMUM_PAGE_START.load(Ordering::Acquire);
        let vcpufd = &VMS.lock().vcpus[0].vcpu_base.vcpu_fd;

        //update shim
        for entry in self.sections.as_ref().unwrap() {
            info!("section:{:#x?}", entry);
            self.tdx_vm
                .as_ref()
                .unwrap()
                .init_mem_region(vcpufd, entry)
                .expect("INIT_MEM_REGION sections failed");
        }
        //update register parameters memory region
        self.tdx_vm
            .as_ref()
            .unwrap()
            .init_mem_region_raw(
                vcpufd,
                MemoryDef::VM_REGS_OFFSET,
                MemoryDef::VM_REGS_OFFSET,
                MemoryDef::VM_REGS_SIZE / MemoryDef::PAGE_SIZE,
                true,
            )
            .expect("INIT_MEM_REGION registers failed");

        //update kernel
        self.tdx_vm
            .as_ref()
            .unwrap()
            .init_mem_region_raw(
                vcpufd,
                self.entry_address,
                self.entry_address,
                (self.vdso_address + 3 * MemoryDef::PAGE_SIZE - self.entry_address)
                    / MemoryDef::PAGE_SIZE,
                true,
            )
            .expect("INIT_MEM_REGION kernel failed");

        //update initial ram
        self.tdx_vm
            .as_ref()
            .unwrap()
            .init_mem_region_raw(
                vcpufd,
                MemoryDef::GUEST_PRIVATE_INIT_HEAP_OFFSET,
                MemoryDef::GUEST_PRIVATE_INIT_HEAP_OFFSET,
                (maximum_pagetable_page + MemoryDef::PAGE_SIZE
                    - MemoryDef::GUEST_PRIVATE_INIT_HEAP_OFFSET)
                    / MemoryDef::PAGE_SIZE,
                true,
            )
            .expect("INIT_MEM_REGION ram failed");
        Ok(())
    }

    fn vm_vcpu_post_initialization(&mut self, vcpus: &Vec<Arc<ArchVirtCpu>>) -> Result<(), Error> {
        let hob_section = tdvf::get_hob_section(self.sections.as_ref().unwrap()).unwrap();
        for vcpu in vcpus {
            set_cpuid_with_x2apic(self.kvm_cpuid.as_mut().unwrap(), &vcpu.vcpu_base.vcpu_fd)
                .expect("Set x2apic cpuid failed");
            vcpu.initialize_sys_registers()
                .expect("Can not run vcpu - failed to init sysregs");
            vcpu.initialize_cpu_registers()
                .expect("Can not run vcpu - failed to init cpu-regs");
            vcpu.conf_comp_extension
                .set_sys_registers(&vcpu.vcpu_base.vcpu_fd)?;
            vcpu.conf_comp_extension
                .set_cpu_registers(&vcpu.vcpu_base.vcpu_fd, vcpu.vcpu_base.id)?;
            const MSR_IA32_APICBASE: u32 = 0x1b;
            const APIC_DEFAULT_ADDRESS: u64 = 0xfee00000;
            const MSR_IA32_APICBASE_BSP: u64 = 1 << 8;
            const XAPIC_ENABLE: u64 = 1 << 10;
            const X2APIC_ENABLE: u64 = 1 << 11;
            let msrs = Msrs::from_entries(&[kvm_msr_entry {
                index: MSR_IA32_APICBASE,
                reserved: 0,
                data: APIC_DEFAULT_ADDRESS | XAPIC_ENABLE | X2APIC_ENABLE | MSR_IA32_APICBASE_BSP,
            }])
            .unwrap();
            vcpu.vcpu_base
                .vcpu_fd
                .set_msrs(&msrs)
                .expect("set msrs failed");
            vcpu.vcpu_base.SignalMask();
            //This should after set cpuid2, otherwise will fail
            init_vcpu(&vcpu.vcpu_base.vcpu_fd, hob_section.memory_address)
                .expect("tdx init_vcpu failed");
        }
        Ok(())
    }
}

fn set_user_memory_region_tdx(vm_fd: &VmFd, gpa: u64, hva: u64, size: u64, slot: u32) {
    const KVM_MEM_PRIVATE: u32 = 1u32 << 2;
    const KVM_MEMORY_ATTRIBUTE_PRIVATE: u64 = 1 << 3;
    let gmem = KvmCreateGuestMemfd {
        size: size,
        flags: 0,
        reserved: [0; 6],
    };
    let fd_priv = linux_ioctls::create_guest_memfd(vm_fd, &gmem);
    let mem_region = KvmUserspaceMemoryRegion2 {
        slot: slot,
        flags: KVM_MEM_PRIVATE,
        guest_phys_addr: gpa,
        memory_size: size,
        userspace_addr: hva,
        guest_memfd_offset: 0,
        guest_memfd: fd_priv as u32,
        pad1: 0,
        pad2: [0; 14],
    };
    linux_ioctls::set_user_memory_region2(vm_fd, &mem_region);
    let attr = KvmMemoryAttributes {
        address: gpa,
        size: size,
        attributes: KVM_MEMORY_ATTRIBUTE_PRIVATE,
        flags: 0,
    };
    linux_ioctls::set_memory_attributes(vm_fd, &attr);
}
