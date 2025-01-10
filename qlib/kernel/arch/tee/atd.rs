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

use crate::qlib::{CCMode, common::Result, linux_def::{FileMode,
    FilePermissions}};
use crate::qlib::kernel::{task::Task, fs::{dirent::Dirent,
    inode::{Inode, Iops}, attr::{InodeType, StableAttr},
    sys::tsm::TsmIops}, LOADER, arch::tee};

pub fn expose_att_driver_func_as_file() -> Result<bool> {
    let mut max_tranv = 0;
    let provider = match tee::get_tee_type() {
        CCMode::Cca => "arm_cca_guest",
        _ => "dummy",
    };
    let sbox_id = LOADER.lock().sandboxID.clone();
    let mns = LOADER.lock().kernel.mounts.read()
        .get(&sbox_id).expect("VM: failed to get MountNs for Sandbox-ID");
    let root = mns.Root();
    let task = Task::Current();

    let k_dirent = mns.FindDirent(&task, &root,
        Some(root.clone()), "/sys/kernel", &mut max_tranv,
        false).expect("Search for /sys/kernel/ dirent failed");
    k_dirent.CreateDirectory(&task, &root, "config", 
        &FilePermissions::FromMode(FileMode(0o755 as u16)))
        .expect("Failed to create /sys/kernel/config");
    let c_dirent = mns.FindDirent(&task, &root,
        Some(k_dirent), "config", &mut max_tranv,
        false).expect("Search for /sys/kernel/config dirent failed");
    c_dirent.CreateDirectory(&task, &root, "tsm",
        &FilePermissions::FromMode(FileMode(0o755 as u16)))
        .expect("Failed to create /sys/kernel/config/tsm/report");
    let t_dirent =  mns.FindDirent(&task, &root,
        Some(c_dirent), "tsm", &mut max_tranv,
        false).expect("Search for /sys/kernel/config/tsm dirent failed");
    t_dirent.CreateDirectory(&task, &root, "report",
        &FilePermissions::FromMode(FileMode(0o557 as u16)))
        .expect("Failed to create /sys/kernel/config/tsm/report");
    let r_dirent = mns.FindDirent(&task, &root,
        Some(t_dirent), "report", &mut max_tranv,
        false).expect("Search for /sys/kernel/config/tsm/report dirent failed");
    r_dirent.CreateDirectory(&task, &root, &provider,
        &FilePermissions::FromMode(FileMode(0o755 as u16)))
        .expect("Failed to create /sys/kernel/config/tsm/report/$provider");
    let p_dirent = mns.FindDirent(&task, &root,
        Some(r_dirent), provider, &mut max_tranv,
        false).expect("Search for /sys/kernel/config/tsm/report/$provider dirent failed");


    let sys_inode = mns.FindDirent(&task, &root, Some(root.clone()), "/sys",
        &mut max_tranv, false).expect("VM: failed to get dirent for /sys").Inode();
    let sys_msrc = sys_inode.0.lock().MountSource.clone(); 
    let stable_attrb = StableAttr {
        Type: InodeType::SpecialFile,
        ..Default::default()
    };
//    let mount_source = MountSource::NewCachingMountSource(sys::SysFileSystem{}, 
//        MountSourceFlags::default());
    let provider_inode = Inode::New(Iops::TsmInodeOps(TsmIops::new()), &sys_msrc, &sys_msrc);
    let provider_dirent = Dirent::New(&provider_inode, "provider");
   // let inblob_dirent = Dirent::New(&inblob_inode, "inblob");
   // let outblob_dirent = Dirent::New(&outblob_inode, "outblob");

    Ok(true)
}
