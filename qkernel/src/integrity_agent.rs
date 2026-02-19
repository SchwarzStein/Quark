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

use alloc::{string::String, vec::Vec};
use hashbrown::{HashMap, HashSet};
use sha2::{Digest, Sha512};
use spin::mutex::Mutex;
use crate::qlib::common::{Result, Error};
use crate::qlib::kernel::fs::host::hostinodeop::Mappable;
use crate::qlib::linux_def::SysErr;
use crate::qlib::{kernel::{fs::file::File, task::Task},
    mem::block_allocator::BLOCK_SIZE,
    pagetable::AlignedAllocator, range::Range};

lazy_static!{
    pub static ref INTEGRITY_AGENT: Mutex<IntegrityAgent> =  Mutex::new(IntegrityAgent::default());
}

#[derive(Deserialize, Debug)]
struct ManifestItem {
    path: String,
    hash: String
}

#[derive(Default, Debug)]
struct Manifest {
    items: HashMap<String, String>,//(path, hash)//
}

#[derive(Default)]
pub struct IntegrityAgent {
    manifest: Manifest,
    cached_set: HashSet<Mappable>
}

impl IntegrityAgent {
    pub fn add_manifest(&mut self, manifest_json: Vec<u8>) {
        let manifest_list: Vec<ManifestItem> = serde_json::from_slice(manifest_json.as_slice())
            .expect("VM: Failed to deserialize manifest");
        for item in manifest_list {
            if let Some(_) = self.manifest.items.insert(item.path.clone(), item.hash) {
                panic!("VM: Duplicated manifest item:{:?}", item.path);
            }
        }
    }

    pub fn try_protect_item(&mut self, file: &File, force_validate: bool) -> Result<()> {
        let fpath = file.Dirent.MyFullName();
        if let Some(h) = self.manifest.items.get(&fpath) {
            if file.Writable() {
                return Err(Error::SysError(SysErr::EPERM));
            }
            let manifet_item = ManifestItem {
                path: fpath.clone(),
                hash: h.clone()
            };
            let res = self.validate_item(manifet_item, file);
            if res.is_err() {
                panic!("VM: failed to validate protected file:{:?} - error:{:?}",
                    fpath, res.unwrap_err());
            }
        } else {
            if force_validate {
                panic!("VM: Item:{:?} must be in manifest but hash not provided.", fpath);
            }
            info!("VM: file:{:?} not in manifest.", fpath);
        }
        Ok(())
    }

    fn validate_item(&mut self, manifest_item: ManifestItem, file: &File) -> Result<()> {
        if self.check_hashed(file) {
            return Ok(());
        }
        if let Ok(blocks) = self.cache_file(file) {
            let mut hasher: Sha512 = Sha512::new();
            for block in blocks {
                let _slice = unsafe {
                    core::slice::from_raw_parts(block as *const u8, BLOCK_SIZE as usize)
                };
                hasher.update(_slice);
            }
            let final_hash = hasher.finalize();
            let hash_string = final_hash.iter()
                .map(|c| format!("{:2x}", c))
                .collect::<String>();
            debug!("VM: Hash:{:?} of file:{:?}", hash_string, manifest_item.path);
            if manifest_item.hash != hash_string {
                panic!("VM: mismatch hashes for file:{:?}: expected:{:?} - computed:{:?}",
                manifest_item.path, manifest_item.hash, hash_string);
            } else {
                let mappable = file.Mappable()
                    .unwrap()
                    .HostIops()
                    .expect("Failed to get host-iops for mmapable")
                    .lock()
                    .mappable
                    .clone()
                    .expect("Failed to get mappable");
                assert_ne!(self.cached_set.insert(mappable), false);
                return Ok(());
            }
        } else {
            panic!("VM: failed to cache file:{:?}", manifest_item.path);
        }
    }

    fn cache_file(&mut self, file: &File) -> Result<Vec<u64>> {
        let binding = file.Mappable()
            .unwrap()
            .HostIops()
            .expect("Failed to get host-iops for mmapable");
        let mut hinodop = binding.lock();

        let current_task = Task::Current();
        let fsize = hinodop.size;
        let range = Range::New(0u64, fsize as u64);
        let res = hinodop.MapInternal(current_task, &range)
            .expect("Failed to map shared file");
        let mut blocks = Vec::new();
        for iovec in res {
            let start = iovec.start;
            let block = Self::cache_allocate()
                .expect("Failed to allocate memory block for protected file");
            unsafe {
                core::ptr::copy_nonoverlapping(start as *const u8,
                    block as *mut u8, BLOCK_SIZE as usize);
            }
            hinodop.insert_cached_mapping(start, block);
            blocks.push(block);
        }
        hinodop.cached_protected_mapping();
        hinodop.release_shared_for_cached();
        Ok(blocks)
    }

    fn check_hashed(&self, file: &File) -> bool {
        file.Mappable()
            .unwrap()
            .HostIops()
            .expect("Failed to get host-iops for mmapable")
            .lock()
            .mappable
            .clone()
            .map_or(false,
                |m| {
                    self.cached_set.contains(&m)
                }
            )
    }

    pub fn clear_cached_file(&mut self, mappable: &Mappable) {
        if self.cached_set.contains(mappable) {
            let mut mappable_locked = mappable.lock();
            assert!(mappable_locked.f2pmap.is_empty()
               && mappable_locked.p2pmap.is_empty());
            mappable_locked.release_cached_protected();
            self.cached_set.remove(mappable);
        }
    }

    fn cache_allocate() -> Result<u64> {
        let alloc = AlignedAllocator::New(BLOCK_SIZE as _, BLOCK_SIZE as _);
        let addr = alloc.Allocate()?;
        Ok(addr)
    }

    pub fn cache_dealocate(address: u64) -> Result<()> {
        let alloc = AlignedAllocator::New(BLOCK_SIZE as _, BLOCK_SIZE as _);
        alloc.Free(address)
    }
}


