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

use alloc::string::{String, ToString};

use crate::{qlib::linux_def::{ATType, Flags, MemoryDef},
    syscalls::{sys_file::{close, openAt}, sys_read::Read}, Task};
use crate::qlib::common::Result;

const DEFAULT_AA_CONFIG_PATH: &'static str = "/etc/attestation-agent.conf";

pub enum AaConfigReq {
    KbsConig
}

#[derive(Deserialize)]
pub struct AaConfig {
    kbs_config: KbsConfig
}

impl AaConfig {
    pub fn new(config_path: Option<String>) -> Self {
        let res = match config_path {
            Some(path) => {
                let _kbs_conf = KbsConfig::new(&path);
                _kbs_conf
            },
            None => {
                let _kbs_conf = KbsConfig::new(&DEFAULT_AA_CONFIG_PATH);
                _kbs_conf
            }
        };
        let kbs_conf = res.expect("AA - Failed to construct KBS config");
        Self { kbs_config: kbs_conf }
    }

    pub fn kbs_url(&self) -> String {
        self.kbs_config.url.clone()
    }

    pub fn kbs_cert(&self) -> Option<String> {
        self.kbs_config.cert.clone()
    }
}

#[derive(Deserialize, Default, Clone)]
pub(self) struct KbsConfig {
    pub(self) url: String,
    pub(self) cert: Option<String>,
}

impl KbsConfig {
    pub(self) fn new(config_path: &str) -> Result<Self> {
        let task = Task::Current();
        let flags = Flags::O_RDONLY as u32;
        let dirFd = ATType::AT_FDCWD;
        let path_addr = config_path.as_ptr() as u64;
        let open_res = openAt(task, dirFd, path_addr, flags);
        if open_res.is_err() {
            error!("AA - failed to open config - err:{:?}", open_res.unwrap());
            return Err(crate::qlib::common::Error::IOError("Failed to open file".to_string()));
        }

        let fd = open_res.unwrap();
        let mut buf_file = [0u8;MemoryDef::PAGE_SIZE_4K as usize];
        let buf_addr = buf_file.as_mut_ptr() as u64;
        let read_res = Read(task, fd, buf_addr, MemoryDef::PAGE_SIZE_4K as i64);
        let _ = close(task, fd);
        if read_res.is_err() {
            error!("AA - failed to read the config file - err:{:?}", read_res.unwrap());
            return Err(crate::qlib::common::Error::IOError("Failed to read file".to_string()));
        }

        let bytes = read_res.unwrap() as usize;
        let conf: AaConfig = serde_json::from_slice(&buf_file[0..bytes])
            .expect("AA - failed to parse config file - read failed"); 
        Ok(
            Self {
            url: conf.kbs_config.url,
            cert: conf.kbs_config.cert,
        })
    }
}
