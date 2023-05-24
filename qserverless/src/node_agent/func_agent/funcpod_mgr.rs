// Copyright (c) 2021 Quark Container Authors
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

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::Mutex;
use std::collections::BTreeMap;
use core::ops::Deref;
use tokio::sync::Notify;

use qobjs::common::*;

use crate::func_agent::funcpod::FuncPod;

#[derive(Debug, Default)]
pub struct FuncPodMgrInner {
    pub closeNotify: Arc<Notify>,
    pub stop: AtomicBool,
    pub currInstanceId: AtomicU64,

    pub pods: Mutex<BTreeMap<String, FuncPod>>,

}

#[derive(Debug, Default, Clone)]
pub struct FuncPodMgr(pub Arc<FuncPodMgrInner>);

impl Deref for FuncPodMgr {
    type Target = Arc<FuncPodMgrInner>;

    fn deref(&self) -> &Arc<FuncPodMgrInner> {
        &self.0
    }
}

impl FuncPodMgr {
    pub fn AddPod(&self, id: &str, pod: &FuncPod) -> Result<()> {
        self.pods.lock().unwrap().insert(id.to_string(), pod.clone());
        return Ok(())
    }

    pub fn GetPod(&self, id: &str) -> Result<FuncPod> {
        match self.pods.lock().unwrap().get(id) {
            None => return Err(Error::ENOENT),
            Some(pod) => return Ok(pod.clone()),
        }
    }
}

