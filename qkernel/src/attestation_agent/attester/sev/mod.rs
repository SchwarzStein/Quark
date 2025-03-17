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

use super::AttesterT;
use crate::drivers::tee::attestation::{Challenge, Response, ATTESTATION_DRIVER};
use crate::qlib::common::{Result, Error};
use crate::qlib::linux_def::SysErr;

#[derive(Default)]
pub struct SevAttester();

impl SevAttester {
    const CHALLENGE_LEGTH_MAX: usize = 64;
    const CHALLENGE_LEGTH_MIN: usize = 0;

    pub fn challenge_range() -> (usize, usize) {
        (Self::CHALLENGE_LEGTH_MIN, Self::CHALLENGE_LEGTH_MAX)
    }
}

impl AttesterT for SevAttester {
    fn get_tee_evidence(&self, challenge: &mut Challenge) -> Result<Response> {
        let mut atd_l = ATTESTATION_DRIVER.lock();
        let res = if atd_l.valid_challenge(challenge) {
            atd_l.get_report(challenge)
        } else {
            error!("VM: challenge was not in valid format.");
            Err(Error::SystemErr(SysErr::EINVAL))
        };
        res
    }
}
