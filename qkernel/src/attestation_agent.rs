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

pub mod config;
pub mod attester;
pub mod kbc;
pub mod util;

use core::convert::TryFrom;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use crate::qlib::common::Result;
use crate::{drivers::attestation::{Challenge, Responce},
    qlib::{config::CCMode, kernel::arch::tee::{get_tee_type,
        is_hw_tee}}};

use self::attester::cca;
use self::kbc::{kbc_build, Kbc};
use self::util::{AttestationToken, InitDataStatus};
use self::{attester::Attester, config::AaConfig};

pub type AttEvidence = Responce;


pub trait AttestationAgentT {
    fn get_hw_tee_type(&self) -> Option<CCMode> {
        if is_hw_tee() {
            return Some(get_tee_type());
        }
        None
    }

    // Check if data matches host initial data provided during launch of TEE enviroment.
    // Possible Support: TDX, SEV/SNP
    fn check_init_data(&self, _init_data:Vec<u8>) -> Result<InitDataStatus> {
        Ok(InitDataStatus::Unsupported)
    }

    fn get_attestation_token(&mut self) -> Result<AttestationToken>;

    // Get measuremnt blob from TEE.
    fn get_tee_evidence(&self, challenge: String) -> Result<AttEvidence>;

    // Extend runtime measuremnt register of TEE when available.
    // Possible Support: TDX, SNV/SNP
    fn extend_runtime_measurement(&self) -> Result<bool> {
        Ok(false)
    }
}

pub struct AttestationAgent {
    attester: Attester,
    kbc: Kbc,
    config: AaConfig,
}

impl AttestationAgent {
    pub fn new(config_path: Option<String>) -> Result<Self> {
        let _attester = match get_tee_type() {
            CCMode::Cca => Box::<cca::CcaAttester>::default(),
            CCMode::SevSnp => todo!(),
            CCMode::Normal | CCMode::NormalEmu
            | CCMode::None => panic!("AA: No AA instance for CC mode ::None")
        };

        let _config = AaConfig::new(config_path);
        let _kbc = kbc_build(kbc::KbsClientType::BckgCheck,
            _config.kbs_url(), _config.kbs_cert());
        Ok(AttestationAgent {
            attester: _attester,
            kbc: _kbc,
            config: _config,
        })
    }
}

impl AttestationAgentT for AttestationAgent {
    fn get_attestation_token(&mut self) -> Result<AttestationToken> {
        let tee = self.get_hw_tee_type()
            .expect("VM: AA - expected HW TEE backup");
        let tee = String::try_from(tee).unwrap();
        let (token, tkp, httpc) = self.kbc.as_ref().get_token(tee, &self)
            .expect("AA - failed to get token");
        let _ = self.kbc.update_token(Some(token.clone()), Some(tkp.clone()));
        if httpc.is_some() {
            self.kbc.update_intern(httpc.unwrap());
        }
        Ok(token.inhalt.clone().as_bytes().to_vec())
    }

    fn get_tee_evidence(&self, challenge: String) -> Result<AttEvidence> {
        //
        //TODO: There is no need other than debug to have the challenge as shared.
        //
//        let mut nonce: Challenge = challenge.as_bytes().to_vec_in(GUEST_HOST_SHARED_ALLOCATOR);
        let mut nonce: Challenge = challenge.as_bytes().to_vec();
        self.attester.get_tee_evidence(&mut nonce)
    }
}
