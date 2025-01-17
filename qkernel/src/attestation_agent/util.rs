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

pub type AttestationToken = Vec<u8>;

pub enum InitDataStatus {
    Match,
    NoMatch,
    Unsupported,
}

pub mod algorithem {
    pub enum HashAlgo {
        Sha256
    }
}

//
// See CoCo - attestation-agent - docs/KBS_URI.mD
//
#[derive(Debug, Default)]
pub struct ResourceUri {
    pub kbs_address: String,
    pub repository: String,
    pub r#type: String,
    pub tag: String,
    pub query: Option<String>,
}

//
// See CoCo - attestation-agent - issues 113
//
#[derive(Default)]
pub struct AnnotationPacket {
    pub kid: ResourceUri,
    pub wrapped_data: String,
    pub iv: String,
    pub wrap_type: String,
}


#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub(crate) struct ProtectedHeader {
    // Enc-Alg for encrypted key
    pub alg: String,
    // Enc-Alg for ciphertext
    pub enc: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub(crate) struct Resource {
    pub protected: ProtectedHeader,
    pub encrypted_key: Vec<u8>,
    pub aad: Option<Vec<u8>>,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>
}

pub mod token {
    use crate::{qlib::linux::time::Timespec, MonotonicNow};
    use alloc::string::String;
    use crate::qlib::common::Result;

    #[derive(Deserialize, Clone)]
    pub(self) struct JWT {
        pub(self) exp: i64,
        pub(self) iat: i64,
        iss: String,
        jwk: String,
    }

    #[derive(Default, Clone)]
    pub struct Token {
        pub inhalt: String,
        exp: Timespec,
        not_before: Timespec
    }

    impl Token {
        pub(crate) fn new(token: String) -> Result<Self> {
            //TODO: decode to str - JWT format
            //Extract time stamps
            let claim_enc = token.split(".").nth(1)
                .expect("AA - JWT expected format: header.claim.signature");
            let claim = base64::decode_config(claim_enc, base64::URL_SAFE_NO_PAD)
                .expect("AA - Failed to decode JWToken");
            let jwt: JWT = serde_json::from_slice(claim.as_slice())
                .expect("AA - Failed to deserialize JWT token");
            let _exp: Timespec = Timespec {
                tv_sec: jwt.exp,
                tv_nsec: 0i64,
            };
            let iat: Timespec = Timespec {
                tv_sec: jwt.iat,
                tv_nsec: 0i64,
            };
            Ok(Self{
                inhalt: token,
                exp: _exp,
                not_before: iat,
            })
        }

        pub(crate) fn is_valid(&self) -> bool {
            let now = MonotonicNow();
            if self.inhalt.is_empty() || self.exp.tv_sec < now {
                debug!("AA - Invalid token");
                return false;
            }
            true
        }
    }
}

pub mod keys {
    use crate::qlib::common::Error;
    use crate::qlib::common::Result;

    use aes_gcm::aead::OsRng;
    use alloc::{string::String, vec::Vec};
    use rsa::{PublicKeyParts, RsaPrivateKey, RsaPublicKey};

    #[derive(Serialize, Deserialize, Clone, Default)]
    pub struct TeePubKey {
        pub alg: String,
        #[serde(rename = "n")]
        pub k_mod: String,
        #[serde(rename = "e")]
        pub k_exp: String,
    }

    #[derive(Clone)]
    pub struct TeeKeyPair {
        priv_key: RsaPrivateKey,
        pub pub_key: RsaPublicKey,
        pub key_length: usize,
        pub alg: String
    }

    impl TeeKeyPair {
        pub fn new(pub_key_length: usize, _alg: String) -> Self {
            let mut rng = OsRng;
            let pvk = RsaPrivateKey::new(&mut rng, pub_key_length)
                .map_err(|e| Error::Common(
                    format!("VM: Tee Rsa-PrivKey generation failed:{:?}", e)))
                .unwrap();
            let pbk = RsaPublicKey::from(&pvk);

            Self {
                pub_key: pbk,
                priv_key: pvk,
                key_length: pub_key_length,
                alg: _alg
            }
        }

        pub fn export_tee_pub_key(&self) -> TeePubKey {
            let n = base64::encode(self.pub_key.n().to_bytes_be());
            let e = base64::encode(self.pub_key.e().to_bytes_be());
            TeePubKey{
                alg: self.alg.clone(),
                k_mod: n,
                k_exp: e,
            }
        }

        pub fn decrypt(&self, cipher: Vec<u8>) -> Result<Vec<u8>> {
            let res = self.priv_key.decrypt(rsa::PaddingScheme::PKCS1v15Encrypt, &cipher);
            let res = res.expect("RSA_DEC failed");
            Ok(res)
        }
    }
}

pub(super) mod connection {
    use core::convert::TryFrom;

    use aes_gcm::aead::OsRng;
    use alloc::string::ToString;
    use alloc::{string::String, sync::Arc, vec::Vec};
    use embedded_io;
    use embedded_tls::blocking::*;
    use crate::attestation_agent::util::Resource;
    use crate::qlib::kernel::fs::file::{FileOperations, SockOperations};
    use crate::qlib::common::Result;

    use crate::qlib::kernel::kernel::time::Time;
    use crate::qlib::linux_def::{DataBuff, IoVec, MemoryDef, MsgHdr, MsgType};
    use crate::{MonotonicNow, GUEST_HOST_SHARED_ALLOCATOR};
    use crate::{qlib::{kernel::{fs::{file::File, flags::SettableFileFlags},
        socket::{hostinet::hostsocket::newHostSocketFile, socket::Provider}, Kernel},
        linux_def::{AFType, Flags, LibcConst, SocketFlags, SocketType, SysErr}},
        tcpip::tcpip::{SockAddr, SockAddrInet}, Error, Task};

    use super::keys::{TeeKeyPair, TeePubKey};

    pub enum ConnError {
        NoTlsConn,
        TlsSockSend,
        TlsSockRead,
        BadResp(u16),
    }

    impl ConnError {
        pub fn to_err(e: ConnError) -> crate::qlib::common::Error {
            let _e = String::try_from(e).unwrap();
            crate::qlib::common::Error::IOError(_e)
        }
    }

    impl TryFrom<ConnError> for String {
        type Error = crate::qlib::common::Error;
        fn try_from(value: ConnError) -> Result<Self> {
            let res = match value {
                ConnError::NoTlsConn => {
                    String::from("TlsConn failed")
                },
                ConnError::TlsSockSend => {
                    String::from("TlsSockSend failed")
                },
                ConnError::TlsSockRead => {
                    String::from("TlsSockRead failed")
                },
                ConnError::BadResp(s) => {
                    format!("BadResp:{}",s)
                },
            };

            Ok(res)
        }
    }

    impl embedded_io::Read for HttpSClient {
        fn read<'a>(&'a mut self, read_buffer: &'a mut [u8])
            -> core::result::Result<usize, Self::Error> {
            let sock_op = self.socket_file.FileOp.clone();
            let cur_task = Task::Current();
            let buff_len = read_buffer.len();
            if buff_len <= self.read_buf.len() {
                read_buffer.copy_from_slice(&self.read_buf[..buff_len]);
                self.read_buf.drain(0..buff_len);
                let mut buff = [0u8; Self::READ_BUFF_LEN as usize];
                let res = self.try_get_data_from_server(cur_task, &sock_op, &mut buff);
                if res.is_err() {
                    info!("VM: Failed to get data from server - {:?}", res);
                } else {
                    let data_size = res.unwrap();
                    let buff_slice = buff.as_slice();
                    let mut buff_vec = buff_slice[..(data_size as usize)].to_vec();
                    self.read_buf.append(&mut buff_vec);
                }
                return Ok(buff_len);
            }
            let cur_task = Task::Current();
            let mut deadline = None;
            let mut flags = 0 as i32;
            let dl = sock_op.SendTimeout();

            if dl > 0 {
                let now = MonotonicNow();
                deadline = Some(Time(dl + now));
            } else if dl < 0 {
                flags |= MsgType::MSG_DONTWAIT;
            }
            let buffer = DataBuff::New(self.read_buf_len);
            let mut buffer_iovec = buffer.Iovs(buffer.Len());
            match sock_op.RecvMsg(cur_task, &mut buffer_iovec, flags, deadline, false, 0) {
                Ok(res) => {
                    let (n, mut _mflags, _, _) = res;
                    let buff_slice = buffer.buf.as_slice();
                    let mut buf_vec = buff_slice[..(n as usize)].to_vec();
                    self.read_buf.append(&mut buf_vec);

                    if self.read_buf.len() < buff_len {
                        let read_buff_slice_len = self.read_buf.len();
                        let read_to_slice = &mut read_buffer[..read_buff_slice_len];
                        read_to_slice.clone_from_slice(&self.read_buf.as_slice());
                        self.read_buf.drain(0..read_buff_slice_len);
                        return Ok(read_buff_slice_len);
                    } else {
                        let read_buffer_slice = &self.read_buf[..read_buffer.len()];
                        read_buffer.clone_from_slice(read_buffer_slice);
                        self.read_buf.drain(0..read_buffer.len());
                        return Ok(read_buffer.len());
                    }
                },
                Err(_e) => {
                    return Err(TlsError::Io(embedded_io::ErrorKind::Other));
                }
            };
        }
    }

    pub fn tls_connection<'a>(client: &'a HttpSClient, read_rec: &'a mut [u8],
        write_rec: &'a mut [u8], rng: &mut OsRng)
        -> core::result::Result<TlsConnection<'a, HttpSClient, Aes128GcmSha256>,
            embedded_tls::TlsError> {
        let tls_conf = TlsConfig::new().enable_rsa_signatures();
        let mut tls_con: TlsConnection<HttpSClient, Aes128GcmSha256> =
            TlsConnection::new(client.clone(), read_rec, write_rec);
        let res = tls_con.open::<OsRng, NoVerify>(TlsContext::new(&tls_conf, rng));
        match res {
            Ok(_) => {
                debug!("VM: TLS conn created");
                return Ok(tls_con);
            },
            Err(e) => {
                error!("VM: TLS conn creation failed with: {:?}", e);
                return Err(e);
            }
        };
    }

    impl embedded_io::ErrorType for HttpSClient {
        type Error = embedded_tls::TlsError;
    }

    impl embedded_io::Write for HttpSClient {
        fn write<'a>(&'a mut self, write_buf: &'a [u8])
            -> core::result::Result<usize, Self::Error> {
            let sock_op = self.socket_file.FileOp.clone();
            let cur_task = Task::Current();
            let mut package = MsgHdr::default();
            package.msgName = 0;
            package.nameLen = 0;

            let mut deadline = None;
            let mut flags = 0 as i32;

            let dl = sock_op.SendTimeout();

            if dl > 0 {
                let now = MonotonicNow();
                deadline = Some(Time(dl + now));
            } else if dl < 0 {
                flags |= MsgType::MSG_DONTWAIT;
            }

            let buf_len = write_buf.len();
            let mut req_buf = DataBuff::New(buf_len);
            //let internal_write_buf = write_buf.to_vec();
            let mut shared_buff = Vec::with_capacity_in(buf_len, GUEST_HOST_SHARED_ALLOCATOR);
            shared_buff.copy_from_slice(write_buf);

            req_buf.buf = shared_buff;
            let src = req_buf.Iovs(buf_len);
            let res = sock_op.SendMsg(cur_task, &src, flags, &mut package, deadline);
            if res.is_err() {
                error!("VM: TLS write failed - socker error:{:?}", res);
                return Err(embedded_tls::TlsError::Io(embedded_io::ErrorKind::Other));
            }

            Ok(res.unwrap() as usize)
        }

        fn flush<'a>(&'a mut self) -> core::result::Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct Request {
        #[serde(rename = "version")]
        pub protocol_version: String,
        pub tee: String,
        #[serde(rename = "extra-params")]
        pub extr_param: String
    }

    impl Request {
        pub fn new(_tee: String, kbs_version: String, extra_params: String) -> Self {
            Self {
                protocol_version: kbs_version,
                tee: _tee,
                extr_param: extra_params
            }
        }
    }

    #[derive(Serialize, Deserialize, Clone)]
    pub struct AttestationReport {
        #[serde(rename = "tee-pubkey")]
        pub pub_tkey: TeePubKey,
        #[serde(rename = "tee-evidence")]
        pub evidence: String,
    }

    #[derive(Deserialize, Clone)]
    pub struct AttestationResponce {
        pub token: String
    }


    #[derive(Debug, Clone, Default)]
    pub(crate) struct KbsResponce {
        pub nonce: Option<String>,
        pub cookie: Option<String>,
        pub token: Option<String>,
        pub resource: Option<Resource>,
        pub extra_params: Option<String>
    }

    #[derive(Clone)]
    pub enum RespType {
        Challenge(Vec<u8>),
        Attestation(Vec<u8>),
        Resource(Vec<u8>)
    }

    #[derive(Serialize, Deserialize, Clone, Default)]
    pub struct KbsChallenge {
        pub nonce: String,
        #[serde(rename = "extra-params")]
        pub extra_params: String
    }

    pub enum HttpReq {
        Get(String),
        Post(String),
    }

    #[derive(Clone)]
    pub struct HttpSClient {
        pub socket_file: Arc<File>,
        pub cookie: String,
        pub read_buf: Vec<u8>,
        pub read_buf_len: usize,
        pub retry_read_times: usize,
        pub tee_key: Option<TeeKeyPair>,
    }

    impl HttpSClient {
        const HTTP_OK: u16 = 200;
        const HTTP_HDR_COOKIE: &'static str = "set-cookie";
        const HTTP_HDR_CONT_LENGTH: &'static str = "content-length";
        const EMPTY_PAYLOAD: u16 = 1;
        const PARTIAL_PACKET: u16 = 0;
        const READ_BUFF_LEN: usize = 30000;

        pub fn create_http_client(kbs_address: &String, key_length: usize, encr_alg: String) -> Self {
            if kbs_address.is_empty() {
                panic!("VM: KBS address - expected IP:PORT - found empty");
            }
            let (_ip, _port) = kbs_address.split_once(":")
                .expect("VM: KBS address expeted as IP:PORT");
            let port: u16 = _port.parse()
                .expect("VM: Failed to parse PORT to u16");
            let mut ip: [u8; 4] = [0u8; 4];
            let ip_parts: Vec<&str> = _ip.split(":").collect();
            assert_eq!(ip_parts.len(), ip.len());
            for i in 0..ip_parts.len() {
                ip[i] = ip_parts[i].parse()
                    .expect("VM: Failed to parse in u8");
            }

            let sock_family = AFType::AF_INET;
            let sock_type = LibcConst::SOCK_STREAM as i32;
            let protocol = 0;
            let provider = SocketProvider{
                family: sock_family
            };

            let task = Task::Current();
            let socket = provider
                .Socket(task, sock_type, protocol)
                .expect("VM: Failed to get socket file")
                .unwrap();

            let flags = SettableFileFlags {
                NonBlocking: sock_type & Flags::O_NONBLOCK != 0,
                ..Default::default()
            };

            socket.SetFlags(task, flags);
            let blocking = !socket.Flags().NonBlocking;
            assert_eq!(blocking, true);
            let sock_file_op = socket.FileOp.clone();

            let _addr = SockAddr::Inet(SockAddrInet {
                Family: AFType::AF_INET as u16,
                Port : port,
                Addr: ip,
                Zero: [0; 8],
            });

            let binding = _addr.ToVec().unwrap();
            let sock_addr = binding.as_slice();
            sock_file_op.Connect(task, sock_addr, blocking)
                .expect("AA - Socket connection failed");
            let tk = TeeKeyPair::new(key_length, encr_alg);

            Self {
                socket_file: socket,
                cookie: String::default(),
                read_buf: Vec::new(),
                tee_key: Some(tk),
                //Arbitratry valuees
                read_buf_len: Self::READ_BUFF_LEN,
                retry_read_times: 10000,
            }
        }

        fn try_get_data_from_server(&self, task: &Task, socket_ops: &FileOperations,
            read_buffer: &mut [u8]) -> Result<i64> {
            let mut package = MsgHdr::default();
            package.msgName = 0;
            package.nameLen = 0;
            let flags = MsgType::MSG_DONTWAIT;
            let mut deadline = None;
            let dl = socket_ops.SendTimeout();

            if dl > 0 {
                let now = MonotonicNow();
                deadline = Some(Time(dl + now));
            }
            let resp_buff = DataBuff::New(read_buffer.len());
            let mut dst = resp_buff.Iovs(resp_buff.Len());
            let mut bytes: i64 = 0;
            let mut loop_times = 0;

            while loop_times < self.retry_read_times {
                match socket_ops.RecvMsg(task, &mut dst, flags, deadline, false, 0) {
                    Ok(res) => {
                        let (n, mut _mflags, _, _) = res;
                        assert!(n > 0);
                        bytes += n;
                        if bytes as usize == read_buffer.len() {
                            break;
                        }
                        let start_pos;
                        unsafe {
                            start_pos = resp_buff.buf.as_ptr().offset(bytes as isize);
                        }
                        let io_vec = IoVec {
                            start: start_pos as u64,
                            len: resp_buff.Len() - bytes as usize,
                        };
                        dst = [io_vec];
                    },
                    Err(e) => match e {
                        Error::SysError(SysErr::EWOULDBLOCK) => {
                            debug!("VM: Socker Recv - EWOULDBLOCK");
                        },
                        _ => {
                            debug!("VM: Try getting data from server failed - err:{:?}", e);
                            break;
                        }
                    }
                };
                loop_times += 1;
            }
            assert!(bytes >= 0);
            read_buffer[0..(bytes as usize)].clone_from_slice(&resp_buff.buf[0..(bytes as usize)]);
            Ok(bytes)
        }

        pub fn send_request(tls_conn: &mut TlsConnection<HttpSClient, Aes128GcmSha256>,
            request: String) -> Result<Vec<u8>> {
            let mut rx_buf = [0u8; MemoryDef::PAGE_SIZE_4K as usize];
            let send_buf = request.as_bytes();
            let res = tls_conn.write(send_buf);
            if res.is_err() {
                return Err(ConnError::to_err(ConnError::TlsSockSend));
            }
            let read_bytes = tls_conn.read(&mut rx_buf);
            if read_bytes.is_err() {
                return Err(ConnError::to_err(ConnError::TlsSockRead));
            }
            let read_slice = rx_buf.as_slice();
            let _data = read_slice[..read_bytes.unwrap()].to_vec();
            Ok(_data)
        }

        pub fn build_request(tee: String, kbs_version: String, extra_params: String,
            request_type: &HttpReq) -> String {
            let req = Request::new(tee, kbs_version, extra_params);
            let serialized_req = serde_json::to_string(&req)
                .expect("VM: Failed to serialize kbs request");
            let req_len = serialized_req.as_bytes().len();
            let binding = Self::create_req_head(request_type);
            let head = binding.as_str();
            let request = format!("{}{}\r\n\r\n{}",head, req_len, serialized_req);
            request
        }

        pub fn build_attest_report(pub_tee_key: TeePubKey,
            tee_evidence: String, request_type: &HttpReq) -> String {
            let att_report = AttestationReport {
                pub_tkey: pub_tee_key,
                evidence: tee_evidence,
            };
            let serialized_rep = serde_json::to_string(&att_report)
                .expect("VM: Failed to serialize attestation report");
            let rep_len = serialized_rep.as_bytes().len();
            let binding = Self::create_req_head(request_type);
            let head = binding.as_str();
            let report = format!("{}{}\r\n\r\n{}", head, rep_len, serialized_rep);
            report
        }

        fn create_req_head(request_type: &HttpReq) -> String {
            let head = match request_type {
                HttpReq::Get(_head) => {
                    format!("GET {}", _head.as_str())
                },
                HttpReq::Post(_head) => {
                    format!("POST {}", _head.as_str())
                },
            };
            head
        }

        pub(crate) fn parse_http_responce(responce: RespType) -> Result<KbsResponce> {
            let mut headers = [httparse::EMPTY_HEADER; 4];
            let mut http_resp = httparse::Response::new(&mut headers);

            let res = match &responce {
                RespType::Resource(resp) | RespType::Challenge(resp)
                | RespType::Attestation(resp) =>
                    http_resp.parse(resp.as_slice())
                        .expect("VM: Parse of responce failed")
            };
            if res.is_partial() {
                error!("VM: server responce is partial");
                return Err(ConnError::to_err(ConnError::BadResp(Self::PARTIAL_PACKET)));
            } else {
                let status = http_resp.code.unwrap();
                if status != Self::HTTP_OK {
                    error!("VM: Http return status - {}", status);
                    return Err(ConnError::to_err(ConnError::BadResp(status)));
                }
            }
            let responce: KbsResponce = match &responce {
                RespType::Challenge(resp) => {
                    let mut _cookie: Option<String> = None;
                    for header in http_resp.headers {
                        if header.name == Self::HTTP_HDR_COOKIE {
                            _cookie = Some(
                                String::from_utf8_lossy(header.value)
                                    .to_string()
                            );
                        }
                    }
                    let payload = res.unwrap();
                    if payload == 0 {
                        error!("VM: Http - got empty payload");
                        return Err(ConnError::to_err(ConnError::BadResp(Self::EMPTY_PAYLOAD)));
                    }
                    let payload_body = &resp[payload..];
                    let challenge: KbsChallenge =
                        serde_json::from_slice(payload_body)
                        .expect("VM: Payload serialization failed");
                    let extra_param = if !challenge.extra_params.is_empty() {
                        Some(challenge.extra_params)
                        } else {
                        None
                    };
                    KbsResponce {
                        cookie: _cookie,
                        nonce: Some(challenge.nonce),
                        token: None,
                        resource: None,
                        extra_params: extra_param,
                    }
                },
                RespType::Attestation(resp) => {
                    let payload = res.unwrap();
                    if payload == 0 {
                        error!("VM: Http - expected token, got empty payload");
                        return Err(ConnError::to_err(ConnError::BadResp(Self::EMPTY_PAYLOAD)));
                    }
                    let payload_body = &resp[payload..];
                    let res: AttestationResponce =
                        serde_json::from_slice(payload_body)
                        .expect("VM: Payload serialization failed");
                    let token = res.token;
                    KbsResponce {
                        nonce: None,
                        cookie: None,
                        token: Some(token),
                        resource: None,
                        extra_params: None,
                    }
                },
                RespType::Resource(resp) => {
                    let payload = res.unwrap();
                    if payload == 0 {
                        error!("VM: Http - resource, got empty payload");
                        return Err(ConnError::to_err(ConnError::BadResp(Self::EMPTY_PAYLOAD)));
                    }
                    let payload_body = &resp[payload..];
                    let resp_res: Resource =
                        serde_json::from_slice(payload_body)
                        .expect("VM: Payload serialization failed");
                    KbsResponce {
                        nonce: None,
                        cookie: None,
                        token: None,
                        resource: Some(resp_res),
                        extra_params: None,
                    }
                }
            };
            Ok(responce)
        }
    }

    struct SocketProvider {
        pub family: i32
    }

    impl Provider for SocketProvider {
        fn Socket(&self, task: &crate::Task, stype: i32, protocol: i32)
            -> Result<Option<Arc<File>>> {
            let non_blocking = stype & SocketFlags::SOCK_NONBLOCK != 0;
            let stype = (stype & SocketType::SOCK_TYPE_MASK)
                | SocketFlags::SOCK_CLOEXEC;
            let res = Kernel::HostSpace::Socket(self.family,
                stype, protocol);
            if res < 0 {
                return Err(Error::SysError(-res as i32));
            }

            let file = newHostSocketFile(task, self.family, res as i32,
                stype & SocketType::SOCK_TYPE_MASK, non_blocking, None)?;

            Ok(Some(Arc::new(file)))
        }

        fn Pair(
            &self,
            _task: &crate::Task,
            _stype: i32,
            _protocol: i32,
        ) -> Result<Option<(Arc<File>, Arc<File>)>> {
            Err(Error::SysError(SysErr::EOPNOTSUPP))
        }
    }
}
