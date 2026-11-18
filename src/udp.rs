//! Windows kernel ETW UDP metadata only. No packet payload is captured.
use crate::collector::{self, Flow};
use serde::Serialize;
use std::{
    collections::HashMap,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
    sync::{Arc, Mutex},
    thread,
};
use windows_sys::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
        },
        System::{
            Diagnostics::Etw::*,
            Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
        },
    },
    core::GUID,
};

pub const IDLE_SECONDS: i64 = 30;
const MAX_FLOWS: usize = 16_384;
const UDP_GUID: GUID = GUID::from_u128(0xbf3a50c5_a9c9_4988_a005_2df0b7c80f80);
const SESSION_GUID: GUID = GUID::from_u128(0x7247b7dd_c76d_4ca5_97ab_7d16fe2298f4);
const SESSION_NAME: &str = "AtlasReseau.UDP";
fn same_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct Key {
    pid: u32,
    local: IpAddr,
    remote: IpAddr,
    local_port: u16,
    port: u16,
}
#[derive(Debug)]
struct Datagram {
    key: Key,
    received: bool,
}
struct Entry {
    first: i64,
    last: i64,
    sent: u64,
    received: u64,
    identity: Option<(String, String)>,
}
#[derive(Default)]
pub struct State {
    entries: HashMap<Key, Entry>,
    events: u64,
    rejected: u64,
    overflow: u64,
    pub running: bool,
    pub error: Option<String>,
}
pub type Shared = Arc<Mutex<State>>;

// V1/V2 fixed metadata layout, documented by Microsoft UdpIp_TypeGroup1/2.
// Incoming events contain packet source/destination, so reverse to local/remote.
fn decode(version: u8, opcode: u8, b: &[u8]) -> Option<Datagram> {
    if !matches!(version, 1 | 2) {
        return None;
    }
    let ipv6 = matches!(opcode, 26 | 27);
    if !matches!(opcode, 10 | 11 | 26 | 27) || b.len() < if ipv6 { 44 } else { 20 } {
        return None;
    }
    let pid = u32::from_le_bytes(b[0..4].try_into().ok()?);
    let (destination, source, dp, sp): (IpAddr, IpAddr, u16, u16) = if ipv6 {
        (
            Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).ok()?).into(),
            Ipv6Addr::from(<[u8; 16]>::try_from(&b[24..40]).ok()?).into(),
            u16::from_be_bytes([b[40], b[41]]),
            u16::from_be_bytes([b[42], b[43]]),
        )
    } else {
        (
            Ipv4Addr::from(<[u8; 4]>::try_from(&b[8..12]).ok()?).into(),
            Ipv4Addr::from(<[u8; 4]>::try_from(&b[12..16]).ok()?).into(),
            u16::from_be_bytes([b[16], b[17]]),
            u16::from_be_bytes([b[18], b[19]]),
        )
    };
    let received = matches!(opcode, 11 | 27);
    let (local, remote, local_port, port) = if received {
        (destination, source, dp, sp)
    } else {
        (source, destination, sp, dp)
    };
    if remote.is_unspecified() || port == 0 {
        return None;
    }
    Some(Datagram {
        key: Key {
            pid,
            local,
            remote,
            local_port,
            port,
        },
        received,
    })
}

impl State {
    fn ingest(&mut self, d: Datagram, time: i64) {
        self.events = self.events.saturating_add(1);
        if !self.entries.contains_key(&d.key) && self.entries.len() >= MAX_FLOWS {
            self.overflow = self.overflow.saturating_add(1);
            return;
        }
        let e = self.entries.entry(d.key).or_insert(Entry {
            first: time,
            last: time,
            sent: 0,
            received: 0,
            identity: None,
        });
        e.first = e.first.min(time);
        e.last = e.last.max(time);
        if d.received {
            e.received = e.received.saturating_add(1);
        } else {
            e.sent = e.sent.saturating_add(1);
        }
    }
    pub fn snapshot(&mut self, now: i64) -> Vec<Flow> {
        let result = self
            .entries
            .iter_mut()
            .map(|(k, e)| {
                let (app, path) = e
                    .identity
                    .get_or_insert_with(|| collector::process(k.pid))
                    .clone();
                Flow {
                    pid: k.pid,
                    app,
                    path,
                    local: k.local.to_string(),
                    local_port: k.local_port,
                    remote: k.remote.to_string(),
                    port: k.port,
                    state: if now - e.last <= IDLE_SECONDS {
                        "Activité récente"
                    } else {
                        "Inactif"
                    }
                    .into(),
                    public: collector::is_public(k.remote),
                    protocol: "UDP".into(),
                    quic_possible: k.port == 443 || k.local_port == 443,
                    first_event: Some(e.first),
                    last_event: Some(e.last),
                    sent: e.sent,
                    received: e.received,
                    domains: Vec::new(),
                    alerts: Vec::new(),
                }
            })
            .collect();
        // Include expired entries once so even a delayed poll persists them.
        self.entries.retain(|_, e| now - e.last <= IDLE_SECONDS);
        result
    }
}

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    // ETW guarantees record/payload validity for the duration of this callback.
    let r = unsafe { &*record };
    if !same_guid(&r.EventHeader.ProviderId, &UDP_GUID)
        || !matches!(r.EventHeader.EventDescriptor.Opcode, 10 | 11 | 26 | 27)
        || r.UserContext.is_null()
    {
        return;
    }
    let shared = unsafe { &*r.UserContext.cast::<Mutex<State>>() };
    let Ok(mut state) = shared.lock() else {
        return;
    };
    if r.UserData.is_null() {
        state.rejected += 1;
        return;
    }
    let b =
        unsafe { std::slice::from_raw_parts(r.UserData.cast::<u8>(), r.UserDataLength as usize) };
    if let Some(d) = decode(
        r.EventHeader.EventDescriptor.Version,
        r.EventHeader.EventDescriptor.Opcode,
        b,
    ) {
        // Without PROCESS_TRACE_MODE_RAW_TIMESTAMP, ETW converts QPC to FILETIME.
        let time = r.EventHeader.TimeStamp / 10_000_000 - 11_644_473_600;
        if time <= 0 || time > crate::now() + 60 {
            state.rejected += 1;
            return;
        }
        state.ingest(d, time);
    } else {
        state.rejected += 1;
    }
}

#[repr(C)]
struct Properties {
    props: EVENT_TRACE_PROPERTIES,
    name: [u16; 128],
}
fn properties() -> Box<Properties> {
    let mut p = Box::new(Properties {
        props: EVENT_TRACE_PROPERTIES::default(),
        name: [0; 128],
    });
    p.props.Wnode.BufferSize = size_of::<Properties>() as u32;
    p.props.Wnode.Guid = SESSION_GUID;
    p.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p.props.Wnode.ClientContext = 1;
    p.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    p.props.EnableFlags = EVENT_TRACE_FLAG_NETWORK_TCPIP;
    p.props.BufferSize = 64;
    p.props.MinimumBuffers = 8;
    p.props.MaximumBuffers = 64;
    p.props.FlushTimer = 1;
    p.props.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    p
}
struct Owner(HANDLE);
impl Drop for Owner {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

pub struct Capture {
    session: CONTROLTRACE_HANDLE,
    reader: PROCESSTRACE_HANDLE,
    props: Box<Properties>,
    worker: Option<thread::JoinHandle<()>>,
    _owner: Owner,
    pub shared: Shared,
}
#[derive(Serialize)]
pub struct Status {
    pub available: bool,
    pub error: Option<String>,
    pub events: u64,
    pub rejected: u64,
    pub dropped: u64,
    pub idle_seconds: i64,
}
impl Capture {
    pub fn start(shared: Shared) -> Result<Self, String> {
        let mutex_name = wide("Global\\AtlasReseau.UDP.Owner");
        let mutex = unsafe { CreateMutexW(ptr::null(), 1, mutex_name.as_ptr()) };
        if mutex.is_null() {
            return Err(format!("Verrou UDP indisponible (Windows {}).", unsafe {
                GetLastError()
            }));
        }
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            let wait = unsafe { WaitForSingleObject(mutex, 0) };
            if wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED {
                unsafe {
                    CloseHandle(mutex);
                };
                return Err("Une autre instance Atlas utilise déjà la collecte UDP.".into());
            }
        }
        let owner = Owner(mutex);
        let name = wide(SESSION_NAME);
        let mut props = properties();
        let mut session = CONTROLTRACE_HANDLE::default();
        let mut code = unsafe { StartTraceW(&mut session, name.as_ptr(), &mut props.props) };
        if code == ERROR_ALREADY_EXISTS {
            // The exclusive owner mutex proves no cooperating Atlas collector is alive.
            // Only reclaim our exact branded session and GUID, never another logger.
            let mut old = properties();
            let query = unsafe {
                ControlTraceW(
                    CONTROLTRACE_HANDLE::default(),
                    name.as_ptr(),
                    &mut old.props,
                    EVENT_TRACE_CONTROL_QUERY,
                )
            };
            if query == 0 && same_guid(&old.props.Wnode.Guid, &SESSION_GUID) {
                let stopped = unsafe {
                    ControlTraceW(
                        CONTROLTRACE_HANDLE::default(),
                        name.as_ptr(),
                        &mut old.props,
                        EVENT_TRACE_CONTROL_STOP,
                    )
                };
                if stopped == 0 {
                    props = properties();
                    code = unsafe { StartTraceW(&mut session, name.as_ptr(), &mut props.props) };
                }
            }
        }
        if code != 0 {
            return Err(if code == 5 {
                "UDP indisponible : lancer Atlas en administrateur pour activer ETW.".into()
            } else {
                format!("UDP indisponible : démarrage ETW, erreur Windows {code}.")
            });
        }
        let mut log = EVENT_TRACE_LOGFILEW {
            LoggerName: name.as_ptr().cast_mut(),
            Context: Arc::as_ptr(&shared).cast_mut().cast(),
            ..Default::default()
        };
        log.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        log.Anonymous2.EventRecordCallback = Some(on_event);
        let reader = unsafe { OpenTraceW(&mut log) };
        if reader.Value == u64::MAX {
            let err = unsafe { GetLastError() };
            unsafe {
                ControlTraceW(
                    session,
                    ptr::null(),
                    &mut props.props,
                    EVENT_TRACE_CONTROL_STOP,
                );
            }
            return Err(format!("Lecture ETW impossible : erreur Windows {err}."));
        }
        shared.lock().unwrap().running = true;
        let thread_state = shared.clone();
        let worker = thread::spawn(move || {
            // This Arc keeps the callback context alive through ProcessTrace.
            let code = unsafe { ProcessTrace(&reader, 1, ptr::null(), ptr::null()) };
            let mut s = thread_state.lock().unwrap();
            s.running = false;
            if code != 0 && code != 1223 {
                s.error = Some(format!("Lecture UDP interrompue : erreur ETW {code}."));
            }
        });
        Ok(Self {
            session,
            reader,
            props,
            worker: Some(worker),
            _owner: owner,
            shared,
        })
    }
    pub fn status(&self) -> Status {
        let mut props = properties();
        let code = unsafe {
            ControlTraceW(
                self.session,
                ptr::null(),
                &mut props.props,
                EVENT_TRACE_CONTROL_QUERY,
            )
        };
        let state = self.shared.lock().unwrap();
        Status {
            available: state.running && code == 0,
            error: state.error.clone().or_else(|| {
                if code != 0 {
                    Some(format!("État ETW indisponible : {code}"))
                } else {
                    None
                }
            }),
            events: state.events,
            rejected: state.rejected,
            dropped: state.overflow
                + props.props.EventsLost as u64
                + props.props.RealTimeBuffersLost as u64,
            idle_seconds: IDLE_SECONDS,
        }
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        unsafe {
            ControlTraceW(
                self.session,
                ptr::null(),
                &mut self.props.props,
                EVENT_TRACE_CONTROL_STOP,
            );
            CloseTrace(self.reader);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ipv4() -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[..4].copy_from_slice(&42u32.to_le_bytes());
        b[8..12].copy_from_slice(&[1, 1, 1, 1]);
        b[12..16].copy_from_slice(&[192, 168, 1, 5]);
        b[16..18].copy_from_slice(&443u16.to_be_bytes());
        b[18..20].copy_from_slice(&53000u16.to_be_bytes());
        b
    }
    #[test]
    fn decodes_ipv4_direction_ports_and_pid() {
        let b = ipv4();
        let d = decode(2, 10, &b).unwrap();
        assert_eq!(d.key.pid, 42);
        assert_eq!(d.key.remote.to_string(), "1.1.1.1");
        assert_eq!(d.key.local_port, 53000);
        assert_eq!(d.key.port, 443);
        let r = decode(2, 11, &b).unwrap();
        assert!(r.received);
        assert_eq!(r.key.remote.to_string(), "192.168.1.5");
        assert_eq!(r.key.local_port, 443);
    }
    #[test]
    fn rejects_unknown_versions_and_truncated_events() {
        assert!(decode(0, 10, &ipv4()).is_none());
        assert!(decode(3, 10, &ipv4()).is_none());
        assert!(decode(2, 10, &ipv4()[..19]).is_none());
        assert!(decode(2, 17, &ipv4()).is_none());
    }
    #[test]
    fn decodes_ipv6() {
        let mut b = vec![0u8; 44];
        b[..4].copy_from_slice(&7u32.to_le_bytes());
        b[8..24].copy_from_slice(&"2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap().octets());
        b[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        b[40..42].copy_from_slice(&443u16.to_be_bytes());
        b[42..44].copy_from_slice(&50000u16.to_be_bytes());
        let d = decode(2, 26, &b).unwrap();
        assert_eq!(d.key.remote.to_string(), "2606:4700:4700::1111");
        assert_eq!(d.key.port, 443);
        let r = decode(2, 27, &b).unwrap();
        assert_eq!(r.key.local_port, 443);
        assert!(r.received);
    }
    #[test]
    fn activity_expires_without_extending_last_event() {
        let mut s = State::default();
        s.ingest(decode(2, 10, &ipv4()).unwrap(), 100);
        s.ingest(decode(2, 10, &ipv4()).unwrap(), 102);
        let f = s.snapshot(110).remove(0);
        assert_eq!(f.last_event, Some(102));
        assert_eq!(f.sent, 2);
        assert!(f.quic_possible);
        let f = s.snapshot(133).remove(0);
        assert_eq!(f.state, "Inactif");
        assert_eq!(f.last_event, Some(102));
        assert!(s.snapshot(134).is_empty());
    }
}
