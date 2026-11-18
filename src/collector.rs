use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub pid: u32,
    pub app: String,
    pub path: String,
    pub local: String,
    pub local_port: u16,
    pub remote: String,
    pub port: u16,
    pub state: String,
    pub public: bool,
    #[serde(default = "tcp_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub quic_possible: bool,
    #[serde(default)]
    pub first_event: Option<i64>,
    #[serde(default)]
    pub last_event: Option<i64>,
    #[serde(default)]
    pub sent: u64,
    #[serde(default)]
    pub received: u64,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub alerts: Vec<crate::intel::Alert>,
}
fn tcp_protocol() -> String {
    "TCP".into()
}

#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn GetExtendedTcpTable(
        table: *mut c_void,
        size: *mut u32,
        order: i32,
        family: u32,
        class: u32,
        reserved: u32,
    ) -> u32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
    fn QueryFullProcessImageNameW(
        handle: *mut c_void,
        flags: u32,
        name: *mut u16,
        size: *mut u32,
    ) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

pub(crate) fn process(pid: u32) -> (String, String) {
    // Query-only access; protected processes may legitimately be unavailable.
    unsafe {
        let h = OpenProcess(0x1000, 0, pid);
        if h.is_null() {
            return (format!("PID {pid}"), String::new());
        }
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return (format!("PID {pid}"), String::new());
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        (path.rsplit('\\').next().unwrap_or(&path).to_string(), path)
    }
}
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_multicast()
                || a == 0
                || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 192 && b == 0 && (c == 0 || c == 2))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return is_public(v4.into());
            }
            let s = v.segments();
            (s[0] & 0xe000 == 0x2000) && !(s[0] == 0x2001 && (s[1] == 0xdb8 || s[1] < 0x200))
        }
    }
}
fn word(b: &[u8], n: usize) -> u32 {
    u32::from_ne_bytes(b[n..n + 4].try_into().unwrap())
}
fn port(b: &[u8], n: usize) -> u16 {
    u16::from_be_bytes([b[n], b[n + 1]])
}
fn state(n: u32) -> String {
    match n {
        3 => "SYN envoyé",
        4 => "SYN reçu",
        5 => "Établie",
        6 => "FIN WAIT 1",
        7 => "FIN WAIT 2",
        8 => "CLOSE WAIT",
        9 => "CLOSING",
        10 => "LAST ACK",
        11 => "TIME WAIT",
        12 => "DELETE TCB",
        _ => "Fermée",
    }
    .into()
}
pub fn collect() -> Result<Vec<Flow>, String> {
    let mut flows = Vec::new();
    let mut names = HashMap::new();
    for family in [2u32, 23] {
        let mut size = 0;
        let first =
            unsafe { GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, family, 5, 0) };
        if first != 122 && first != 0 {
            return Err(format!("Table TCP : erreur Windows {first}"));
        }
        let mut data = Vec::<u32>::new();
        let mut result = 122;
        for _ in 0..3 {
            data.resize((size as usize).div_ceil(4), 0);
            result = unsafe {
                GetExtendedTcpTable(data.as_mut_ptr().cast(), &mut size, 0, family, 5, 0)
            };
            if result != 122 {
                break;
            }
        }
        if result != 0 {
            return Err(format!("Table TCP : erreur Windows {result}"));
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), data.len() * 4) };
        if bytes.len() < 4 {
            return Err("Table TCP tronquée".into());
        }
        let stride = if family == 2 { 24 } else { 56 };
        let count = word(bytes, 0) as usize;
        if count > (bytes.len() - 4) / stride {
            return Err("Taille de table TCP invalide".into());
        }
        for b in bytes[4..4 + count * stride].chunks_exact(stride) {
            let (local, remote, lp, rp, status, pid): (IpAddr, IpAddr, _, _, _, _) = if family == 2
            {
                (
                    Ipv4Addr::from(<[u8; 4]>::try_from(&b[4..8]).unwrap()).into(),
                    Ipv4Addr::from(<[u8; 4]>::try_from(&b[12..16]).unwrap()).into(),
                    port(b, 8),
                    port(b, 16),
                    word(b, 0),
                    word(b, 20),
                )
            } else {
                (
                    Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).unwrap()).into(),
                    Ipv6Addr::from(<[u8; 16]>::try_from(&b[24..40]).unwrap()).into(),
                    port(b, 20),
                    port(b, 44),
                    word(b, 48),
                    word(b, 52),
                )
            };
            if status <= 2 || remote.is_unspecified() {
                continue;
            }
            let (app, path) = names.entry(pid).or_insert_with(|| process(pid)).clone();
            flows.push(Flow {
                pid,
                app,
                path,
                local: local.to_string(),
                local_port: lp,
                remote: remote.to_string(),
                port: rp,
                state: state(status),
                public: is_public(remote),
                protocol: tcp_protocol(),
                quic_possible: false,
                first_event: None,
                last_event: None,
                sent: 0,
                received: 0,
                domains: Vec::new(),
                alerts: Vec::new(),
            });
        }
    }
    Ok(flows)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn excludes_non_public_destinations() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "100.64.0.1",
            "192.0.2.1",
            "198.51.100.5",
            "203.0.113.4",
            "::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "::ffff:192.168.1.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public(ip.parse().unwrap()));
        }
    }
    #[test]
    fn network_port_order() {
        assert_eq!(port(&[1, 187, 0, 0], 0), 443);
    }
    #[test]
    fn windows_snapshot_is_readable() {
        assert!(collect().is_ok());
    }
}
