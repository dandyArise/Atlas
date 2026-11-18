//! Local reputation matching. Downloads are fixed trusted-source URLs only.
use crate::collector::Flow;
use ipnet::IpNet;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    net::IpAddr,
    os::windows::process::CommandExt,
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const MAX_DOWNLOAD: u64 = 8 * 1024 * 1024;
const SOURCES: [(&str, &str, &str, &str); 3] = [
    (
        "drop4",
        "Spamhaus DROP IPv4",
        "https://www.spamhaus.org/drop/drop_v4.json",
        "IP / CIDR",
    ),
    (
        "drop6",
        "Spamhaus DROP IPv6",
        "https://www.spamhaus.org/drop/drop_v6.json",
        "IP / CIDR",
    ),
    (
        "stevenblack",
        "StevenBlack",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "Domaines · publicité / malveillance",
    ),
];
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Alert {
    pub source: String,
    pub indicator: String,
    pub confidence: String,
    pub description: String,
    pub evaluated: i64,
}
struct List {
    id: String,
    name: String,
    url: String,
    kind: String,
    enabled: bool,
    updated: i64,
    error: Option<String>,
    copyright: String,
    nets: Vec<IpNet>,
    domains: HashSet<String>,
}
impl List {
    fn count(&self) -> usize {
        self.nets.len() + self.domains.len()
    }
}
pub struct Engine {
    lists: Vec<List>,
    dns: HashMap<IpAddr, Vec<(String, i64)>>,
    pub dns_error: Option<String>,
    pub dns_updated: i64,
    pub updating: bool,
}
pub type Shared = Arc<Mutex<Engine>>;

pub fn open(db: &Connection) -> rusqlite::Result<Shared> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS reputation_lists(id TEXT PRIMARY KEY, body TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1, updated INTEGER NOT NULL DEFAULT 0, error TEXT);")?;
    let mut lists = Vec::new();
    for (id, name, url, kind) in SOURCES {
        db.execute(
            "INSERT OR IGNORE INTO reputation_lists(id) VALUES(?1)",
            [id],
        )?;
        let (body, enabled, updated, error): (String, bool, i64, Option<String>) = db.query_row(
            "SELECT body,enabled,updated,error FROM reputation_lists WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        let mut l = List {
            id: id.into(),
            name: name.into(),
            url: url.into(),
            kind: kind.into(),
            enabled,
            updated,
            error,
            copyright: String::new(),
            nets: Vec::new(),
            domains: HashSet::new(),
        };
        if !body.is_empty()
            && let Err(e) = parse(&mut l, &body)
        {
            l.error = Some(e);
        }
        lists.push(l);
    }
    Ok(Arc::new(Mutex::new(Engine {
        lists,
        dns: HashMap::new(),
        dns_error: None,
        dns_updated: 0,
        updating: false,
    })))
}
fn parse(l: &mut List, body: &str) -> Result<(), String> {
    let mut nets = Vec::new();
    let mut domains = HashSet::new();
    let mut copyright = String::new();
    for line in body.lines() {
        if l.id == "stevenblack" {
            let line = line.split('#').next().unwrap_or("");
            let mut p = line.split_whitespace();
            if matches!(p.next(), Some("0.0.0.0" | "127.0.0.1")) {
                for domain in p {
                    if let Some(d) = domain_name(domain) {
                        domains.insert(d);
                    }
                }
            }
        } else {
            let v: Value = serde_json::from_str(line)
                .map_err(|_| "Liste JSON invalide : ancienne version conservée".to_string())?;
            if let Some(cidr) = v["cidr"].as_str() {
                nets.push(cidr.parse::<IpNet>().map_err(|_| "CIDR invalide")?);
            }
            if let Some(c) = v["copyright"].as_str() {
                copyright = c.into();
            }
        }
    }
    if nets.len() + domains.len() < 10 {
        return Err("Liste vide ou incomplète : ancienne version conservée".into());
    }
    l.nets = nets;
    l.domains = domains;
    l.copyright = copyright;
    Ok(())
}
fn domain_name(s: &str) -> Option<String> {
    let s = s.trim_end_matches('.').to_ascii_lowercase();
    if s.len() > 253
        || !s.contains('.')
        || s.parse::<IpAddr>().is_ok()
        || !s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return None;
    }
    Some(s)
}
impl Engine {
    pub fn status(&self) -> Value {
        json!({"updating":self.updating,"dns_updated":self.dns_updated,"dns_error":self.dns_error,"lists":self.lists.iter().map(|l|json!({"id":l.id,"name":l.name,"url":l.url,"kind":l.kind,"enabled":l.enabled,"updated":l.updated,"count":l.count(),"error":l.error,"stale":l.updated==0||crate::now()-l.updated>7*86400,"copyright":l.copyright})).collect::<Vec<_>>()})
    }
    pub fn set_enabled(&mut self, db: &Connection, id: &str, enabled: bool) -> Result<(), String> {
        let l = self
            .lists
            .iter_mut()
            .find(|l| l.id == id)
            .ok_or("Liste inconnue")?;
        db.execute(
            "UPDATE reputation_lists SET enabled=?1 WHERE id=?2",
            params![enabled, id],
        )
        .map_err(|e| e.to_string())?;
        l.enabled = enabled;
        Ok(())
    }
    pub fn enrich(&self, flows: &mut [Flow], now: i64) {
        for f in flows {
            let Ok(ip) = f.remote.parse::<IpAddr>() else {
                continue;
            };
            f.domains = self
                .dns
                .get(&ip)
                .map(|v| {
                    v.iter()
                        .filter(|(_, expires)| *expires >= now)
                        .map(|(name, _)| name.clone())
                        .take(24)
                        .collect()
                })
                .unwrap_or_default();
            f.alerts.clear();
            for l in self.lists.iter().filter(|l| l.enabled) {
                if let Some(net) = l.nets.iter().find(|net| net.contains(&ip)) {
                    f.alerts.push(Alert{source:l.name.clone(),indicator:net.to_string(),confidence:"ip_exact".into(),description:"IP comprise dans une plage répertoriée ; signal de réputation, pas preuve d’infection.".into(),evaluated:now});
                }
                for domain in &f.domains {
                    // Hosts lists describe exact names, not arbitrary parent-domain wildcards.
                    if l.domains.contains(domain) {
                        f.alerts.push(Alert{source:l.name.clone(),indicator:domain.clone(),confidence:"dns_possible".into(),description:"Domaine du cache DNS associé à cette IP. Attribution à l’application non confirmée, IP potentiellement partagée.".into(),evaluated:now});
                    }
                }
            }
        }
    }
}
fn dns_snapshot() -> Result<HashMap<IpAddr, Vec<(String, i64)>>, String> {
    // Read the existing Windows DNS cache. No reverse DNS or outbound lookup.
    const SCRIPT: &str = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); $r=@(Get-DnsClientCache | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } | Select-Object -First 12000 Name,Data,TimeToLive); ConvertTo-Json -InputObject $r -Compress";
    let mut child = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
        .creation_flags(0x08000000)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let output = child.stdout.take().ok_or("Sortie DNS indisponible")?;
    let reader = thread::spawn(move || {
        let mut b = Vec::new();
        output.take(MAX_DOWNLOAD + 1).read_to_end(&mut b).map(|_| b)
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Ok(s),
            Ok(None) => {}
            Err(e) => break Err(e.to_string()),
        };
        if start.elapsed() > Duration::from_secs(12) {
            let _ = child.kill();
            let _ = child.wait();
            break Err("Lecture du cache DNS : délai dépassé".into());
        }
        thread::sleep(Duration::from_millis(100));
    };
    let bytes = reader
        .join()
        .map_err(|_| "Lecture DNS interrompue")?
        .map_err(|e| e.to_string())?;
    if !status?.success() {
        return Err("Cache DNS Windows inaccessible".into());
    }
    if bytes.len() as u64 > MAX_DOWNLOAD {
        return Err("Cache DNS trop volumineux".into());
    }
    let rows: Vec<Value> = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let mut result: HashMap<IpAddr, Vec<(String, i64)>> = HashMap::new();
    for r in rows {
        if let (Some(name), Some(ip)) = (
            r["Name"].as_str().and_then(domain_name),
            r["Data"].as_str().and_then(|s| s.parse::<IpAddr>().ok()),
        ) {
            let ttl = r["TimeToLive"].as_i64().unwrap_or(0).clamp(0, 86400);
            if ttl > 0 {
                let names = result.entry(ip).or_default();
                if names.len() < 24 && !names.iter().any(|(n, _)| n == &name) {
                    names.push((name, crate::now() + ttl));
                }
            }
        }
    }
    Ok(result)
}
pub fn spawn(
    engine: Shared,
    db: Arc<Mutex<Connection>>,
    refresh: Arc<AtomicBool>,
    allow_download: bool,
) {
    thread::spawn(move || {
        let client = match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(25))
            .user_agent("AtlasReseau/0.2 local-reputation-monitor")
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                for l in &mut engine.lock().unwrap().lists {
                    l.error = Some(e.to_string());
                }
                return;
            }
        };
        let mut dns_at = 0;
        let mut attempted = HashMap::<String, i64>::new();
        while !crate::STOP.load(Ordering::Relaxed) {
            let force = refresh.swap(false, Ordering::Relaxed);
            let now = crate::now();
            let downloads: Vec<_> = engine
                .lock()
                .unwrap()
                .lists
                .iter()
                .filter(|l| {
                    allow_download
                        && l.enabled
                        && (force || now - l.updated > 86400)
                        && attempted.get(&l.id).is_none_or(|t| now - *t >= 3600)
                })
                .map(|l| (l.id.clone(), l.url.clone()))
                .collect();
            if !downloads.is_empty() {
                engine.lock().unwrap().updating = true;
            }
            for (id, url) in downloads {
                attempted.insert(id.clone(), now);
                let result = (|| -> Result<String, String> {
                    let response = client
                        .get(&url)
                        .send()
                        .and_then(|r| r.error_for_status())
                        .map_err(|e| e.to_string())?;
                    let mut body = String::new();
                    response
                        .take(MAX_DOWNLOAD + 1)
                        .read_to_string(&mut body)
                        .map_err(|e| e.to_string())?;
                    if body.len() as u64 > MAX_DOWNLOAD {
                        return Err("Liste trop volumineuse".into());
                    }
                    Ok(body)
                })();
                let mut engine = engine.lock().unwrap();
                let l = engine.lists.iter_mut().find(|l| l.id == id).unwrap();
                let result = result.and_then(|body| {
                    parse(l, &body)?;
                    db.lock()
                        .unwrap()
                        .execute(
                            "UPDATE reputation_lists SET body=?1,updated=?2,error=NULL WHERE id=?3",
                            params![body, now, id],
                        )
                        .map_err(|e| e.to_string())?;
                    l.updated = now;
                    Ok(())
                });
                l.error = result.err();
                if let Some(e) = &l.error {
                    let _ = db.lock().unwrap().execute(
                        "UPDATE reputation_lists SET error=?1 WHERE id=?2",
                        params![e, id],
                    );
                }
            }
            engine.lock().unwrap().updating = false;
            if now - dns_at >= 30 {
                dns_at = now;
                let result = dns_snapshot();
                let mut e = engine.lock().unwrap();
                match result {
                    Ok(d) => {
                        e.dns = d;
                        e.dns_error = None;
                        e.dns_updated = crate::now();
                    }
                    Err(err) => e.dns_error = Some(err),
                }
            }
            thread::sleep(Duration::from_secs(2));
        }
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn domain_matching_is_exact_and_dns_uncertain() {
        assert_eq!(
            domain_name("Ads.Example.COM."),
            Some("ads.example.com".into())
        );
        assert!(domain_name("1.1.1.1").is_none());
        assert!(domain_name("bad/name.example").is_none());
        let db = Connection::open_in_memory().unwrap();
        let engine = open(&db).unwrap();
        let mut e = engine.lock().unwrap();
        e.lists[0].nets.push("203.0.113.0/24".parse().unwrap());
        e.lists[2].domains.insert("ads.example.com".into());
        e.dns.insert(
            "203.0.113.7".parse().unwrap(),
            vec![("ads.example.com".into(), 200)],
        );
        let mut flows = vec![crate::store::test_flow()];
        flows[0].remote = "203.0.113.7".into();
        e.enrich(&mut flows, 100);
        assert_eq!(flows[0].alerts.len(), 2);
        assert_eq!(flows[0].alerts[0].confidence, "ip_exact");
        assert_eq!(flows[0].alerts[1].confidence, "dns_possible");
        e.lists[0].enabled = false;
        e.enrich(&mut flows, 201);
        assert!(flows[0].alerts.is_empty());
    }
    #[test]
    fn rejects_empty_updates_without_destroying_old_list() {
        let db = Connection::open_in_memory().unwrap();
        let e = open(&db).unwrap();
        let mut e = e.lock().unwrap();
        let l = &mut e.lists[0];
        l.nets.push("203.0.113.0/24".parse().unwrap());
        assert!(parse(l, "{}").is_err());
        assert_eq!(l.nets.len(), 1);
    }
}
