use crate::collector::Flow;
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::collections::HashMap;

pub fn open(path: &std::path::Path) -> rusqlite::Result<Connection> {
    let db = Connection::open(path)?;
    db.busy_timeout(std::time::Duration::from_secs(5))?;
    db.execute_batch("PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL, app TEXT NOT NULL, remote TEXT NOT NULL, first INTEGER NOT NULL, last INTEGER NOT NULL, active INTEGER NOT NULL, flow TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS sessions_last ON sessions(last);
        CREATE INDEX IF NOT EXISTS sessions_active ON sessions(active,fingerprint);
        CREATE TABLE IF NOT EXISTS geo(ip TEXT PRIMARY KEY, payload TEXT NOT NULL, updated INTEGER NOT NULL);")?;
    Ok(db)
}
pub fn record(db: &mut Connection, flows: &[Flow], now: i64) -> rusqlite::Result<()> {
    let tx = db.transaction()?;
    let old: HashMap<String, i64> = {
        let mut stmt = tx.prepare("SELECT fingerprint,id FROM sessions WHERE active=1")?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?
    };
    tx.execute("UPDATE sessions SET active=0 WHERE active=1", [])?;
    for f in flows {
        let base_key = format!(
            "{}|{}|{}|{}|{}|{}",
            f.pid, f.path, f.local, f.local_port, f.remote, f.port
        );
        let key = if f.protocol == "UDP" {
            format!("UDP|{base_key}")
        } else {
            base_key
        };
        let first = f.first_event.unwrap_or(now);
        let last = f.last_event.unwrap_or(now);
        let active = f.protocol != "UDP" || now - last <= crate::udp::IDLE_SECONDS;
        let serialized = serde_json::to_string(f).expect("serializable flow");
        if let Some(id) = old.get(&key) {
            tx.execute(
                "UPDATE sessions SET last=?1,active=?4,flow=?2 WHERE id=?3",
                params![last, serialized, id, active],
            )?;
        } else {
            tx.execute("INSERT INTO sessions(fingerprint,app,remote,first,last,active,flow) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![key,f.app,f.remote,first,last,active,serialized])?;
        }
    }
    tx.execute(
        "DELETE FROM sessions WHERE active=0 AND last<?1",
        [now - 30 * 86400],
    )?;
    tx.execute("DELETE FROM geo WHERE updated<?1", [now - 30 * 86400])?;
    tx.commit()
}
#[cfg(test)]
pub fn query(
    db: &Connection,
    active: bool,
    search: &str,
    since: i64,
    until: i64,
    offset: i64,
) -> rusqlite::Result<Value> {
    query_filtered(
        db,
        &Filter {
            active,
            search: search.into(),
            since,
            until,
            offset,
            ..Default::default()
        },
    )
}
#[derive(Default)]
pub struct Filter {
    pub active: bool,
    pub search: String,
    pub since: i64,
    pub until: i64,
    pub offset: i64,
    pub protocol: String,
    pub country: String,
    pub alerts_only: bool,
}
pub fn query_filtered(db: &Connection, f: &Filter) -> rusqlite::Result<Value> {
    let condition = "(?1=0 OR s.active=1) AND (instr(lower(s.app),lower(?2))>0 OR instr(s.remote,?2)>0 OR instr(lower(coalesce(json_extract(s.flow,'$.domains'),'')),lower(?2))>0 OR instr(lower(coalesce(json_extract(g.payload,'$.city'),'')),lower(?2))>0) AND s.last>=?3 AND s.first<=?4 AND (?5='' OR coalesce(json_extract(s.flow,'$.protocol'),'TCP')=?5 OR (?5='QUIC' AND json_extract(s.flow,'$.quic_possible')=1)) AND (?6='' OR json_extract(g.payload,'$.country')=?6) AND (?7=0 OR coalesce(json_array_length(json_extract(s.flow,'$.alerts')),0)>0)";
    let joined = "sessions s LEFT JOIN geo g ON g.ip=s.remote";
    let args = params![
        f.active as i32,
        f.search,
        f.since,
        f.until,
        f.protocol,
        f.country,
        f.alerts_only as i32
    ];
    let count: i64 = db.query_row(
        &format!("SELECT count(*) FROM {joined} WHERE {condition}"),
        args,
        |r| r.get(0),
    )?;
    let mut stmt = db.prepare(&format!("SELECT s.id,s.first,s.last,s.active,s.flow,g.payload FROM {joined} WHERE {condition} ORDER BY s.last DESC,s.id DESC LIMIT 200 OFFSET ?8"))?;
    let rows = stmt
        .query_map(
            params![
                f.active as i32,
                f.search,
                f.since,
                f.until,
                f.protocol,
                f.country,
                f.alerts_only as i32,
                f.offset
            ],
            |r| {
                let raw: String = r.get(4)?;
                let mut flow: Value = serde_json::from_str(&raw).unwrap_or(json!({}));
                if flow["protocol"].is_null() {
                    flow["protocol"] = json!("TCP");
                }
                flow["id"] = json!(r.get::<_, i64>(0)?);
                flow["first"] = json!(r.get::<_, i64>(1)?);
                flow["last"] = json!(r.get::<_, i64>(2)?);
                flow["active"] = json!(r.get::<_, i64>(3)? == 1);
                flow["geo"] = r
                    .get::<_, Option<String>>(5)?
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or(Value::Null);
                Ok(flow)
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let apps: i64 = db.query_row(
        &format!("SELECT count(DISTINCT s.app) FROM {joined} WHERE {condition}"),
        args,
        |r| r.get(0),
    )?;
    let destinations: i64 = db.query_row(
        &format!("SELECT count(DISTINCT s.remote) FROM {joined} WHERE {condition}"),
        args,
        |r| r.get(0),
    )?;
    let alert_count:i64=db.query_row(&format!("SELECT count(*) FROM {joined} WHERE {condition} AND coalesce(json_array_length(json_extract(s.flow,'$.alerts')),0)>0"),args,|r|r.get(0))?;
    let mut countries=db.prepare("SELECT DISTINCT json_extract(payload,'$.country') FROM geo WHERE json_extract(payload,'$.country') IS NOT NULL ORDER BY 1")?;
    let countries = countries
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(
        json!({"rows":rows,"total":count,"apps":apps,"destinations":destinations,"offset":f.offset,"alert_count":alert_count,"countries":countries}),
    )
}

#[cfg(test)]
pub fn test_flow() -> Flow {
    serde_json::from_value(json!({"pid":42,"app":"test.exe","path":"test.exe","local":"127.0.0.1","local_port":1234,"remote":"8.8.8.8","port":443,"state":"Établie","public":true})).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn flow() -> Flow {
        Flow {
            pid: 42,
            app: "test.exe".into(),
            path: "test.exe".into(),
            local: "127.0.0.1".into(),
            local_port: 1234,
            remote: "8.8.8.8".into(),
            port: 443,
            state: "Établie".into(),
            public: true,
            protocol: "TCP".into(),
            quic_possible: false,
            first_event: None,
            last_event: None,
            sent: 0,
            received: 0,
            domains: Vec::new(),
            alerts: Vec::new(),
        }
    }
    #[test]
    fn udp_history_filters_and_legacy_tcp() {
        let p = std::env::temp_dir().join(format!("atlas-udp-store-{}.sqlite", std::process::id()));
        {
            let mut db = open(&p).unwrap();
            let tcp = flow();
            let mut udp = tcp.clone();
            udp.protocol = "UDP".into();
            udp.quic_possible = true;
            udp.first_event = Some(100);
            udp.last_event = Some(101);
            udp.domains = vec!["test.example".into()];
            udp.alerts = vec![crate::intel::Alert {
                source: "Fixture".into(),
                indicator: "test.example".into(),
                confidence: "dns_possible".into(),
                description: "Test only".into(),
                evaluated: 101,
            }];
            record(&mut db, &[tcp, udp.clone()], 103).unwrap();
            db.execute(
                "INSERT INTO geo VALUES(?1,?2,103)",
                params![
                    udp.remote,
                    r#"{"country":"France","city":"Paris","lat":48.8,"lon":2.3}"#
                ],
            )
            .unwrap();
            let f = Filter {
                until: 999,
                protocol: "QUIC".into(),
                country: "France".into(),
                search: "test.example".into(),
                alerts_only: true,
                ..Default::default()
            };
            let result = query_filtered(&db, &f).unwrap();
            assert_eq!(result["total"], 1);
            assert_eq!(result["alert_count"], 1);
            let id = result["rows"][0]["id"].clone();
            record(&mut db, &[udp], 135).unwrap();
            let result = query_filtered(&db, &f).unwrap();
            assert_eq!(result["rows"][0]["id"], id);
            assert_eq!(result["rows"][0]["last"], 101);
            assert_eq!(result["rows"][0]["active"], false);
            assert_eq!(query(&db, false, "", 0, 999, 0).unwrap()["total"], 2);
            db.execute("UPDATE sessions SET flow=json_remove(flow,'$.protocol') WHERE fingerprint NOT LIKE 'UDP|%'",[]).unwrap();
            let legacy = query_filtered(
                &db,
                &Filter {
                    protocol: "TCP".into(),
                    until: 999,
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(legacy["total"], 1);
            assert_eq!(legacy["rows"][0]["protocol"], "TCP");
        }
        std::fs::remove_file(p).unwrap();
    }
    #[test]
    fn persists_closes_reopens_and_filters_sessions() {
        let p = std::env::temp_dir().join(format!("atlas-test-{}.sqlite", std::process::id()));
        {
            let mut db = open(&p).unwrap();
            record(&mut db, &[flow()], 100).unwrap();
            record(&mut db, &[flow()], 103).unwrap();
            assert_eq!(query(&db, true, "test", 0, 999, 0).unwrap()["total"], 1);
            record(&mut db, &[], 106).unwrap();
            assert_eq!(query(&db, true, "", 0, 999, 0).unwrap()["total"], 0);
            record(&mut db, &[flow()], 109).unwrap();
        }
        {
            let db = open(&p).unwrap();
            assert_eq!(query(&db, false, "", 0, 999, 0).unwrap()["total"], 2);
            assert_eq!(query(&db, false, "missing", 0, 999, 0).unwrap()["total"], 0);
            assert_eq!(query(&db, false, "", 107, 999, 0).unwrap()["total"], 1);
            assert_eq!(
                query(&db, false, "", 0, 999, 1).unwrap()["rows"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        }
        std::fs::remove_file(p).unwrap();
    }
}
