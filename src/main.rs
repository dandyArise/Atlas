mod collector;
mod geo;
mod icons;
mod intel;
mod store;
mod udp;
use serde_json::json;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tiny_http::{Header, Method, Response, Server};
static STOP: AtomicBool = AtomicBool::new(false);
unsafe extern "system" fn console_stop(kind: u32) -> i32 {
    if kind <= 2 || kind == 5 || kind == 6 {
        STOP.store(true, Ordering::Relaxed);
        1
    } else {
        0
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
#[derive(Default)]
struct Health {
    last: i64,
    error: Option<String>,
    geo_error: Option<String>,
}
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().collect();
    let arg = |name: &str| args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone());
    let port: u16 = arg("--port").unwrap_or_else(|| "47831".into()).parse()?;
    let directory = arg("--data-dir")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap_or_else(|| ".".into()))
                .join("AtlasReseau")
        });
    std::fs::create_dir_all(&directory)?;
    let server = Server::http(("127.0.0.1", port))?;
    let mut db = store::open(&directory.join("history.sqlite"))?;
    db.execute("UPDATE sessions SET active=0 WHERE active=1", [])?;
    if args.iter().any(|a| a == "--check") {
        let flows = collector::collect()?;
        store::record(&mut db, &flows, now())?;
        println!(
            "{}",
            json!({"ok":true,"observed":flows.len(),"database":directory.join("history.sqlite")})
        );
        return Ok(());
    }
    let intelligence = intel::open(&db)?;
    let db = Arc::new(Mutex::new(db));
    let app_icons = icons::spawn(db.clone());
    let lists_refresh = Arc::new(AtomicBool::new(false));
    intel::spawn(
        intelligence.clone(),
        db.clone(),
        lists_refresh.clone(),
        !args.iter().any(|a| a == "--offline-lists"),
    );
    let health = Arc::new(Mutex::new(Health::default()));
    let geo_enabled = Arc::new(AtomicBool::new(false));
    let udp_state = Arc::new(Mutex::new(udp::State::default()));
    let udp_capture = udp::Capture::start(udp_state.clone());
    if let Err(ref e) = udp_capture {
        eprintln!("{e}");
    }
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(console_stop), 1);
    }
    {
        let db = db.clone();
        let health = health.clone();
        let udp_state = udp_state.clone();
        let intelligence = intelligence.clone();
        thread::spawn(move || {
            while !STOP.load(Ordering::Relaxed) {
                let result = collector::collect().and_then(|mut flows| {
                    flows.extend(udp_state.lock().unwrap().snapshot(now()));
                    intelligence.lock().unwrap().enrich(&mut flows, now());
                    store::record(&mut db.lock().unwrap(), &flows, now()).map_err(|e| e.to_string())
                });
                let mut h = health.lock().unwrap();
                match result {
                    Ok(()) => {
                        h.last = now();
                        h.error = None;
                    }
                    Err(e) => h.error = Some(e),
                }
                drop(h);
                thread::sleep(Duration::from_secs(3));
            }
        });
    }
    {
        let db = db.clone();
        let enabled = geo_enabled.clone();
        let health = health.clone();
        thread::spawn(move || {
            let client = match reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(8))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    health.lock().unwrap().geo_error = Some(e.to_string());
                    return;
                }
            };
            let mut attempted = std::collections::HashMap::<String, i64>::new();
            let mut requests = 0;
            let mut day = now() / 86400;
            loop {
                thread::sleep(Duration::from_secs(2));
                if !enabled.load(Ordering::Relaxed) {
                    continue;
                }
                if now() / 86400 != day {
                    day = now() / 86400;
                    requests = 0;
                }
                if requests >= 900 {
                    health.lock().unwrap().geo_error =
                        Some("Budget quotidien atteint (900 requêtes).".into());
                    continue;
                }
                let candidates: Vec<String> = {
                    let db = db.lock().unwrap();
                    let result = (|| -> rusqlite::Result<Vec<String>> {
                        let mut q=db.prepare("SELECT DISTINCT s.remote FROM sessions s LEFT JOIN geo g ON g.ip=s.remote WHERE g.ip IS NULL OR g.updated<?1 ORDER BY s.last DESC LIMIT 2000")?;
                        q.query_map([now() - 7 * 86400], |r| r.get(0))?.collect()
                    })();
                    match result {
                        Ok(v) => v,
                        Err(e) => {
                            health.lock().unwrap().geo_error = Some(e.to_string());
                            continue;
                        }
                    }
                };
                let next = candidates.into_iter().find(|ip| {
                    ip.parse().is_ok_and(collector::is_public)
                        && attempted.get(ip).is_none_or(|t| now() - t > 3600)
                });
                let Some(ip) = next else {
                    continue;
                };
                attempted.insert(ip.clone(), now());
                requests += 1;
                let result = geo::lookup(&client, &ip);
                match result {
                    Ok(v) => {
                        let result=db.lock().unwrap().execute("INSERT INTO geo(ip,payload,updated) VALUES(?1,?2,?3) ON CONFLICT(ip) DO UPDATE SET payload=excluded.payload,updated=excluded.updated",rusqlite::params![ip,v.to_string(),now()]);
                        health.lock().unwrap().geo_error = result.err().map(|e| e.to_string());
                    }
                    Err(e) => {
                        health.lock().unwrap().geo_error =
                            Some(format!("Géolocalisation indisponible : {e}"));
                        thread::sleep(Duration::from_secs(30));
                    }
                }
            }
        });
    }
    println!(
        "Atlas réseau : http://127.0.0.1:{port}\nHistorique : {}\nCtrl+C pour arrêter.",
        directory.display()
    );
    let address = format!("127.0.0.1:{port}");
    while !STOP.load(Ordering::Relaxed) {
        let Some(request) = server.recv_timeout(Duration::from_millis(200))? else {
            continue;
        };
        let host = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Host"))
            .map(|h| h.value.as_str())
            .unwrap_or("");
        let origin = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Origin"))
            .map(|h| h.value.as_str());
        if host != address || origin.is_some_and(|o| o != format!("http://{address}")) {
            let _ = request.respond(Response::from_string("Forbidden").with_status_code(403));
            continue;
        }
        let parsed = reqwest::Url::parse(&format!("http://{address}{}", request.url()))?;
        let qp: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        let numeric = |key: &str, default: i64| {
            qp.get(key)
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(default)
                .max(0)
        };
        let (code, mime, body) = match (request.method(), parsed.path()) {
            (&Method::Get, "/") => (
                200,
                "text/html; charset=utf-8",
                include_str!("../web/index.html").to_string(),
            ),
            (&Method::Get, "/app.js") => (
                200,
                "text/javascript; charset=utf-8",
                include_str!("../web/app.js").to_string(),
            ),
            (&Method::Get, "/style.css") => (
                200,
                "text/css",
                include_str!("../web/style.css").to_string(),
            ),
            (&Method::Get, "/world.json") => (
                200,
                "application/json",
                include_str!("../web/world.json").to_string(),
            ),
            (&Method::Get, "/vendor/leaflet.js") => (
                200,
                "text/javascript",
                include_str!("../web/vendor/leaflet.js").to_string(),
            ),
            (&Method::Get, "/vendor/leaflet.css") => (
                200,
                "text/css",
                include_str!("../web/vendor/leaflet.css").to_string(),
            ),
            (&Method::Get, "/api/connections") => {
                let result = store::query_filtered(
                    &db.lock().unwrap(),
                    &store::Filter {
                        active: qp.get("mode").is_none_or(|s| s != "history"),
                        search: qp.get("q").cloned().unwrap_or_default(),
                        since: numeric("since", 0),
                        until: numeric("until", i64::MAX),
                        offset: numeric("offset", 0),
                        protocol: qp.get("protocol").cloned().unwrap_or_default(),
                        country: qp.get("country").cloned().unwrap_or_default(),
                        alerts_only: qp.get("alerts").is_some_and(|s| s == "true"),
                    },
                );
                match result {
                    Ok(mut v) => {
                        let h = health.lock().unwrap();
                        v["health"] = json!({"last":h.last,"error":h.error,"geo_error":h.geo_error,"geo_enabled":geo_enabled.load(Ordering::Relaxed)});
                        v["health"]["udp"] = match &udp_capture {
                            Ok(c) => serde_json::to_value(c.status()).unwrap(),
                            Err(e) => {
                                json!({"available":false,"error":e,"events":0,"rejected":0,"dropped":0,"idle_seconds":udp::IDLE_SECONDS})
                            }
                        };
                        (200, "application/json", v.to_string())
                    }
                    Err(e) => (
                        500,
                        "application/json",
                        json!({"error":e.to_string()}).to_string(),
                    ),
                }
            }
            (&Method::Get, "/country-names.json") => (
                200,
                "application/json",
                include_str!("../web/country-names.json").to_string(),
            ),
            (&Method::Get, "/api/icons") => (
                200,
                "application/json",
                serde_json::to_string(&*app_icons.lock().unwrap()).unwrap(),
            ),
            (&Method::Get, "/api/lists") => (
                200,
                "application/json",
                intelligence.lock().unwrap().status().to_string(),
            ),
            (&Method::Post, "/api/lists/refresh")
                if request
                    .headers()
                    .iter()
                    .any(|h| h.field.equiv("X-Atlas-Local") && h.value.as_str() == "1") =>
            {
                lists_refresh.store(true, Ordering::Relaxed);
                (200, "application/json", "{\"ok\":true}".into())
            }
            (&Method::Post, "/api/lists/toggle")
                if request
                    .headers()
                    .iter()
                    .any(|h| h.field.equiv("X-Atlas-Local") && h.value.as_str() == "1") =>
            {
                let result = intelligence.lock().unwrap().set_enabled(
                    &db.lock().unwrap(),
                    qp.get("id").map(String::as_str).unwrap_or(""),
                    qp.get("enabled").is_some_and(|s| s == "true"),
                );
                match result {
                    Ok(()) => (200, "application/json", "{\"ok\":true}".into()),
                    Err(e) => (400, "application/json", json!({"error":e}).to_string()),
                }
            }
            (&Method::Post, "/api/geo")
                if request
                    .headers()
                    .iter()
                    .any(|h| h.field.equiv("X-Atlas-Local") && h.value.as_str() == "1") =>
            {
                geo_enabled.store(
                    qp.get("enabled").is_some_and(|s| s == "true"),
                    Ordering::Relaxed,
                );
                (200, "application/json", "{\"ok\":true}".into())
            }
            (&Method::Post, "/api/shutdown")
                if request
                    .headers()
                    .iter()
                    .any(|h| h.field.equiv("X-Atlas-Local") && h.value.as_str() == "1") =>
            {
                STOP.store(true, Ordering::Relaxed);
                (200, "application/json", "{\"ok\":true}".into())
            }
            _ => (404, "text/plain", "Not found".into()),
        };
        let mut response = Response::from_string(body).with_status_code(code);
        for (k, v) in [
            ("Content-Type", mime),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            (
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://tile.openstreetmap.org; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            ),
        ] {
            response.add_header(Header::from_bytes(k, v).unwrap());
        }
        let _ = request.respond(response);
    }
    Ok(())
}
