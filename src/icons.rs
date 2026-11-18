//! Extract icons only from local executables already observed by the collector.
//! Windows performs resource extraction, never execution of the target file.
use rusqlite::Connection;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashSet},
    io::{Read, Write},
    os::windows::process::CommandExt,
    process::{Command, Stdio},
    sync::{Arc, Mutex, atomic::Ordering},
    thread,
    time::{Duration, Instant},
};

pub type Shared = Arc<Mutex<BTreeMap<String, String>>>;

fn local_executable(path: &str) -> bool {
    let b = path.as_bytes();
    b.len() > 3
        && b.len() < 2048
        && b[0].is_ascii_alphabetic()
        && b[1] == b':'
        && (b[2] == b'\\' || b[2] == b'/')
        && path.to_ascii_lowercase().ends_with(".exe")
}

#[derive(Deserialize)]
struct Icon {
    path: String,
    data: String,
}

fn extract(paths: &[String]) -> Result<Vec<Icon>, String> {
    // Paths travel as JSON on stdin, never interpolated into PowerShell code.
    let script = r#"$ErrorActionPreference='Stop'; [Console]::InputEncoding=[Text.Encoding]::UTF8; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); Add-Type -AssemblyName System.Drawing; $paths=ConvertFrom-Json ([Console]::In.ReadToEnd()); $result=@(foreach($p in $paths){ $ico=$null; $bmp=$null; $stream=$null; try { $ico=[Drawing.Icon]::ExtractAssociatedIcon($p); if($null -ne $ico){ $bmp=$ico.ToBitmap(); $stream=[IO.MemoryStream]::new(); $bmp.Save($stream,[Drawing.Imaging.ImageFormat]::Png); [pscustomobject]@{path=$p;data=[Convert]::ToBase64String($stream.ToArray())} } } catch {} finally { if($stream){$stream.Dispose()}; if($bmp){$bmp.Dispose()}; if($ico){$ico.Dispose()} } }); ConvertTo-Json -Compress -InputObject $result"#;
    let mut child = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(0x08000000)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(paths).map_err(|e| e.to_string())?;
    if let Err(e) = child.stdin.take().unwrap().write_all(&bytes) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e.to_string());
    }
    let stdout = child.stdout.take().unwrap();
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            // A cold Windows PowerShell/.NET startup can exceed eight seconds
            // on hosted runners and slower PCs. This worker never blocks the API.
            Ok(None) if start.elapsed() < Duration::from_secs(30) => {
                thread::sleep(Duration::from_millis(100))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("Extraction des icônes interrompue".to_string());
            }
        }
    };
    let bytes = reader
        .join()
        .map_err(|_| "Lecture des icônes interrompue")?
        .map_err(|e| e.to_string())?;
    if !status?.success() || bytes.len() > 1024 * 1024 {
        return Err("Extraction des icônes indisponible".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

pub fn spawn(db: Arc<Mutex<Connection>>) -> Shared {
    let cache = Shared::default();
    let result = cache.clone();
    thread::spawn(move || {
        let mut attempted = HashSet::new();
        while !crate::STOP.load(Ordering::Relaxed) && attempted.len() < 512 {
            let paths:Vec<String>=(|| -> rusqlite::Result<Vec<String>> {
                let db=db.lock().unwrap();
                let mut stmt=db.prepare("SELECT json_extract(flow,'$.path') FROM sessions GROUP BY json_extract(flow,'$.path') ORDER BY max(last) DESC LIMIT 256")?;
                let rows=stmt.query_map([],|r|r.get::<_,Option<String>>(0))?;
                Ok(rows.filter_map(Result::ok).flatten().filter(|p|local_executable(p)&&!attempted.contains(p)).take(8).collect())
            })().unwrap_or_default();
            if !paths.is_empty() {
                attempted.extend(paths.iter().cloned());
                match extract(&paths) {
                    Ok(icons) => {
                        let mut cache = cache.lock().unwrap();
                        for icon in icons {
                            if paths.contains(&icon.path)
                                && icon.data.starts_with("iVBORw0KGgo")
                                && icon.data.len() < 65536
                            {
                                cache.insert(
                                    icon.path,
                                    format!("data:image/png;base64,{}", icon.data),
                                );
                            }
                        }
                    }
                    Err(e) => eprintln!("{e}; icônes de remplacement utilisées"),
                }
            }
            thread::sleep(Duration::from_secs(3));
        }
    });
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_network_and_non_executable_paths() {
        assert!(local_executable(r"C:\Program Files\App\app.exe"));
        for p in [
            r"\\server\share\app.exe",
            r"\\?\C:\app.exe",
            "https://site/app.exe",
            "app.exe",
            r"C:\app.dll",
        ] {
            assert!(!local_executable(p));
        }
    }
    #[test]
    fn extracts_a_real_windows_icon() {
        let path = format!(r"{}\System32\cmd.exe", std::env::var("SystemRoot").unwrap());
        let icons = extract(std::slice::from_ref(&path)).unwrap();
        assert_eq!(icons.len(), 1);
        assert_eq!(icons[0].path, path);
        assert!(icons[0].data.starts_with("iVBORw0KGgo"));
    }
}
