//! cervus-vault: speaks newline-delimited JSON on stdin/stdout. It is started by cervusd and
//! has no socket on disk, so only its parent process can talk to it. Logs go to stderr.

mod protocol;
mod store;
mod totp;

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use zeroize::Zeroize;

use protocol::{Request, Response};
use store::{Scope, Vault, VaultError};

fn vault_dir() -> PathBuf {
    if let Ok(p) = std::env::var("CERVUS_VAULT_DIR") {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").expect("HOME is not set");
    PathBuf::from(home).join(".cervus/vault")
}

fn idle_timeout() -> Duration {
    let secs = std::env::var("CERVUS_IDLE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(4 * 60 * 60); // default: 4 hours
    Duration::from_secs(secs)
}

/// Best-effort process hardening: no core dumps, no debugger attach.
fn harden() {
    unsafe {
        let lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &lim);
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        #[cfg(target_os = "macos")]
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }
}

fn str_param<'a>(params: &'a Value, key: &str) -> Result<&'a str, VaultError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| VaultError::BadInput(format!("missing string parameter '{key}'")))
}

fn handle(vault: &mut Vault, req: &Request) -> Result<Value, VaultError> {
    vault.check_idle();
    match req.op.as_str() {
        "ping" => Ok(json!({ "pong": true })),
        "status" => Ok(json!({
            "initialized": vault.is_initialized(),
            "locked": vault.is_locked(),
            "version": env!("CARGO_PKG_VERSION"),
            "idle_timeout_secs": vault.idle_timeout_secs(),
            "dir": vault.dir().to_string_lossy(),
        })),
        "init" => {
            let recovery = vault.init(str_param(&req.params, "passphrase")?)?;
            Ok(json!({ "recovery_key": recovery.as_str() }))
        }
        "unlock" => {
            vault.unlock(str_param(&req.params, "passphrase")?)?;
            Ok(json!({ "locked": false }))
        }
        "recover" => {
            let drop_local = req.params.get("drop_local").and_then(Value::as_bool).unwrap_or(false);
            let report = vault.recover(
                str_param(&req.params, "recovery_key")?,
                str_param(&req.params, "passphrase")?,
                drop_local,
            )?;
            Ok(json!({ "reencrypted": report.reencrypted, "lost_local": report.lost_local }))
        }
        "lock" => {
            vault.lock();
            Ok(json!({ "locked": true }))
        }
        "put" => {
            let name = str_param(&req.params, "name")?;
            let kind = req.params.get("type").and_then(Value::as_str).unwrap_or("generic");
            let scope = match req.params.get("scope").and_then(Value::as_str).unwrap_or("synced") {
                "synced" => Scope::Synced,
                "local" => Scope::Local,
                other => return Err(VaultError::BadInput(format!("unknown scope '{other}'"))),
            };
            let mut value = B64
                .decode(str_param(&req.params, "value")?)
                .map_err(|_| VaultError::BadInput("value must be base64".into()))?;
            let res = vault.put(name, kind, &value, scope);
            value.zeroize();
            res?;
            Ok(json!({}))
        }
        "get" => {
            let secret = vault.get(str_param(&req.params, "name")?)?;
            Ok(json!({
                "type": secret.kind,
                "scope": secret.scope.as_str(),
                "value": B64.encode(&secret.value[..]),
            }))
        }
        "list" => {
            let prefix = req.params.get("prefix").and_then(Value::as_str).unwrap_or("");
            let items: Vec<Value> = vault
                .list(prefix)?
                .into_iter()
                .map(|(name, scope)| json!({ "name": name, "scope": scope.as_str() }))
                .collect();
            Ok(json!({ "secrets": items }))
        }
        "delete" => {
            vault.delete(str_param(&req.params, "name")?)?;
            Ok(json!({}))
        }
        "totp" => {
            let secret = vault.get(str_param(&req.params, "name")?)?;
            if secret.kind != "mfa_seed" {
                return Err(VaultError::BadInput("secret is not of type mfa_seed".into()));
            }
            let text = std::str::from_utf8(&secret.value[..])
                .map_err(|_| VaultError::BadInput("MFA seed is not valid text".into()))?;
            let seed = zeroize::Zeroizing::new(
                totp::base32_decode(text)
                    .ok_or_else(|| VaultError::BadInput("MFA seed is not valid base32".into()))?,
            );
            let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            Ok(json!({
                "code": format!("{:06}", totp::totp_at(&seed, now)),
                "valid_for_secs": totp::valid_for_secs(now),
            }))
        }
        other => Err(VaultError::BadInput(format!("unknown op '{other}'"))),
    }
}

fn respond(vault: &mut Vault, line: &str) -> Response {
    match serde_json::from_str::<Request>(line) {
        Err(e) => Response::failure(0, "bad_request", &e.to_string()),
        Ok(req) => match handle(vault, &req) {
            Ok(data) => Response::success(req.id, data),
            Err(e) => Response::failure(req.id, e.code(), &e.message()),
        },
    }
}

fn main() {
    harden();

    let vault = Arc::new(Mutex::new(Vault::new(vault_dir(), idle_timeout())));

    // Enforce the idle timeout even when no requests arrive.
    let watcher = Arc::clone(&vault);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(5));
        if watcher.lock().unwrap().check_idle() {
            eprintln!("cervus-vault: idle timeout reached, vault locked");
        }
    });

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut line = String::new();
    loop {
        line.clear();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break, // parent closed the pipe: exit, which also drops all keys
            Ok(_) => {}
            Err(e) => {
                eprintln!("cervus-vault: read error: {e}");
                break;
            }
        }
        if line.trim().is_empty() {
            continue;
        }
        let resp = respond(&mut vault.lock().unwrap(), &line);
        line.zeroize(); // the request may have contained a passphrase or secret value
        match serde_json::to_string(&resp) {
            Ok(out) => {
                if writeln!(stdout, "{out}").and_then(|_| stdout.flush()).is_err() {
                    break;
                }
            }
            Err(e) => eprintln!("cervus-vault: encode error: {e}"),
        }
    }
}
