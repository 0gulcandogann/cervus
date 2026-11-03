//! Vault storage and crypto. All encryption is age; there is no custom crypto here.
//!
//! Layout inside the vault directory:
//!   vault.json        format version
//!   device.key.age    device identity, encrypted with the user's passphrase (age scrypt)
//!   recipients.txt    public keys that synced secrets are encrypted to (device + recovery)
//!   secrets/<n>.age   synced secrets (encrypted to every recipient)
//!   local/<n>.age     device-only secrets (encrypted to the device key only)

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};

use age::secrecy::{ExposeSecret, SecretString};
use age::x25519;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MIN_PASSPHRASE_LEN: usize = 10;

#[derive(Debug)]
pub enum VaultError {
    Locked,
    NotInitialized,
    AlreadyInitialized,
    AuthFailed,
    NotFound,
    BadInput(String),
    Internal(String),
}

impl VaultError {
    pub fn code(&self) -> &'static str {
        match self {
            VaultError::Locked => "locked",
            VaultError::NotInitialized => "not_initialized",
            VaultError::AlreadyInitialized => "already_initialized",
            VaultError::AuthFailed => "auth_failed",
            VaultError::NotFound => "not_found",
            VaultError::BadInput(_) => "bad_request",
            VaultError::Internal(_) => "internal",
        }
    }

    pub fn message(&self) -> String {
        match self {
            VaultError::Locked => "vault is locked; run `cervus unlock`".into(),
            VaultError::NotInitialized => "vault is not initialized; run `cervus init`".into(),
            VaultError::AlreadyInitialized => "vault is already initialized".into(),
            VaultError::AuthFailed => "wrong passphrase".into(),
            VaultError::NotFound => "no such secret".into(),
            VaultError::BadInput(m) | VaultError::Internal(m) => m.clone(),
        }
    }
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Internal(format!("io error: {e}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    Synced,
    Local,
}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Synced => "synced",
            Scope::Local => "local",
        }
    }
    fn dir(&self) -> &'static str {
        match self {
            Scope::Synced => "secrets",
            Scope::Local => "local",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Payload {
    v: u32,
    #[serde(rename = "type")]
    kind: String,
    value: String, // base64
}

pub struct Secret {
    pub kind: String,
    pub value: Zeroizing<Vec<u8>>,
    pub scope: Scope,
}

pub struct Vault {
    dir: PathBuf,
    identity: Option<x25519::Identity>,
    last_activity: Instant,
    idle_timeout: Duration,
}

pub fn validate_name(name: &str) -> Result<(), VaultError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(VaultError::BadInput(
            "secret names use letters, digits, '.', '_' and '-' (max 64, no leading dot)".into(),
        ))
    }
}

impl Vault {
    pub fn new(dir: PathBuf, idle_timeout: Duration) -> Self {
        Self { dir, identity: None, last_activity: Instant::now(), idle_timeout }
    }

    fn device_key_path(&self) -> PathBuf {
        self.dir.join("device.key.age")
    }
    fn recipients_path(&self) -> PathBuf {
        self.dir.join("recipients.txt")
    }
    fn secret_path(&self, scope: Scope, name: &str) -> PathBuf {
        self.dir.join(scope.dir()).join(format!("{name}.age"))
    }

    pub fn is_initialized(&self) -> bool {
        self.device_key_path().exists()
    }
    pub fn is_locked(&self) -> bool {
        self.identity.is_none()
    }
    pub fn idle_timeout_secs(&self) -> u64 {
        self.idle_timeout.as_secs()
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Locks the vault if it has been idle longer than the timeout. Returns true if it locked.
    pub fn check_idle(&mut self) -> bool {
        if self.identity.is_some() && self.last_activity.elapsed() >= self.idle_timeout {
            self.lock();
            return true;
        }
        false
    }

    pub fn lock(&mut self) {
        self.identity = None; // x25519::Identity zeroizes its secret on drop
    }

    /// Creates a new vault. Returns the recovery key, which is shown to the user exactly once.
    pub fn init(&mut self, passphrase: &str) -> Result<Zeroizing<String>, VaultError> {
        if self.is_initialized() {
            return Err(VaultError::AlreadyInitialized);
        }
        if passphrase.chars().count() < MIN_PASSPHRASE_LEN {
            return Err(VaultError::BadInput(format!(
                "passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
            )));
        }

        for sub in ["", "secrets", "local"] {
            let p = self.dir.join(sub);
            fs::create_dir_all(&p)?;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700))?;
        }

        let device = x25519::Identity::generate();
        let recovery = x25519::Identity::generate();

        let device_secret = Zeroizing::new(device.to_string().expose_secret().to_string());
        let wrapped = encrypt_with_passphrase(device_secret.as_bytes(), passphrase)?;
        write_atomic(&self.device_key_path(), &wrapped)?;

        let recipients = format!(
            "# Cervus recipients: synced secrets are encrypted to every key below.\n{}\n{}\n",
            device.to_public(),
            recovery.to_public()
        );
        write_atomic(&self.recipients_path(), recipients.as_bytes())?;
        write_atomic(&self.dir.join("vault.json"), b"{\"version\":1}\n")?;

        self.identity = Some(device);
        self.touch();
        Ok(Zeroizing::new(recovery.to_string().expose_secret().to_string()))
    }

    pub fn unlock(&mut self, passphrase: &str) -> Result<(), VaultError> {
        if !self.is_initialized() {
            return Err(VaultError::NotInitialized);
        }
        let wrapped = fs::read(self.device_key_path())?;
        let plain = match decrypt_with_passphrase(&wrapped, passphrase) {
            Ok(p) => p,
            Err(_) => {
                std::thread::sleep(Duration::from_secs(1)); // slow down guessing
                return Err(VaultError::AuthFailed);
            }
        };
        let text = std::str::from_utf8(&plain)
            .map_err(|_| VaultError::Internal("corrupt device key".into()))?;
        let identity = x25519::Identity::from_str(text.trim())
            .map_err(|_| VaultError::Internal("corrupt device key".into()))?;
        self.identity = Some(identity);
        self.touch();
        Ok(())
    }

    fn identity(&self) -> Result<&x25519::Identity, VaultError> {
        if !self.is_initialized() {
            return Err(VaultError::NotInitialized);
        }
        self.identity.as_ref().ok_or(VaultError::Locked)
    }

    fn recipients(&self, scope: Scope) -> Result<Vec<x25519::Recipient>, VaultError> {
        let identity = self.identity()?;
        match scope {
            Scope::Local => Ok(vec![identity.to_public()]),
            Scope::Synced => {
                let text = fs::read_to_string(self.recipients_path())?;
                let mut out = Vec::new();
                for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                    out.push(
                        x25519::Recipient::from_str(line)
                            .map_err(|e| VaultError::Internal(format!("bad recipient: {e}")))?,
                    );
                }
                if out.is_empty() {
                    return Err(VaultError::Internal("recipients.txt is empty".into()));
                }
                Ok(out)
            }
        }
    }

    fn find(&self, name: &str) -> Option<Scope> {
        [Scope::Synced, Scope::Local]
            .into_iter()
            .find(|s| self.secret_path(*s, name).exists())
    }

    pub fn put(&mut self, name: &str, kind: &str, value: &[u8], scope: Scope) -> Result<(), VaultError> {
        validate_name(name)?;
        let recipients = self.recipients(scope)?;
        if let Some(existing) = self.find(name) {
            if existing != scope {
                return Err(VaultError::BadInput(format!(
                    "'{name}' already exists with scope {}; delete it first",
                    existing.as_str()
                )));
            }
        }
        let payload = Zeroizing::new(
            serde_json::to_vec(&Payload { v: 1, kind: kind.to_string(), value: B64.encode(value) })
                .map_err(|e| VaultError::Internal(e.to_string()))?,
        );
        let sealed = encrypt_to(&recipients, &payload)?;
        write_atomic(&self.secret_path(scope, name), &sealed)?;
        self.touch();
        Ok(())
    }

    pub fn get(&mut self, name: &str) -> Result<Secret, VaultError> {
        validate_name(name)?;
        let identity = self.identity()?;
        let scope = self.find(name).ok_or(VaultError::NotFound)?;
        let sealed = fs::read(self.secret_path(scope, name))?;
        let plain = decrypt_with_identity(&sealed, identity)?;
        let payload: Payload = serde_json::from_slice(&plain)
            .map_err(|_| VaultError::Internal("corrupt secret payload".into()))?;
        let value = B64
            .decode(payload.value.as_bytes())
            .map_err(|_| VaultError::Internal("corrupt secret payload".into()))?;
        self.touch();
        Ok(Secret { kind: payload.kind, value: Zeroizing::new(value), scope })
    }

    pub fn list(&mut self, prefix: &str) -> Result<Vec<(String, Scope)>, VaultError> {
        self.identity()?;
        let mut out = Vec::new();
        for scope in [Scope::Synced, Scope::Local] {
            let dir = self.dir.join(scope.dir());
            if !dir.exists() {
                continue;
            }
            for entry in fs::read_dir(dir)? {
                let file = entry?.file_name().to_string_lossy().to_string();
                if let Some(name) = file.strip_suffix(".age") {
                    if name.starts_with(prefix) {
                        out.push((name.to_string(), scope));
                    }
                }
            }
        }
        out.sort();
        self.touch();
        Ok(out)
    }

    pub fn delete(&mut self, name: &str) -> Result<(), VaultError> {
        validate_name(name)?;
        self.identity()?;
        let scope = self.find(name).ok_or(VaultError::NotFound)?;
        fs::remove_file(self.secret_path(scope, name))?;
        self.touch();
        Ok(())
    }
}

fn encrypt_to(recipients: &[x25519::Recipient], plain: &[u8]) -> Result<Vec<u8>, VaultError> {
    let enc = age::Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn age::Recipient))
        .map_err(|e| VaultError::Internal(format!("encrypt: {e}")))?;
    let mut out = Vec::new();
    let mut w = enc.wrap_output(&mut out).map_err(|e| VaultError::Internal(format!("encrypt: {e}")))?;
    w.write_all(plain)?;
    w.finish().map_err(|e| VaultError::Internal(format!("encrypt: {e}")))?;
    Ok(out)
}

fn decrypt_with_identity(sealed: &[u8], identity: &x25519::Identity) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let dec = age::Decryptor::new(sealed).map_err(|e| VaultError::Internal(format!("decrypt: {e}")))?;
    let mut r = dec
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| VaultError::Internal(format!("decrypt: {e}")))?;
    let mut buf = Zeroizing::new(Vec::new());
    r.read_to_end(&mut buf)?;
    Ok(buf)
}

fn encrypt_with_passphrase(plain: &[u8], passphrase: &str) -> Result<Vec<u8>, VaultError> {
    let enc = age::Encryptor::with_user_passphrase(SecretString::from(passphrase.to_owned()));
    let mut out = Vec::new();
    let mut w = enc.wrap_output(&mut out).map_err(|e| VaultError::Internal(format!("encrypt: {e}")))?;
    w.write_all(plain)?;
    w.finish().map_err(|e| VaultError::Internal(format!("encrypt: {e}")))?;
    Ok(out)
}

fn decrypt_with_passphrase(sealed: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let dec = age::Decryptor::new(sealed).map_err(|_| VaultError::AuthFailed)?;
    let id = age::scrypt::Identity::new(SecretString::from(passphrase.to_owned()));
    let mut r = dec
        .decrypt(std::iter::once(&id as &dyn age::Identity))
        .map_err(|_| VaultError::AuthFailed)?;
    let mut buf = Zeroizing::new(Vec::new());
    r.read_to_end(&mut buf).map_err(|_| VaultError::AuthFailed)?;
    Ok(buf)
}

/// Atomic write: temp file in the same directory, fsync, rename. Mode 0600.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), VaultError> {
    let dir = path.parent().ok_or_else(|| VaultError::Internal("no parent dir".into()))?;
    let tmp = dir.join(format!(".tmp-{}", std::process::id()));
    {
        let mut f: File = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "correct horse battery";

    fn vault() -> (tempfile::TempDir, Vault) {
        let t = tempfile::tempdir().unwrap();
        let v = Vault::new(t.path().join("vault"), Duration::from_secs(3600));
        (t, v)
    }

    #[test]
    fn init_put_get_roundtrip_and_ciphertext_on_disk() {
        let (_t, mut v) = vault();
        v.init(PASS).unwrap();
        v.put("aws-work", "aws_access_key", b"AKIA-SUPER-SECRET", Scope::Synced).unwrap();
        let s = v.get("aws-work").unwrap();
        assert_eq!(&s.value[..], b"AKIA-SUPER-SECRET");
        assert_eq!(s.kind, "aws_access_key");

        let raw = fs::read(v.secret_path(Scope::Synced, "aws-work")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("AKIA"));
    }

    #[test]
    fn lock_blocks_access_and_unlock_restores_it() {
        let (_t, mut v) = vault();
        v.init(PASS).unwrap();
        v.put("a", "generic", b"x", Scope::Synced).unwrap();
        v.lock();
        assert!(matches!(v.get("a"), Err(VaultError::Locked)));
        assert!(matches!(v.unlock("wrong passphrase!"), Err(VaultError::AuthFailed)));
        v.unlock(PASS).unwrap();
        assert_eq!(&v.get("a").unwrap().value[..], b"x");
    }

    #[test]
    fn recovery_key_opens_synced_but_not_local_secrets() {
        let (_t, mut v) = vault();
        let recovery = v.init(PASS).unwrap();
        v.put("shared", "generic", b"s1", Scope::Synced).unwrap();
        v.put("seed", "mfa_seed", b"s2", Scope::Local).unwrap();
        let rec = x25519::Identity::from_str(recovery.as_str()).unwrap();

        let synced = fs::read(v.secret_path(Scope::Synced, "shared")).unwrap();
        assert!(decrypt_with_identity(&synced, &rec).is_ok());
        let local = fs::read(v.secret_path(Scope::Local, "seed")).unwrap();
        assert!(decrypt_with_identity(&local, &rec).is_err());
    }

    #[test]
    fn idle_timeout_locks() {
        let t = tempfile::tempdir().unwrap();
        let mut v = Vault::new(t.path().join("vault"), Duration::from_millis(50));
        v.init(PASS).unwrap();
        std::thread::sleep(Duration::from_millis(80));
        assert!(v.check_idle());
        assert!(v.is_locked());
    }

    #[test]
    fn rejects_weak_passphrase_double_init_and_bad_names() {
        let (_t, mut v) = vault();
        assert!(matches!(v.init("short"), Err(VaultError::BadInput(_))));
        v.init(PASS).unwrap();
        assert!(matches!(v.init(PASS), Err(VaultError::AlreadyInitialized)));
        assert!(validate_name("../etc/passwd").is_err());
        assert!(validate_name(".hidden").is_err());
        assert!(validate_name("ok-name_1.v2").is_ok());
    }

    #[test]
    fn list_and_delete() {
        let (_t, mut v) = vault();
        v.init(PASS).unwrap();
        v.put("b", "generic", b"1", Scope::Synced).unwrap();
        v.put("a", "generic", b"2", Scope::Local).unwrap();
        let names: Vec<String> = v.list("").unwrap().into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, vec!["a", "b"]);
        v.delete("a").unwrap();
        assert!(matches!(v.get("a"), Err(VaultError::NotFound)));
    }
}
