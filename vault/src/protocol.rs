//! Wire types for the daemon <-> vault protocol (newline-delimited JSON over stdio).
//! See docs/PROTOCOL.md.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct Request {
    pub id: u64,
    pub op: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl Response {
    pub fn success(id: u64, data: Value) -> Self {
        Self { id, ok: true, data: Some(data), error: None }
    }

    pub fn failure(id: u64, code: &str, message: &str) -> Self {
        Self {
            id,
            ok: false,
            data: None,
            error: Some(ErrorBody { code: code.into(), message: message.into() }),
        }
    }
}
