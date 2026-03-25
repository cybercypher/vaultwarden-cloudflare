use serde::de::DeserializeOwned;
use wasm_bindgen::JsValue;
use worker::D1Database;

use crate::error::{Error, Result};

/// Execute a D1 query that returns a single row.
pub async fn query_one<T: DeserializeOwned>(
    db: &D1Database,
    query: &str,
    params: &[JsValue],
) -> Result<Option<T>> {
    let stmt = db.prepare(query);
    let stmt = stmt.bind(params).map_err(|e| Error::internal(format!("D1 bind error: {e}")))?;
    stmt.first::<T>(None)
        .await
        .map_err(|e| Error::internal(format!("D1 query error: {e}")))
}

/// Execute a D1 query that returns multiple rows.
pub async fn query_all<T: DeserializeOwned>(
    db: &D1Database,
    query: &str,
    params: &[JsValue],
) -> Result<Vec<T>> {
    let stmt = db.prepare(query);
    let stmt = stmt.bind(params).map_err(|e| Error::internal(format!("D1 bind error: {e}")))?;
    let result = stmt
        .all()
        .await
        .map_err(|e| Error::internal(format!("D1 query error: {e}")))?;
    result
        .results::<T>()
        .map_err(|e| Error::internal(format!("D1 deserialize error: {e}")))
}

/// Execute a D1 statement that doesn't return rows (INSERT, UPDATE, DELETE).
pub async fn execute(
    db: &D1Database,
    query: &str,
    params: &[JsValue],
) -> Result<()> {
    let stmt = db.prepare(query);
    let stmt = stmt.bind(params).map_err(|e| Error::internal(format!("D1 bind error: {e}")))?;
    stmt.run()
        .await
        .map_err(|e| Error::internal(format!("D1 execute error: {e}")))?;
    Ok(())
}

/// Execute a batch of D1 statements in a transaction.

/// Helper to convert a value to JsValue for D1 bind parameters.
pub fn val(v: &str) -> JsValue {
    JsValue::from_str(v)
}

pub fn val_i32(v: i32) -> JsValue {
    JsValue::from(v)
}

pub fn val_i64(v: i64) -> JsValue {
    JsValue::from(v as f64) // JS numbers are f64
}


pub fn val_opt(v: &Option<String>) -> JsValue {
    match v {
        Some(s) => JsValue::from_str(s),
        None => JsValue::NULL,
    }
}

pub fn val_opt_i32(v: Option<i32>) -> JsValue {
    match v {
        Some(n) => JsValue::from(n),
        None => JsValue::NULL,
    }
}
