//! File storage abstraction — supports R2 (if configured) or KV fallback.
//!
//! R2 is preferred (larger files, better performance) but requires a credit card.
//! KV works for free (no CC) with 25MB per file limit and 1GB total storage.
//!
//! The backend is auto-detected: if the ATTACHMENTS R2 bucket binding exists,
//! R2 is used. Otherwise, falls back to KV.

use worker::Env;

use crate::error::{Error, Result};

/// Store a file. Tries R2 first, falls back to KV.
pub async fn put(env: &Env, key: &str, data: Vec<u8>) -> Result<()> {
    if let Ok(r2) = env.bucket("ATTACHMENTS") {
        r2.put(key, data).execute().await.map_err(|e| Error::internal(format!("R2 upload failed: {e}")))?;
        Ok(())
    } else if let Ok(kv) = env.kv("KV") {
        let prefixed = format!("file:{key}");
        kv.put_bytes(&prefixed, &data)
            .map_err(|e| Error::internal(format!("KV put error: {e}")))?
            .execute()
            .await
            .map_err(|e| Error::internal(format!("KV upload failed: {e}")))?;
        Ok(())
    } else {
        Err(Error::internal("No file storage configured. Add R2 (ATTACHMENTS) or KV binding."))
    }
}

/// Retrieve a file. Returns None if not found.
pub async fn get(env: &Env, key: &str) -> Result<Option<Vec<u8>>> {
    if let Ok(r2) = env.bucket("ATTACHMENTS") {
        let object = r2.get(key).execute().await.map_err(|e| Error::internal(format!("R2 error: {e}")))?;

        match object {
            Some(obj) => {
                let body = obj.body().ok_or_else(|| Error::internal("Empty R2 object"))?;
                let bytes = body.bytes().await.map_err(|e| Error::internal(e.to_string()))?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    } else if let Ok(kv) = env.kv("KV") {
        let prefixed = format!("file:{key}");
        let result = kv.get(&prefixed).bytes().await.map_err(|e| Error::internal(format!("KV get error: {e}")))?;
        Ok(result)
    } else {
        Err(Error::internal("No file storage configured. Add R2 (ATTACHMENTS) or KV binding."))
    }
}

/// Delete a file.
pub async fn delete(env: &Env, key: &str) -> Result<()> {
    if let Ok(r2) = env.bucket("ATTACHMENTS") {
        let _ = r2.delete(key).await;
    } else if let Ok(kv) = env.kv("KV") {
        let prefixed = format!("file:{key}");
        let _ = kv.delete(&prefixed).await;
    }
    Ok(())
}

/// Return which backend is active (for diagnostics).
pub fn backend_name(env: &Env) -> &'static str {
    if env.bucket("ATTACHMENTS").is_ok() {
        "R2"
    } else if env.kv("KV").is_ok() {
        "KV"
    } else {
        "none"
    }
}
