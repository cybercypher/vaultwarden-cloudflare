use chrono::NaiveDateTime;
use uuid::Uuid;

/// Generate a new UUID v4 string (lowercase, no hyphens).
pub fn get_uuid() -> String {
    Uuid::new_v4().to_string().replace('-', "")
}

/// Format a NaiveDateTime as an ISO 8601 string with Z suffix (what Bitwarden clients expect).
pub fn format_date(dt: &str) -> String {
    // D1 stores dates as ISO strings; ensure they end with Z for UTC
    if dt.ends_with('Z') {
        dt.to_string()
    } else {
        format!("{dt}Z")
    }
}

/// Get current UTC time as ISO 8601 string.
pub fn now_utc() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6f").to_string()
}

/// Parse a date string to NaiveDateTime.
pub fn parse_date(s: &str) -> Option<NaiveDateTime> {
    let s = s.trim_end_matches('Z');
    NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
        .ok()
        .or_else(|| NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").ok())
}
