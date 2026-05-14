// Windows FileTime (100-ns ticks since 1601-01-01 UTC) <-> Unix epoch.

pub const EPOCH_AS_FILETIME: i64 = 116_444_736_000_000_000;
pub const HUNDREDS_OF_NANOSECONDS: i64 = 10_000_000;

/// Returns (seconds, nanoseconds) since the Unix epoch.
pub fn filetime_to_unix(ft: i64) -> (i64, u32) {
    let delta = ft - EPOCH_AS_FILETIME;
    // Go uses truncated integer division — same as Rust's `/` for i64.
    let secs = delta / HUNDREDS_OF_NANOSECONDS;
    let ns100 = delta % HUNDREDS_OF_NANOSECONDS;
    (secs, (ns100 * 100) as u32)
}

/// Converts (seconds, nanoseconds) since the Unix epoch into a Windows FileTime.
pub fn unix_to_filetime(secs: i64, nanos: u32) -> i64 {
    EPOCH_AS_FILETIME
        .wrapping_add(secs.wrapping_mul(HUNDREDS_OF_NANOSECONDS))
        .wrapping_add((nanos / 100) as i64)
}

/// Mirrors Go: time.Unix(s, ns100*100) followed by .String() roughly.
/// Returns ISO 8601-ish string (UTC) used only for logging — no chrono dep.
pub fn format_filetime(ft: i64) -> String {
    let (secs, nanos) = filetime_to_unix(ft);
    format!("{}s+{}ns (filetime={})", secs, nanos, ft)
}
