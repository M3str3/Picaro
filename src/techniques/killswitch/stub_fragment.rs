// --- Killswitch (technique fragment) ---

// A Preparation gate. It returns `Ok(false)` to abort the chain before the
// payload runs, `Ok(true)` to let it continue, or an `Err` carrying a
// diagnostic when a check cannot be evaluated. See `README.md`.

/// Runs the deadline and run-count checks and decides whether the chain may
/// continue.
///
/// Deadline: when `expire_on` is set, abort once the current date is past it
/// (the comparison is lexicographic, so both sides must be `YYYY-MM-DD`).
///
/// Run-count: when `max_runs` is set, read a counter from a file under the
/// per-user temporary directory, increment it and write it back, then abort
/// once the counter exceeds the limit. The counter survives between runs,
/// which is the point of the gate; a first run on a fresh machine starts at
/// zero. A missing counter file is the first run, not an error, while an
/// unreadable or unwritable file is.
///
/// A check that cannot be evaluated (the clock is before the epoch, or the
/// counter cannot be read or written) is an error rather than a silent pass.
pub fn killswitch() -> Result<bool, String> {
    let expire_on: Option<String> = $EXPIRE_ON_DEF$;
    let max_runs: Option<u32> = $MAX_RUNS_DEF$;
    let run_key: String = $RUN_KEY_DEF$;

    if let Some(deadline) = expire_on {
        let today = current_date()?;
        if today > deadline {
            crate::tech_dbg!(
                "killswitch",
                "today {today} is past the deadline {deadline}; aborting the chain"
            );
            return Ok(false);
        }
    }

    if let Some(limit) = max_runs {
        let path = std::env::temp_dir().join(run_key);
        let runs = bump_counter(&path)?;
        if runs > limit {
            crate::tech_dbg!(
                "killswitch",
                "run {runs} exceeds the limit {limit}; aborting the chain"
            );
            return Ok(false);
        }
        crate::tech_dbg!("killswitch", "run {runs}/{limit} allowed");
    }

    Ok(true)
}

/// Returns today's date as an ISO `YYYY-MM-DD` string derived from the system
/// clock, without a calendar library.
fn current_date() -> Result<String, String> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| $MSG_DATE_FAILED$)?
        .as_secs();
    let days = (secs / 86_400) as i64;
    let (year, month, day) = civil_from_days(days);
    Ok(format_ymd(year, month, day))
}

/// Reads the persisted run counter, increments it and writes the new value
/// back, returning the incremented count.
///
/// A missing file is the first run and starts at zero. The counter is only ever
/// incremented, so deleting the file resets it to zero and therefore aborts
/// sooner, never later.
fn bump_counter(path: &std::path::Path) -> Result<u32, String> {
    let current = match std::fs::read_to_string(path) {
        Ok(text) => match text.trim().parse::<u32>() {
            Ok(value) => value,
            Err(_) => return Err($MSG_COUNTER_CORRUPT$),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => return Err($MSG_COUNTER_READ_FAILED$),
    };
    let next = current.saturating_add(1);
    std::fs::write(path, next.to_string()).map_err(|_| $MSG_COUNTER_WRITE_FAILED$)?;
    Ok(next)
}

/// Converts a count of days since 1970-01-01 to a `(year, month, day)` triple.
///
/// This is Howard Hinnant's `civil_from_days` algorithm, exact across the whole
/// proleptic Gregorian calendar, so the fragment needs no date library.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (y + (if m <= 2 { 1 } else { 0 }), m, d)
}

/// Formats a `(year, month, day)` triple as `YYYY-MM-DD`.
///
/// The dashes are built from byte arithmetic rather than a stored string
/// literal, so the date separator never lands in `.rdata`.
fn format_ymd(year: i64, month: u32, day: u32) -> String {
    let mut out = String::new();
    push_four(&mut out, year as u32);
    out.push('-');
    push_two(&mut out, month);
    out.push('-');
    push_two(&mut out, day);
    out
}

/// Appends `n` as exactly two decimal digits.
fn push_two(out: &mut String, n: u32) {
    out.push((b'0' + (n / 10) as u8) as char);
    out.push((b'0' + (n % 10) as u8) as char);
}

/// Appends `n` as exactly four decimal digits.
fn push_four(out: &mut String, n: u32) {
    out.push((b'0' + (n / 1000 % 10) as u8) as char);
    out.push((b'0' + (n / 100 % 10) as u8) as char);
    out.push((b'0' + (n / 10 % 10) as u8) as char);
    out.push((b'0' + (n % 10) as u8) as char);
}
