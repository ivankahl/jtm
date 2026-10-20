//! UTC timestamps as signed files write them: `2026-10-19T03:00:00Z`, nothing else.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp(i64);

const DAY: i64 = 86_400;

impl Timestamp {
    pub const fn from_unix(seconds: i64) -> Timestamp {
        Timestamp(seconds)
    }

    pub const fn unix(self) -> i64 {
        self.0
    }

    /// The current time. A clock before 1970 reads as the epoch.
    pub fn now() -> Timestamp {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        Timestamp(seconds)
    }

    /// Parses exactly `YYYY-MM-DDTHH:MM:SSZ`. Offsets, fractions and lowercase letters are
    /// refused so every signed timestamp has one spelling.
    pub fn parse(input: &str) -> Option<Timestamp> {
        let b = input.as_bytes();
        if b.len() != 20
            || b[4] != b'-'
            || b[7] != b'-'
            || b[10] != b'T'
            || b[13] != b':'
            || b[16] != b':'
            || b[19] != b'Z'
        {
            return None;
        }
        let num = |range: std::ops::Range<usize>| -> Option<i64> {
            let digits = &b[range];
            if !digits.iter().all(u8::is_ascii_digit) {
                return None;
            }
            std::str::from_utf8(digits).ok()?.parse().ok()
        };
        let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
        let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
        if !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return None;
        }
        let days = days_from_civil(year, month, day);
        Some(Timestamp(days * DAY + hour * 3600 + minute * 60 + second))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = self.0.div_euclid(DAY);
        let secs = self.0.rem_euclid(DAY);
        let (year, month, day) = civil_from_days(days);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            secs / 3600,
            secs % 3600 / 60,
            secs % 60
        )
    }
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_round_trip() {
        for (text, unix) in [
            ("1970-01-01T00:00:00Z", 0),
            ("2000-02-29T12:34:56Z", 951_827_696),
            ("2026-10-19T03:00:00Z", 1_792_378_800),
            ("2026-11-18T03:00:00Z", 1_794_970_800),
            ("1969-12-31T23:59:59Z", -1),
        ] {
            let ts = Timestamp::parse(text).unwrap();
            assert_eq!(ts.unix(), unix, "{text}");
            assert_eq!(ts.to_string(), text);
        }
    }

    #[test]
    fn rejects_other_spellings() {
        for bad in [
            "",
            "2026-10-19",
            "2026-10-19T03:00:00",
            "2026-10-19T03:00:00+00:00",
            "2026-10-19T03:00:00.5Z",
            "2026-10-19t03:00:00z",
            "2026-13-01T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-10-19T24:00:00Z",
            "2026-10-19T03:60:00Z",
            "2026-10-19T03:00:60Z",
            "+026-10-19T03:00:00Z",
        ] {
            assert_eq!(Timestamp::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn now_is_after_this_code_was_written() {
        assert!(Timestamp::now() > Timestamp::parse("2026-01-01T00:00:00Z").unwrap());
    }
}
