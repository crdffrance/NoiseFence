//! Operational ClamD VERSION checks. No content is sent and no signature hash is inferred.
use crate::antivirus::AntivirusConfig;
use serde_json::{Value, json};
use std::{sync::OnceLock, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::Semaphore,
};

/// VERSION dates lack a timezone. Preserve a ±14-hour uncertainty, not a fake exact age.
pub fn version_report(text: &str, now: i64) -> Value {
    let mut report = json!({"status":"unknown","checked_at":now,"database_revision":null,"database_date":null,
        "minimum_age_seconds":null,"maximum_age_seconds":null,"exact_loaded_set_verified":false});
    if text.len() > 512 || text.chars().any(char::is_control) {
        return report;
    }
    let fields: Vec<_> = text.split('/').collect();
    if fields.len() != 3 || !fields[0].starts_with("ClamAV ") {
        return report;
    }
    let Ok(revision) = fields[1].parse::<u64>() else {
        return report;
    };
    report["database_revision"] = json!(revision);
    let fields_date: Vec<_> = fields[2].split_whitespace().collect();
    if fields_date.len() != 5
        || !["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].contains(&fields_date[0])
    {
        return report;
    }
    let Some(month) = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ]
    .iter()
    .position(|m| m == &fields_date[1]) else {
        return report;
    };
    let (Ok(day), Ok(year)) = (fields_date[2].parse::<i64>(), fields_date[4].parse::<i64>()) else {
        return report;
    };
    let Ok(time) = fields_date[3]
        .split(':')
        .map(str::parse::<i64>)
        .collect::<Result<Vec<_>, _>>()
    else {
        return report;
    };
    if !(2000..=2100).contains(&year)
        || time.len() != 3
        || !(0..24).contains(&time[0])
        || !(0..60).contains(&time[1])
        || !(0..60).contains(&time[2])
    {
        return report;
    }
    let leap = |y: i64| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let lengths = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day < 1 || day > lengths[month] {
        return report;
    }
    let days: i64 = (1970..year)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<i64>()
        + lengths[..month].iter().sum::<i64>()
        + day
        - 1;
    let nominal = days * 86400 + time[0] * 3600 + time[1] * 60 + time[2];
    if nominal > now + 14 * 3600 {
        return report;
    }
    let minimum = (now - nominal - 14 * 3600).max(0);
    let maximum = (now - nominal + 14 * 3600).max(0);
    report["database_date"] = json!(fields[2]);
    report["minimum_age_seconds"] = json!(minimum);
    report["maximum_age_seconds"] = json!(maximum);
    report["status"] = json!(if minimum > 3 * 86400 {
        "stale"
    } else if maximum <= 3 * 86400 {
        "fresh"
    } else {
        "unknown"
    });
    report
}

pub async fn check(config: Option<&AntivirusConfig>) -> Value {
    let Some(config) = config else {
        return json!({"status":"disabled"});
    };
    static LIMIT: OnceLock<Semaphore> = OnceLock::new();
    let Ok(_permit) = LIMIT.get_or_init(|| Semaphore::new(2)).try_acquire() else {
        return json!({"status":"busy"});
    };
    let work = async {
        let mut stream = UnixStream::connect(&config.socket).await?;
        stream.write_all(b"zVERSION\0").await?;
        let mut raw = Vec::new();
        loop {
            let byte = stream.read_u8().await?;
            if byte == 0 {
                break;
            }
            anyhow::ensure!(raw.len() < 512, "oversized ClamD version reply");
            raw.push(byte);
        }
        Ok::<_, anyhow::Error>(version_report(std::str::from_utf8(&raw)?, crate::now()))
    };
    match tokio::time::timeout(Duration::from_millis(500), work).await {
        Ok(Ok(value)) => value,
        _ => {
            json!({"status":"unavailable","checked_at":crate::now(),"exact_loaded_set_verified":false})
        }
    }
}
