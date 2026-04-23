//! GeoIP lookup — maps client IPs to country/continent codes.
//!
//! Wraps `maxminddb::Reader` with a shape that matches the three
//! fields nefarious2's ircd_geoip.c exposes on each client:
//!
//! - `country_code`   — ISO 3166-1 alpha-2 (e.g. "US", "DE")
//! - `country_name`   — human-readable (e.g. "United States")
//! - `continent_code` — 2-char continent (e.g. "NA", "EU")
//!
//! The reader is `Arc`-wrapped on `ServerState` so /REHASH can
//! swap it atomically if the operator points MMDB_FILE at a new
//! database file. Failed lookups return sentinel "--" / "Unknown"
//! values — matches C behaviour and keeps the oper-visible output
//! uniform regardless of which IPs are in the database.

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use maxminddb::Reader;
use serde::Deserialize;

/// One client's GeoIP tags. Empty strings aren't used; we emit
/// "--" / "Unknown" for unknowns so the output is always the same
/// width regardless of database content.
#[derive(Debug, Clone)]
pub struct GeoTag {
    pub country_code: String,
    pub country_name: String,
    pub continent_code: String,
}

impl GeoTag {
    pub fn unknown() -> Self {
        Self {
            country_code: "--".into(),
            country_name: "Unknown".into(),
            continent_code: "--".into(),
        }
    }
}

/// MaxMindDB Country schema — owned-string form so the decoded
/// value doesn't borrow from the reader. The slight allocation
/// cost is irrelevant at connect rate and avoids threading
/// lifetimes through the lookup API.
#[derive(Debug, Deserialize)]
struct CountryRecord {
    country: Option<Country>,
    continent: Option<Continent>,
}

#[derive(Debug, Deserialize)]
struct Country {
    iso_code: Option<String>,
    names: Option<Names>,
}

#[derive(Debug, Deserialize)]
struct Continent {
    code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Names {
    en: Option<String>,
}

/// Open an MMDB file and return a shareable reader. `None` on any
/// read/parse error — callers keep the existing reader (if any) and
/// log a warning rather than treating GeoIP as required.
pub fn open(path: &Path) -> Option<Arc<Reader<Vec<u8>>>> {
    match Reader::open_readfile(path) {
        Ok(r) => Some(Arc::new(r)),
        Err(e) => {
            tracing::warn!("GeoIP: failed to open {}: {e}", path.display());
            None
        }
    }
}

/// Look up `ip` in the reader. Returns the three-field tag or
/// `GeoTag::unknown()` on NotFound / decode errors — we never
/// refuse to produce a value, so callers can unconditionally
/// render the columns.
pub fn lookup(reader: &Reader<Vec<u8>>, ip: IpAddr) -> GeoTag {
    // maxminddb ≥ 0.25 returns `Result<Option<T>, _>`; `Ok(None)` is
    // "IP not in the database" (what the older API signalled as
    // AddressNotFoundError). Either flavour of miss collapses to an
    // "unknown" tag so callers can render the columns unconditionally.
    let r = match reader.lookup::<CountryRecord>(ip) {
        Ok(Some(r)) => r,
        Ok(None) | Err(_) => return GeoTag::unknown(),
    };
    let country_code = r
        .country
        .as_ref()
        .and_then(|c| c.iso_code.clone())
        .unwrap_or_else(|| "--".into());
    let country_name = r
        .country
        .as_ref()
        .and_then(|c| c.names.as_ref())
        .and_then(|n| n.en.clone())
        .unwrap_or_else(|| "Unknown".into());
    let continent_code = r
        .continent
        .as_ref()
        .and_then(|c| c.code.clone())
        .unwrap_or_else(|| "--".into());
    GeoTag {
        country_code,
        country_name,
        continent_code,
    }
}
