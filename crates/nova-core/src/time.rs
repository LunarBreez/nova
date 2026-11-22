//! Dates en UTC, sans dépendance : RFC 3339 et `AAAAMMJJ`.

use std::time::{SystemTime, UNIX_EPOCH};

/// Date civile d'un instant, en UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    /// Année.
    pub year: i64,
    /// Mois, de 1 à 12.
    pub month: u32,
    /// Jour, de 1 à 31.
    pub day: u32,
    /// Heure.
    pub hour: u32,
    /// Minute.
    pub minute: u32,
    /// Seconde.
    pub second: u32,
}

impl Civil {
    /// Date civile d'un nombre de secondes depuis l'époque Unix.
    pub fn from_unix(seconds: u64) -> Self {
        let days = (seconds / 86_400) as i64;
        let rest = (seconds % 86_400) as u32;
        // Algorithme « civil_from_days » de Howard Hinnant.
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
        let year = yoe + era * 400 + i64::from(month <= 2);
        Self {
            year,
            month,
            day,
            hour: rest / 3_600,
            minute: rest % 3_600 / 60,
            second: rest % 60,
        }
    }

    /// Date civile d'un instant système ; l'époque Unix si l'horloge est antérieure.
    pub fn from_system(time: SystemTime) -> Self {
        Self::from_unix(time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()))
    }

    /// Forme RFC 3339, par exemple `2026-11-22T14:05:09Z`.
    pub fn rfc3339(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    /// Forme compacte `AAAAMMJJ`, pour les noms de fichiers.
    pub fn compact_date(&self) -> String {
        format!("{:04}{:02}{:02}", self.year, self.month, self.day)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch() {
        assert_eq!(Civil::from_unix(0).rfc3339(), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_instants() {
        assert_eq!(
            Civil::from_unix(951_782_400).rfc3339(),
            "2000-02-29T00:00:00Z"
        );
        assert_eq!(
            Civil::from_unix(1_795_356_309).rfc3339(),
            "2026-11-22T14:05:09Z"
        );
        assert_eq!(Civil::from_unix(1_795_356_309).compact_date(), "20261122");
    }
}
