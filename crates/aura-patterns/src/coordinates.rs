use std::sync::OnceLock;

use regex::Regex;

#[derive(Debug, Clone)]
pub struct CoordinateMatch {
    pub lat: f64,
    pub lon: f64,
    pub format: CoordinateFormat,
    pub raw_text: String,
}

#[derive(Debug, Clone)]
pub enum CoordinateFormat {
    DecimalDegrees,
    Dms,
    Mgrs,
    PlusCode,
    MilitaryGrid,
}

const UKRAINE_LAT_MIN: f64 = 44.0;
const UKRAINE_LAT_MAX: f64 = 52.5;
const UKRAINE_LON_MIN: f64 = 22.0;
const UKRAINE_LON_MAX: f64 = 40.5;

fn decimal_degrees_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(\d{2})\.(\d{4,7})\s*[,;/\s]\s*(\d{2})\.(\d{4,7})")
            .expect("invalid decimal degrees regex")
    })
}

fn mgrs_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"3[4-7][TU]\s*[A-Z]{2}\s*\d{4,10}").expect("invalid MGRS regex")
    })
}

fn military_grid_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"(?:квадрат|кв\.?)\s*\d{2,4}[-/]\d{2,4}")
            .expect("invalid military grid regex")
    })
}

pub fn validate_ukraine_coordinates(text: &str) -> Vec<CoordinateMatch> {
    let mut results = Vec::new();

    for captures in decimal_degrees_regex().captures_iter(text) {
        let lat = format!("{}.{}", &captures[1], &captures[2]);
        let lon = format!("{}.{}", &captures[3], &captures[4]);
        let lat = match lat.parse::<f64>() {
            Ok(value) => value,
            Err(_) => continue,
        };
        let lon = match lon.parse::<f64>() {
            Ok(value) => value,
            Err(_) => continue,
        };

        if (UKRAINE_LAT_MIN..=UKRAINE_LAT_MAX).contains(&lat)
            && (UKRAINE_LON_MIN..=UKRAINE_LON_MAX).contains(&lon)
        {
            results.push(CoordinateMatch {
                lat,
                lon,
                format: CoordinateFormat::DecimalDegrees,
                raw_text: captures[0].to_string(),
            });
        }
    }

    for match_item in mgrs_regex().find_iter(text) {
        results.push(CoordinateMatch {
            lat: 0.0,
            lon: 0.0,
            format: CoordinateFormat::Mgrs,
            raw_text: match_item.as_str().to_string(),
        });
    }

    for match_item in military_grid_regex().find_iter(text) {
        results.push(CoordinateMatch {
            lat: 0.0,
            lon: 0.0,
            format: CoordinateFormat::MilitaryGrid,
            raw_text: match_item.as_str().to_string(),
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::validate_ukraine_coordinates;

    #[test]
    fn validates_decimal_degrees_inside_ukraine() {
        let matches = validate_ukraine_coordinates("48.8566, 30.3522");
        assert_eq!(matches.len(), 1);
        let first = &matches[0];
        assert!((first.lat - 48.8566).abs() < 0.001);
        assert!((first.lon - 30.3522).abs() < 0.001);
    }

    #[test]
    fn rejects_outside_ukraine_bounding_box() {
        let matches = validate_ukraine_coordinates("55.7558, 37.6173");
        assert!(matches.is_empty());
    }

    #[test]
    fn detects_mgrs_notation() {
        let matches = validate_ukraine_coordinates("36TUQ 12345 67890");
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn detects_military_grid_notation() {
        let matches = validate_ukraine_coordinates("квадрат 34-56");
        assert_eq!(matches.len(), 1);
    }
}
