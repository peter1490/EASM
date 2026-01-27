use std::cmp::Ordering;

#[derive(Debug, Eq, PartialEq)]
pub struct Version {
    parts: Vec<u64>,
    pre_release: Option<String>,
}

impl Version {
    pub fn from(s: &str) -> Option<Self> {
        // Strip common prefixes
        let s = s.trim_start_matches(|c: char| !c.is_numeric());

        // Split into main version and pre-release
        let (main, pre) = match s.split_once(['-', '_', '+']) {
            Some((m, p)) => (m, Some(p.to_string())),
            None => (s, None),
        };

        let parts: Vec<u64> = main
            .split('.')
            .map(|p| p.parse().ok())
            .collect::<Option<Vec<_>>>()?;

        Some(Version {
            parts,
            pre_release: pre,
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare numeric parts
        let len = std::cmp::max(self.parts.len(), other.parts.len());
        for i in 0..len {
            let a = self.parts.get(i).unwrap_or(&0);
            let b = other.parts.get(i).unwrap_or(&0);
            match a.cmp(b) {
                Ordering::Equal => continue,
                other => return other,
            }
        }

        // Compare pre-release
        // Standard SemVer: 1.0.0 > 1.0.0-alpha
        // So having a pre-release makes it SMALLER than one without, if parts are equal.
        match (&self.pre_release, &other.pre_release) {
            (None, None) => Ordering::Equal,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_compare() {
        assert!(Version::from("1.2.3").unwrap() < Version::from("1.2.4").unwrap());
        assert!(Version::from("1.2.3").unwrap() == Version::from("1.2.3").unwrap());
        assert!(Version::from("1.2").unwrap() < Version::from("1.2.1").unwrap());
        assert!(Version::from("1.11").unwrap() > Version::from("1.2").unwrap()); // Numeric comparison
        assert!(Version::from("1.0.0").unwrap() > Version::from("1.0.0-rc1").unwrap());
    }
}
