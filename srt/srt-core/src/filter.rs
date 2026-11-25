//! Packet filter configuration: parse, validate and negotiate (spec 8.1-8.3).
//! The FEC filter itself is not implemented yet; this only decides which
//! config string both sides agree on, exactly as libsrt 1.5.7 does.

use std::collections::BTreeMap;

/// A parsed filter config: `type[,key:value]*`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterConfig {
    pub kind: String,
    pub params: BTreeMap<String, String>,
}

/// Defaults of the built-in `fec` filter.
const FEC_DEFAULTS: [(&str, &str); 3] = [("rows", "1"), ("layout", "staircase"), ("arq", "onreq")];

impl FilterConfig {
    /// Parse; empty values are ignored (as libsrt). `None` if malformed or,
    /// for `fec`, invalid.
    pub fn parse(s: &str) -> Option<FilterConfig> {
        let mut it = s.split(',');
        let kind = it.next()?.trim().to_string();
        if kind.is_empty() {
            return None;
        }
        let mut params = BTreeMap::new();
        for kv in it {
            let (k, v) = kv.split_once(':')?;
            if v.is_empty() {
                continue;
            }
            params.insert(k.to_string(), v.to_string());
        }
        let c = FilterConfig { kind, params };
        if c.kind == "fec" && !c.fec_valid() {
            return None;
        }
        Some(c)
    }

    fn fec_valid(&self) -> bool {
        for (k, v) in &self.params {
            let ok = match k.as_str() {
                "cols" => v.parse::<i64>().map_or(false, |c| (2..=65535).contains(&c)),
                "rows" => v.parse::<i64>().map_or(false, |r| r != 0 && r != -1 && r.abs() <= 65535),
                "layout" => v == "even" || v == "staircase",
                "arq" => v == "never" || v == "onreq" || v == "always",
                _ => false,
            };
            if !ok {
                return false;
            }
        }
        true
    }

    fn fill_defaults(&mut self) {
        if self.kind == "fec" {
            for (k, v) in FEC_DEFAULTS {
                self.params.entry(k.to_string()).or_insert_with(|| v.to_string());
            }
        }
    }

    /// Canonical string, keys sorted (what a libsrt listener echoes).
    pub fn to_config_string(&self) -> String {
        let mut s = self.kind.clone();
        for (k, v) in &self.params {
            s.push(',');
            s.push_str(k);
            s.push(':');
            s.push_str(v);
        }
        s
    }

    /// `fec` needs `cols` (after merging).
    fn complete(&self) -> bool {
        self.kind != "fec" || self.params.contains_key("cols")
    }
}

/// The two sides' filter configs cannot be reconciled (reject FILTER, 1014).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilterMismatch;

/// Validate a locally configured filter string.
pub fn validate(s: &str) -> bool {
    s.len() <= crate::handshake::MAX_FILTER_LEN && FilterConfig::parse(s).is_some()
}

/// Listener side (spec 8.3): `Ok(Some(s))` is the config to use and echo,
/// `Ok(None)` means no filter, `Err` rejects with FILTER (1014).
pub fn negotiate_listener(own: Option<&str>, caller: Option<&str>) -> Result<Option<String>, FilterMismatch> {
    match (own, caller) {
        (_, None) => Ok(None), // listener drops its own filter
        (None, Some(c)) => {
            let p = FilterConfig::parse(c).ok_or(FilterMismatch)?;
            if !p.complete() {
                return Err(FilterMismatch);
            }
            Ok(Some(c.to_string()))
        }
        (Some(o), Some(c)) => {
            let mut a = FilterConfig::parse(o).ok_or(FilterMismatch)?;
            let mut b = FilterConfig::parse(c).ok_or(FilterMismatch)?;
            if a.kind != b.kind {
                return Err(FilterMismatch);
            }
            let a0 = a.params.clone();
            for (k, v) in &b.params {
                a.params.entry(k.clone()).or_insert_with(|| v.clone());
            }
            for (k, v) in &a0 {
                b.params.entry(k.clone()).or_insert_with(|| v.clone());
            }
            a.fill_defaults();
            b.fill_defaults();
            if a != b || !a.complete() {
                return Err(FilterMismatch);
            }
            Ok(Some(a.to_config_string()))
        }
    }
}

/// Caller side: what it uses after the response (`Err` rejects FILTER).
pub fn negotiate_caller(own: Option<&str>, response: Option<&str>) -> Result<Option<String>, FilterMismatch> {
    match (own, response) {
        (None, None) => Ok(None),
        (Some(_), None) => Err(FilterMismatch),
        (_, Some(r)) => {
            FilterConfig::parse(r).ok_or(FilterMismatch)?;
            Ok(Some(r.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_matches_libsrt_capture() {
        // libsrt 1.5.7 listener with fec,cols:4,rows:2 and a caller with the
        // same string answered "fec,arq:onreq,cols:4,layout:staircase,rows:2"
        let m = negotiate_listener(Some("fec,cols:4,rows:2"), Some("fec,cols:4,rows:2")).unwrap();
        assert_eq!(m.as_deref(), Some("fec,arq:onreq,cols:4,layout:staircase,rows:2"));
    }

    #[test]
    fn negotiation_rules() {
        assert_eq!(negotiate_listener(None, Some("fec,cols:10")).unwrap().as_deref(), Some("fec,cols:10"));
        assert_eq!(negotiate_listener(Some("fec,cols:10"), None).unwrap(), None);
        assert!(negotiate_listener(Some("fec,cols:10"), Some("fec,cols:20")).is_err());
        assert!(negotiate_listener(Some("fec,cols:10,arq:never"), Some("fec,cols:10,arq:onreq")).is_err());
        // a key set on one side only is filled from it (libsrt CheckFilterCompat)
        assert_eq!(
            negotiate_listener(Some("fec,cols:10,arq:never"), Some("fec,cols:10")).unwrap().as_deref(),
            Some("fec,arq:never,cols:10,layout:staircase,rows:1")
        );
        assert_eq!(
            negotiate_listener(Some("fec"), Some("fec,cols:10,rows:5")).unwrap().as_deref(),
            Some("fec,arq:onreq,cols:10,layout:staircase,rows:5")
        );
        assert!(negotiate_listener(Some("fec"), Some("fec")).is_err(), "cols is mandatory");
        assert!(negotiate_caller(Some("fec,cols:4"), None).is_err());
        assert_eq!(
            negotiate_caller(Some("fec,cols:4"), Some("fec,cols:4,rows:1")).unwrap().as_deref(),
            Some("fec,cols:4,rows:1")
        );
        assert_eq!(negotiate_caller(None, None).unwrap(), None);
    }

    #[test]
    fn validation() {
        assert!(validate("fec,cols:10,rows:5,layout:staircase,arq:onreq"));
        assert!(!validate("fec,cols:1"));
        assert!(!validate("fec,cols:10,rows:-1"));
        assert!(!validate("fec,cols:10,rows:0"));
        assert!(!validate("fec,cols:10,layout:staggered"));
        assert!(!validate("fec,cols:10,bogus:1"));
        assert!(validate("fec,cols:10,rows:-2"));
        assert!(validate("fec,cols:10,rows:"));
    }
}
