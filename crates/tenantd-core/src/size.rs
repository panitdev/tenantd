use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Bytes, Error, Result};

/// A byte size in config: an integer, or a string such as `"4g"`, `"512MiB"`.
/// Suffixes are binary (k = 1024).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteSize(pub Bytes);

pub fn parse_size(s: &str) -> Result<Bytes> {
    let t = s.trim();
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| Error::invalid(format!("bad size {s:?}")))?;
    let unit = unit.trim().to_ascii_lowercase();
    let unit = unit.trim_end_matches('b').trim_end_matches('i');
    let shift = match unit {
        "" => 0,
        "k" => 10,
        "m" => 20,
        "g" => 30,
        "t" => 40,
        _ => return Err(Error::invalid(format!("bad size unit in {s:?}"))),
    };
    n.checked_mul(1u64 << shift)
        .ok_or_else(|| Error::invalid(format!("size {s:?} overflows")))
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            N(u64),
            S(String),
        }
        match Raw::deserialize(d)? {
            Raw::N(n) => Ok(ByteSize(n)),
            Raw::S(s) => parse_size(&s)
                .map(ByteSize)
                .map_err(serde::de::Error::custom),
        }
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_u64(self.0)
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("4g").unwrap(), 4 << 30);
        assert_eq!(parse_size("512MiB").unwrap(), 512 << 20);
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size("2 KB").unwrap(), 2048);
        assert!(parse_size("g").is_err());
        assert!(parse_size("4x").is_err());
        assert!(parse_size("99999999999t").is_err());
    }
}
