use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub const ID_MAX_LEN: usize = 64;

/// IDs become paths, runsc container IDs, netns names and cgroup paths, so
/// only `[a-z0-9_-]{1,64}` is accepted.
pub fn validate_id(kind: &str, s: &str) -> Result<()> {
    if s.is_empty() || s.len() > ID_MAX_LEN {
        return Err(Error::invalid(format!(
            "{kind} id must be 1-{ID_MAX_LEN} characters"
        )));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(Error::invalid(format!(
            "{kind} id {s:?} must match [a-z0-9_-]{{1,64}}"
        )));
    }
    Ok(())
}

macro_rules! id_type {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn new(s: impl Into<String>) -> Result<Self> {
                let s = s.into();
                validate_id($kind, &s)?;
                Ok(Self(s))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = Error;
            fn try_from(s: String) -> Result<Self> {
                Self::new(s)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }

        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self> {
                Self::new(s)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

id_type!(TenantId, "tenant");
id_type!(SandboxId, "sandbox");
id_type!(ProcessId, "process");

/// A sandbox is scoped to its tenant. The key renders as `<tenant>.<sandbox>`;
/// `.` is outside the ID alphabet, so the split is unambiguous.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SandboxKey {
    pub tenant: TenantId,
    pub sandbox: SandboxId,
}

impl SandboxKey {
    pub fn new(tenant: TenantId, sandbox: SandboxId) -> Self {
        Self { tenant, sandbox }
    }
}

impl fmt::Display for SandboxKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.tenant, self.sandbox)
    }
}

impl FromStr for SandboxKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let (t, sb) = s
            .split_once('.')
            .ok_or_else(|| Error::invalid(format!("bad sandbox key {s:?}")))?;
        Ok(Self {
            tenant: t.parse()?,
            sandbox: sb.parse()?,
        })
    }
}

/// A process is scoped to its sandbox. Renders as `<tenant>.<sandbox>.<id>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProcessKey {
    pub tenant: TenantId,
    pub sandbox: SandboxId,
    pub id: ProcessId,
}

impl ProcessKey {
    pub fn new(sandbox: SandboxKey, id: ProcessId) -> Self {
        Self {
            tenant: sandbox.tenant,
            sandbox: sandbox.sandbox,
            id,
        }
    }

    pub fn sandbox_key(&self) -> SandboxKey {
        SandboxKey::new(self.tenant.clone(), self.sandbox.clone())
    }
}

impl fmt::Display for ProcessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.tenant, self.sandbox, self.id)
    }
}

/// Filesystem project ID. Allocated by tenantd from the configured range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProjectId(pub u32);

impl fmt::Display for ProjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(TenantId::new("acme-1_x").is_ok());
        assert!(TenantId::new("").is_err());
        assert!(TenantId::new("A").is_err());
        assert!(TenantId::new("a/b").is_err());
        assert!(TenantId::new("..").is_err());
        assert!(TenantId::new("a".repeat(64)).is_ok());
        assert!(TenantId::new("a".repeat(65)).is_err());
        assert!(serde_json::from_str::<TenantId>("\"x y\"").is_err());
    }

    #[test]
    fn key_roundtrip() {
        let k: SandboxKey = "acme.box-1".parse().unwrap();
        assert_eq!(k.tenant.as_str(), "acme");
        assert_eq!(k.to_string(), "acme.box-1");
        assert!("acme".parse::<SandboxKey>().is_err());
        assert!("a.b.c".parse::<SandboxKey>().is_err());
    }
}
