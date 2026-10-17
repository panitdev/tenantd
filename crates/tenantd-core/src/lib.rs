//! The core of tenantd: the tenant/sandbox model, policy resolution, the
//! backend traits and the orchestration that drives them.
//!
//! Nothing in this crate touches the host directly; every side effect goes
//! through a trait in [`backend`] or [`state`], so the whole service can run
//! against fakes in tests.

pub mod backend;
pub mod config;
pub mod error;
pub mod events;
pub mod fsutil;
pub mod id;
pub mod model;
pub mod policy;
pub mod process;
pub mod reconcile;
pub mod service;
pub mod size;
pub mod state;

pub use error::{Error, Result};
pub use id::{ProcessId, ProcessKey, ProjectId, SandboxId, SandboxKey, TenantId};
pub use service::{Backends, Tenantd};

/// Byte counts. Plain `u64` keeps arithmetic and serialisation simple.
pub type Bytes = u64;

/// Seconds since the Unix epoch.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
