use std::collections::HashSet;

use async_trait::async_trait;

use crate::model::{ProcessRecord, ProcessTombstone, SandboxRecord, TenantLimits, TenantRecord};
use crate::{ProcessKey, Result, SandboxId, SandboxKey, TenantId};

/// Durable records. Each call is atomic.
#[async_trait]
pub trait StateStore: Send + Sync {
    /// Insert a tenant in state `provisioning`, allocating the lowest free
    /// project ID in `range` (inclusive) in the same transaction.
    /// IDs in `exclude` (found on disk without a row) are skipped too.
    /// `AlreadyExists` if the row exists; `ResourceExhausted` if the range is full.
    async fn insert_tenant(
        &self,
        id: &TenantId,
        limits: &TenantLimits,
        range: (u32, u32),
        exclude: &HashSet<u32>,
    ) -> Result<TenantRecord>;
    async fn get_tenant(&self, id: &TenantId) -> Result<Option<TenantRecord>>;
    async fn list_tenants(&self) -> Result<Vec<TenantRecord>>;
    async fn update_tenant(&self, rec: &TenantRecord) -> Result<()>;
    async fn delete_tenant(&self, id: &TenantId) -> Result<()>;

    /// `AlreadyExists` if the row exists.
    async fn insert_sandbox(&self, rec: &SandboxRecord) -> Result<()>;
    async fn get_sandbox(&self, t: &TenantId, s: &SandboxId) -> Result<Option<SandboxRecord>>;
    async fn list_sandboxes(&self, t: Option<&TenantId>) -> Result<Vec<SandboxRecord>>;
    async fn update_sandbox(&self, rec: &SandboxRecord) -> Result<()>;
    /// Also deletes the sandbox's process rows and tombstones.
    async fn delete_sandbox(&self, t: &TenantId, s: &SandboxId) -> Result<()>;

    /// `AlreadyExists` if the row exists.
    async fn insert_process(&self, rec: &ProcessRecord) -> Result<()>;
    async fn get_process(&self, k: &ProcessKey) -> Result<Option<ProcessRecord>>;
    async fn list_processes(&self, s: Option<&SandboxKey>) -> Result<Vec<ProcessRecord>>;
    async fn update_process(&self, rec: &ProcessRecord) -> Result<()>;
    /// Delete the row and, when given, write its tombstone in the same
    /// transaction.
    async fn delete_process(
        &self,
        k: &ProcessKey,
        tombstone: Option<&ProcessTombstone>,
    ) -> Result<()>;
    async fn get_tombstone(&self, k: &ProcessKey) -> Result<Option<ProcessTombstone>>;
    /// Remove tombstones that expired at or before `now`; returns how many.
    async fn purge_tombstones(&self, now: i64) -> Result<usize>;
}
