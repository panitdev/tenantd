//! Volumes: durable directories in a tenant's quota, the only state that
//! outlives a container. Containers mount them through the slots their
//! profile declares; callers on the host reach them at their path.
//!
//! Create and delete follow the intent pattern: the row is written as
//! `creating` or `deleting` before the directory is touched, so reconcile
//! can finish either. Volume locks come after sandbox locks and before
//! container locks: a container create holds the locks of the volumes it
//! binds while it checks them and inserts its row, so a delete either sees
//! that row or deletes the volume first.

use std::path::{Component, Path, PathBuf};

use tracing::{info, warn};

use crate::Tenantd;
use crate::model::{PruneReport, VolumeOwner, VolumeRecord, VolumeState};
use crate::{Error, Result, TenantId, VolumeKey, now, policy};

/// A prune's path prefix: relative, plain components, at most 4 KiB.
pub fn prefix_path(prefix: &str) -> Result<PathBuf> {
    let bad = || {
        Error::invalid(format!(
            "path prefix {prefix:?} must be a relative path inside the volume"
        ))
    };
    if prefix.len() > 4096 || prefix.contains('\0') || prefix.starts_with('/') {
        return Err(bad());
    }
    let p = Path::new(prefix);
    if !p.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(bad());
    }
    Ok(p.to_path_buf())
}

impl Tenantd {
    /// Idempotent on the key: the same owner returns the existing volume, a
    /// different one is `AlreadyExists`.
    pub async fn create_volume(&self, key: VolumeKey, owner: VolumeOwner) -> Result<VolumeRecord> {
        self.require_enforcement()?;
        self.require_unblocked(&key.tenant)?;
        policy::check_volume_owner(&self.config(), &owner)?;
        let _t = self.tenant_locks.lock(key.tenant.clone()).await;
        self.ready_tenant(&key.tenant).await?;
        let _v = self.volume_locks.lock(key.clone()).await;
        let mut rec = match self.state.get_volume(&key.tenant, &key.volume).await? {
            Some(r) if r.owner != owner => {
                return Err(Error::AlreadyExists(format!(
                    "volume {key} exists with a different owner or mode"
                )));
            }
            Some(r) => match r.state {
                VolumeState::Ready => return Ok(r),
                VolumeState::Deleting => {
                    return Err(Error::FailedPrecondition(format!(
                        "volume {key} is being deleted"
                    )));
                }
                VolumeState::Creating => r,
            },
            None => {
                let ts = now();
                let rec = VolumeRecord {
                    tenant: key.tenant.clone(),
                    id: key.volume.clone(),
                    owner,
                    state: VolumeState::Creating,
                    created_at: ts,
                    updated_at: ts,
                };
                self.state.insert_volume(&rec).await?;
                rec
            }
        };
        self.finish_create_volume(&mut rec).await?;
        Ok(rec)
    }

    /// Create the directory and mark the row ready; rolls back on failure.
    /// Caller holds the volume lock.
    pub(crate) async fn finish_create_volume(&self, rec: &mut VolumeRecord) -> Result<()> {
        let dir = self.storage.tenant_dir(&rec.tenant);
        match self.volumes.create(&dir, &rec.id, rec.owner).await {
            Ok(_) => {
                rec.state = VolumeState::Ready;
                rec.updated_at = now();
                self.state.update_volume(rec).await?;
                info!(volume = %rec.key(), "volume ready");
                Ok(())
            }
            Err(e) => {
                warn!(volume = %rec.key(), error = %e, "volume create failed, rolling back");
                self.volumes.delete(&dir, &rec.id).await?;
                self.state.delete_volume(&rec.tenant, &rec.id).await?;
                Err(e)
            }
        }
    }

    pub async fn get_volume(&self, key: &VolumeKey) -> Result<VolumeRecord> {
        self.state
            .get_volume(&key.tenant, &key.volume)
            .await?
            .ok_or_else(|| Error::NotFound(format!("volume {key}")))
    }

    pub async fn list_volumes(&self, t: &TenantId) -> Result<Vec<VolumeRecord>> {
        if self.state.get_tenant(t).await?.is_none() {
            return Err(Error::NotFound(format!("tenant {t}")));
        }
        self.state.list_volumes(Some(t)).await
    }

    /// Where a volume is on the host.
    pub fn volume_path(&self, rec: &VolumeRecord) -> PathBuf {
        self.volumes
            .path(&self.storage.tenant_dir(&rec.tenant), &rec.id)
    }

    /// Removes the volume and everything in it. Refused while a container
    /// binds it; deleting a missing volume succeeds.
    pub async fn delete_volume(&self, key: &VolumeKey) -> Result<()> {
        let _v = self.volume_locks.lock(key.clone()).await;
        let Some(mut rec) = self.state.get_volume(&key.tenant, &key.volume).await? else {
            return Ok(());
        };
        if rec.state != VolumeState::Deleting {
            let users: Vec<String> = self
                .state
                .list_containers(None)
                .await?
                .into_iter()
                .filter(|c| c.tenant == key.tenant && c.binds(&key.volume))
                .map(|c| c.key().to_string())
                .collect();
            if !users.is_empty() {
                return Err(Error::FailedPrecondition(format!(
                    "volume {key} is bound by containers {}; delete them first",
                    users.join(", ")
                )));
            }
            rec.state = VolumeState::Deleting;
            rec.updated_at = now();
            self.state.update_volume(&rec).await?;
        }
        self.finish_delete_volume(&rec).await
    }

    /// Caller holds the volume lock and the row is `deleting`.
    pub(crate) async fn finish_delete_volume(&self, rec: &VolumeRecord) -> Result<()> {
        let dir = self.storage.tenant_dir(&rec.tenant);
        self.volumes.delete(&dir, &rec.id).await?;
        self.state.delete_volume(&rec.tenant, &rec.id).await?;
        info!(volume = %rec.key(), "volume deleted");
        Ok(())
    }

    /// Remove what is at or below `prefix` and has not been accessed,
    /// modified or changed for `older_than_secs`; 0 removes all of it.
    pub async fn prune_volume(
        &self,
        key: &VolumeKey,
        prefix: &str,
        older_than_secs: u64,
    ) -> Result<PruneReport> {
        let prefix = prefix_path(prefix)?;
        // No volume lock: a long walk would hold up container creates that
        // bind the volume. A delete racing it only cuts it short.
        let rec = self.get_volume(key).await?;
        if rec.state != VolumeState::Ready {
            return Err(Error::FailedPrecondition(format!(
                "volume {key} is {}",
                rec.state.as_str()
            )));
        }
        let cutoff = (older_than_secs > 0)
            .then(|| now().saturating_sub(i64::try_from(older_than_secs).unwrap_or(i64::MAX)));
        let dir = self.storage.tenant_dir(&rec.tenant);
        let rep = self.volumes.prune(&dir, &rec.id, &prefix, cutoff).await?;
        info!(volume = %key, prefix = %prefix.display(), entries = rep.entries, bytes = rep.bytes, "volume pruned");
        Ok(rep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes() {
        assert_eq!(prefix_path("").unwrap(), PathBuf::new());
        assert_eq!(prefix_path("s-1/").unwrap(), PathBuf::from("s-1"));
        assert_eq!(prefix_path("a/b").unwrap(), PathBuf::from("a/b"));
        for bad in ["/", "/etc", "..", "a/../b", "./a", "a\0b"] {
            assert!(prefix_path(bad).is_err(), "{bad:?}");
        }
    }
}
