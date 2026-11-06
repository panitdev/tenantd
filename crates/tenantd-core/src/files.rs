//! File access to a running container's root, for callers that would
//! otherwise exec a binary in the image to read or write it.
//!
//! The core only decides whether a call may go ahead and how it runs. The
//! caller must be allowed exec on the sandbox's profile, acting as one of
//! its `exec.users`. Each call then runs one of two ways:
//!
//! - By default, through tenantd's file helper ([`HELPER_PATH`], tenantd's
//!   own binary bound read-only into every container), exec'd in the
//!   container as that user. It sees what the container sees (its mounts,
//!   `/tmp`, volumes, FUSE), on any layer, and costs a `runsc exec` per
//!   call.
//! - For a container created with host file access, on the host against
//!   its root, which is faster per call. Paths under a mount the host can't
//!   see through still go through the helper.

use std::path::PathBuf;
use std::sync::Arc;

use futures::FutureExt;

use crate::Tenantd;
use crate::backend::{PipedProcess, RuntimeHandle};
use crate::model::{ContainerState, ResolvedProcess};
use crate::{ContainerKey, Error, ProcessId, ProcessKey, Result, policy};

/// Where every container has tenantd's file helper: tenantd's own binary,
/// which serves one call over stdin and stdout when run under this name.
pub const HELPER_PATH: &str = "/dev/.tenantd-files";

/// File helpers running at once in one sandbox; more calls wait their
/// turn. Each is a `runsc exec` on the host.
pub const HELPERS_PER_SANDBOX: usize = 8;

/// How and as whom a file call runs.
#[derive(Clone, Debug, PartialEq)]
pub struct FileAccess {
    /// The container's runtime handle, for the helper.
    pub handle: RuntimeHandle,
    /// The helper as a process of the caller's user; `user` and
    /// `image_layers` there also say who a host call acts as.
    pub helper: ResolvedProcess,
    /// Host access, for a container created with it.
    pub host: Option<HostRoot>,
}

/// A container root the host serves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostRoot {
    /// The root on the host.
    pub root: PathBuf,
    /// Paths inside the container where something is mounted over the
    /// root: the runtime's own mounts (proc, devices, generated files),
    /// volumes and the FUSE slot. What the host sees there is the root's
    /// own directory, not the mount, so calls there go through the helper.
    pub mounts: Vec<String>,
}

impl Tenantd {
    /// Admit a file call on `key`'s root, acting as `user` (`None` or
    /// empty: the image's user). `write` calls also need enforcement to be
    /// healthy and the tenant not blocked, as every other write does.
    pub async fn file_access(
        &self,
        key: &ContainerKey,
        user: Option<&str>,
        write: bool,
    ) -> Result<FileAccess> {
        if write {
            self.require_enforcement()?;
            self.require_unblocked(&key.tenant)?;
        }
        let rec = self.get_container(key).await?;
        if rec.state != ContainerState::Running {
            return Err(Error::FailedPrecondition(format!(
                "container {key} is {}",
                rec.state.as_str()
            )));
        }
        let sk = key.sandbox_key();
        let sandbox = self.running_sandbox(&sk).await?;
        let user = policy::exec_user(&self.config(), &sandbox, user)?;
        let helper = ResolvedProcess {
            key: ProcessKey::new(sk, ProcessId::new("tenantd-files")?),
            args: vec![HELPER_PATH.to_string()],
            env: Vec::new(),
            cwd: "/".into(),
            user,
            capabilities: sandbox.spec.capabilities.clone(),
            image_layers: sandbox.spec.image.layers.clone(),
        };
        let host = if rec.host_file_access {
            let layer = self.layer(sandbox.spec.rootfs)?;
            let root = layer
                .container_files_root(&key.sandbox, &key.id, &self.storage.tenant_dir(&key.tenant))
                .await?
                .ok_or_else(|| {
                    Error::Internal(format!(
                        "container {key} has host file access but its layer has no host root"
                    ))
                })?;
            let mut mounts = self.runtime.runtime_mounts(&sandbox.spec);
            mounts.extend(rec.volumes.into_iter().map(|m| m.path));
            mounts.extend(rec.fuse);
            Some(HostRoot { root, mounts })
        } else {
            None
        };
        Ok(FileAccess {
            handle: RuntimeHandle::for_container(key),
            helper,
            host,
        })
    }

    /// Start the file helper for one call admitted by
    /// [`Tenantd::file_access`], once the sandbox has a helper slot free.
    pub async fn file_helper(&self, a: &FileAccess) -> Result<PipedProcess> {
        let slots = self
            .file_helpers
            .lock()
            .unwrap()
            .entry(a.helper.key.sandbox_key())
            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(HELPERS_PER_SANDBOX)))
            .clone();
        let permit = slots
            .acquire_owned()
            .await
            .map_err(|e| Error::internal("file helper slots", e))?;
        let mut p = self.runtime.exec_piped(&a.handle, &a.helper).await?;
        // Held until it exits, or until the call drops it.
        let exit = p.exit;
        p.exit = async move {
            let r = exit.await;
            drop(permit);
            r
        }
        .boxed();
        Ok(p)
    }
}
