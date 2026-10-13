//! SQLite state. One connection behind a mutex, used from `spawn_blocking`.
//! Records are columns for what reconcile and admission query, plus the
//! resolved sandbox spec as JSON.

use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, Row, params};
use tenantd_core::model::{
    Overrides, ResolvedSandbox, SandboxRecord, SandboxState, TenantLimits, TenantRecord,
    TenantState,
};
use tenantd_core::state::StateStore;
use tenantd_core::{Error, ProjectId, Result, SandboxId, TenantId, now};

const MIGRATIONS: &[&str] = &[
    // 1
    "CREATE TABLE tenants (
        id            TEXT PRIMARY KEY,
        project_id    INTEGER NOT NULL UNIQUE,
        storage_limit INTEGER NOT NULL,
        cpus          REAL,
        memory        INTEGER,
        state         TEXT NOT NULL,
        created_at    INTEGER NOT NULL,
        updated_at    INTEGER NOT NULL
    );
    CREATE TABLE sandboxes (
        tenant_id  TEXT NOT NULL REFERENCES tenants(id),
        id         TEXT NOT NULL,
        profile    TEXT NOT NULL,
        image      TEXT NOT NULL,
        overrides  TEXT NOT NULL,
        spec       TEXT NOT NULL,
        state      TEXT NOT NULL,
        exit_code  INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, id)
    );",
];

#[derive(Clone)]
pub struct SqliteState {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteState {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        let conn = Connection::open(path).map_err(db)?;
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")
            .map_err(db)?;
        Self::init(conn)
    }

    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory().map_err(db)?)
    }

    fn init(mut conn: Connection) -> Result<Self> {
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;")
            .map_err(db)?;
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(db)?;
        let version = version as usize;
        if version > MIGRATIONS.len() {
            return Err(Error::Internal(format!(
                "state schema version {version} is newer than this binary ({})",
                MIGRATIONS.len()
            )));
        }
        let tx = conn.transaction().map_err(db)?;
        for (i, m) in MIGRATIONS.iter().enumerate().skip(version) {
            tx.execute_batch(m).map_err(db)?;
            tx.pragma_update(None, "user_version", (i + 1) as i64)
                .map_err(db)?;
        }
        tx.commit().map_err(db)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || f(&mut conn.lock().unwrap()))
            .await
            .map_err(|e| Error::internal("state task", e))?
    }
}

fn db(e: rusqlite::Error) -> Error {
    Error::internal("state", e)
}

fn json<T: serde::Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|e| Error::internal("state encode", e))
}

fn conv<E: std::fmt::Display>(e: E) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, e.to_string().into())
}

fn tenant_state(s: &str) -> rusqlite::Result<TenantState> {
    serde_json::from_value(serde_json::Value::String(s.into())).map_err(conv)
}

fn sandbox_state(s: &str) -> rusqlite::Result<SandboxState> {
    serde_json::from_value(serde_json::Value::String(s.into())).map_err(conv)
}

const TENANT_COLS: &str =
    "id, project_id, storage_limit, cpus, memory, state, created_at, updated_at";

fn tenant_row(r: &Row) -> rusqlite::Result<TenantRecord> {
    Ok(TenantRecord {
        id: TenantId::new(r.get::<_, String>(0)?).map_err(conv)?,
        project: ProjectId(r.get(1)?),
        limits: TenantLimits {
            storage: r.get::<_, i64>(2)? as u64,
            cpus: r.get(3)?,
            memory: r.get::<_, Option<i64>>(4)?.map(|m| m as u64),
        },
        state: tenant_state(&r.get::<_, String>(5)?)?,
        created_at: r.get(6)?,
        updated_at: r.get(7)?,
    })
}

const SANDBOX_COLS: &str =
    "tenant_id, id, profile, image, overrides, spec, state, exit_code, created_at, updated_at";

fn sandbox_row(r: &Row) -> rusqlite::Result<SandboxRecord> {
    let overrides: Overrides = serde_json::from_str(&r.get::<_, String>(4)?).map_err(conv)?;
    let spec: ResolvedSandbox = serde_json::from_str(&r.get::<_, String>(5)?).map_err(conv)?;
    Ok(SandboxRecord {
        tenant: TenantId::new(r.get::<_, String>(0)?).map_err(conv)?,
        id: SandboxId::new(r.get::<_, String>(1)?).map_err(conv)?,
        profile: r.get(2)?,
        image: r.get(3)?,
        overrides,
        spec,
        state: sandbox_state(&r.get::<_, String>(6)?)?,
        exit_code: r.get(7)?,
        created_at: r.get(8)?,
        updated_at: r.get(9)?,
    })
}

fn is_constraint(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation)
}

#[async_trait]
impl StateStore for SqliteState {
    async fn insert_tenant(
        &self,
        id: &TenantId,
        limits: &TenantLimits,
        (lo, hi): (u32, u32),
        exclude: &HashSet<u32>,
    ) -> Result<TenantRecord> {
        let (id, limits, exclude) = (id.clone(), limits.clone(), exclude.clone());
        self.run(move |c| {
            let tx = c.transaction().map_err(db)?;
            let used: HashSet<u32> = {
                let mut st = tx
                    .prepare("SELECT project_id FROM tenants WHERE project_id BETWEEN ?1 AND ?2")
                    .map_err(db)?;
                st.query_map(params![lo, hi], |r| r.get(0))
                    .map_err(db)?
                    .collect::<rusqlite::Result<_>>()
                    .map_err(db)?
            };
            let project = (lo..=hi)
                .find(|p| !used.contains(p) && !exclude.contains(p))
                .ok_or_else(|| Error::ResourceExhausted("project ID range is full".into()))?;
            let ts = now();
            let rec = TenantRecord {
                id,
                project: ProjectId(project),
                limits,
                state: TenantState::Provisioning,
                created_at: ts,
                updated_at: ts,
            };
            tx.execute(
                &format!(
                    "INSERT INTO tenants ({TENANT_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
                ),
                params![
                    rec.id.as_str(),
                    rec.project.0,
                    rec.limits.storage as i64,
                    rec.limits.cpus,
                    rec.limits.memory.map(|m| m as i64),
                    rec.state.as_str(),
                    rec.created_at,
                    rec.updated_at
                ],
            )
            .map_err(|e| {
                if is_constraint(&e) {
                    Error::AlreadyExists(format!("tenant {}", rec.id))
                } else {
                    db(e)
                }
            })?;
            tx.commit().map_err(db)?;
            Ok(rec)
        })
        .await
    }

    async fn get_tenant(&self, id: &TenantId) -> Result<Option<TenantRecord>> {
        let id = id.clone();
        self.run(move |c| {
            c.query_row(
                &format!("SELECT {TENANT_COLS} FROM tenants WHERE id = ?1"),
                [id.as_str()],
                tenant_row,
            )
            .optional()
            .map_err(db)
        })
        .await
    }

    async fn list_tenants(&self) -> Result<Vec<TenantRecord>> {
        self.run(|c| {
            let mut st = c
                .prepare(&format!("SELECT {TENANT_COLS} FROM tenants ORDER BY id"))
                .map_err(db)?;
            st.query_map([], tenant_row)
                .map_err(db)?
                .collect::<rusqlite::Result<_>>()
                .map_err(db)
        })
        .await
    }

    async fn update_tenant(&self, rec: &TenantRecord) -> Result<()> {
        let rec = rec.clone();
        self.run(move |c| {
            let n = c
                .execute(
                    "UPDATE tenants SET storage_limit = ?2, cpus = ?3, memory = ?4, state = ?5, updated_at = ?6
                     WHERE id = ?1",
                    params![
                        rec.id.as_str(),
                        rec.limits.storage as i64,
                        rec.limits.cpus,
                        rec.limits.memory.map(|m| m as i64),
                        rec.state.as_str(),
                        rec.updated_at
                    ],
                )
                .map_err(db)?;
            if n == 0 {
                return Err(Error::NotFound(format!("tenant {}", rec.id)));
            }
            Ok(())
        })
        .await
    }

    async fn delete_tenant(&self, id: &TenantId) -> Result<()> {
        let id = id.clone();
        self.run(move |c| {
            c.execute("DELETE FROM tenants WHERE id = ?1", [id.as_str()])
                .map_err(|e| {
                    if is_constraint(&e) {
                        Error::FailedPrecondition(format!("tenant {id} still has sandboxes"))
                    } else {
                        db(e)
                    }
                })?;
            Ok(())
        })
        .await
    }

    async fn insert_sandbox(&self, rec: &SandboxRecord) -> Result<()> {
        let rec = rec.clone();
        let (ov, spec) = (json(&rec.overrides)?, json(&rec.spec)?);
        self.run(move |c| {
            c.execute(
                &format!("INSERT INTO sandboxes ({SANDBOX_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"),
                params![
                    rec.tenant.as_str(),
                    rec.id.as_str(),
                    rec.profile,
                    rec.image,
                    ov,
                    spec,
                    rec.state.as_str(),
                    rec.exit_code,
                    rec.created_at,
                    rec.updated_at
                ],
            )
            .map_err(|e| if is_constraint(&e) { Error::AlreadyExists(format!("sandbox {}", rec.key())) } else { db(e) })?;
            Ok(())
        })
        .await
    }

    async fn get_sandbox(&self, t: &TenantId, s: &SandboxId) -> Result<Option<SandboxRecord>> {
        let (t, s) = (t.clone(), s.clone());
        self.run(move |c| {
            c.query_row(
                &format!("SELECT {SANDBOX_COLS} FROM sandboxes WHERE tenant_id = ?1 AND id = ?2"),
                [t.as_str(), s.as_str()],
                sandbox_row,
            )
            .optional()
            .map_err(db)
        })
        .await
    }

    async fn list_sandboxes(&self, t: Option<&TenantId>) -> Result<Vec<SandboxRecord>> {
        let t = t.cloned();
        self.run(move |c| {
            let rows = match &t {
                Some(t) => {
                    let mut st = c
                        .prepare(&format!(
                            "SELECT {SANDBOX_COLS} FROM sandboxes WHERE tenant_id = ?1 ORDER BY id"
                        ))
                        .map_err(db)?;
                    st.query_map([t.as_str()], sandbox_row)
                        .map_err(db)?
                        .collect::<rusqlite::Result<Vec<_>>>()
                }
                None => {
                    let mut st = c
                        .prepare(&format!(
                            "SELECT {SANDBOX_COLS} FROM sandboxes ORDER BY tenant_id, id"
                        ))
                        .map_err(db)?;
                    st.query_map([], sandbox_row)
                        .map_err(db)?
                        .collect::<rusqlite::Result<Vec<_>>>()
                }
            };
            rows.map_err(db)
        })
        .await
    }

    async fn update_sandbox(&self, rec: &SandboxRecord) -> Result<()> {
        let rec = rec.clone();
        let spec = json(&rec.spec)?;
        self.run(move |c| {
            let n = c
                .execute(
                    "UPDATE sandboxes SET spec = ?3, state = ?4, exit_code = ?5, updated_at = ?6
                     WHERE tenant_id = ?1 AND id = ?2",
                    params![
                        rec.tenant.as_str(),
                        rec.id.as_str(),
                        spec,
                        rec.state.as_str(),
                        rec.exit_code,
                        rec.updated_at
                    ],
                )
                .map_err(db)?;
            if n == 0 {
                return Err(Error::NotFound(format!("sandbox {}", rec.key())));
            }
            Ok(())
        })
        .await
    }

    async fn delete_sandbox(&self, t: &TenantId, s: &SandboxId) -> Result<()> {
        let (t, s) = (t.clone(), s.clone());
        self.run(move |c| {
            c.execute(
                "DELETE FROM sandboxes WHERE tenant_id = ?1 AND id = ?2",
                [t.as_str(), s.as_str()],
            )
            .map_err(db)?;
            Ok(())
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenantd_core::SandboxKey;
    use tenantd_core::model::{ImageConfig, LayerKind, NetworkMode, ResolvedImage};

    fn limits() -> TenantLimits {
        TenantLimits {
            storage: 1 << 30,
            cpus: Some(2.0),
            memory: None,
        }
    }

    #[tokio::test]
    async fn tenants_and_projects() {
        let s = SqliteState::in_memory().unwrap();
        let a = TenantId::new("a").unwrap();
        let b = TenantId::new("b").unwrap();
        let c = TenantId::new("c").unwrap();
        let none = HashSet::new();
        let ra = s
            .insert_tenant(&a, &limits(), (10, 12), &none)
            .await
            .unwrap();
        assert_eq!(ra.project, ProjectId(10));
        assert!(matches!(
            s.insert_tenant(&a, &limits(), (10, 12), &none).await,
            Err(Error::AlreadyExists(_))
        ));
        let rb = s
            .insert_tenant(&b, &limits(), (10, 12), &HashSet::from([11]))
            .await
            .unwrap();
        assert_eq!(rb.project, ProjectId(12));
        assert!(matches!(
            s.insert_tenant(&c, &limits(), (10, 12), &HashSet::from([11]))
                .await,
            Err(Error::ResourceExhausted(_))
        ));
        s.delete_tenant(&a).await.unwrap();
        assert_eq!(
            s.insert_tenant(&c, &limits(), (10, 12), &none)
                .await
                .unwrap()
                .project,
            ProjectId(10)
        );

        let mut rc = s.get_tenant(&c).await.unwrap().unwrap();
        assert_eq!(rc.state, TenantState::Provisioning);
        rc.state = TenantState::Ready;
        rc.limits.memory = Some(5);
        s.update_tenant(&rc).await.unwrap();
        assert_eq!(s.get_tenant(&c).await.unwrap().unwrap(), rc);
        assert_eq!(s.list_tenants().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn sandboxes_roundtrip_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.db");
        let t = TenantId::new("t").unwrap();
        let rec = {
            let s = SqliteState::open(&path).unwrap();
            s.insert_tenant(&t, &limits(), (1, 5), &HashSet::new())
                .await
                .unwrap();
            let id = SandboxId::new("box").unwrap();
            let rec = SandboxRecord {
                tenant: t.clone(),
                id: id.clone(),
                profile: "default".into(),
                image: "alpine".into(),
                overrides: Overrides {
                    memory: Some(1),
                    ..Default::default()
                },
                spec: ResolvedSandbox {
                    key: SandboxKey::new(t.clone(), id),
                    profile: "default".into(),
                    image: ResolvedImage {
                        reference: "docker.io/library/alpine:latest".into(),
                        digest: "sha256:00".into(),
                        layers: vec!["/data/images/layers/x".into()],
                        config: ImageConfig::default(),
                    },
                    memory: 1,
                    cpus: 1.0,
                    pids: 10,
                    capabilities: vec![],
                    rootfs: LayerKind::HostOverlay,
                    size: None,
                    tmp_size: 0,
                    network: NetworkMode::None,
                    dns: vec![],
                },
                state: SandboxState::Creating,
                exit_code: None,
                created_at: 1,
                updated_at: 1,
            };
            s.insert_sandbox(&rec).await.unwrap();
            assert!(matches!(
                s.insert_sandbox(&rec).await,
                Err(Error::AlreadyExists(_))
            ));
            assert!(matches!(
                s.delete_tenant(&t).await,
                Err(Error::FailedPrecondition(_))
            ));
            rec
        };
        let s = SqliteState::open(&path).unwrap();
        let mut got = s.get_sandbox(&t, &rec.id).await.unwrap().unwrap();
        assert_eq!(got, rec);
        got.state = SandboxState::Exited;
        got.exit_code = Some(3);
        s.update_sandbox(&got).await.unwrap();
        assert_eq!(s.list_sandboxes(Some(&t)).await.unwrap(), vec![got.clone()]);
        assert_eq!(s.list_sandboxes(None).await.unwrap().len(), 1);
        s.delete_sandbox(&t, &rec.id).await.unwrap();
        assert!(s.get_sandbox(&t, &rec.id).await.unwrap().is_none());
    }
}
