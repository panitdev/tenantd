use std::time::Duration;

use tenantd_core::backend::{RuntimeHandle, RuntimeState};
use tenantd_core::events::EventKind;
use tenantd_core::model::{NetworkMode, Overrides, SandboxState, TenantLimits, TenantState};
use tenantd_core::{Error, ProjectId, SandboxId, SandboxKey, TenantId};
use tenantd_testkit::{Env, FakeTenant};

const GIB: u64 = 1 << 30;

fn tid(s: &str) -> TenantId {
    TenantId::new(s).unwrap()
}

fn sid(s: &str) -> SandboxId {
    SandboxId::new(s).unwrap()
}

fn limits(storage: u64) -> TenantLimits {
    TenantLimits {
        storage,
        cpus: None,
        memory: None,
    }
}

async fn env_with_tenant(l: TenantLimits) -> Env {
    let env = Env::new().await;
    env.tenantd.create_tenant(tid("t"), l).await.unwrap();
    env
}

async fn create(
    env: &Env,
    id: &str,
    profile: &str,
    image: &str,
) -> tenantd_core::Result<tenantd_core::model::SandboxRecord> {
    env.tenantd
        .create_sandbox(
            tid("t"),
            sid(id),
            profile.into(),
            image.into(),
            Overrides::default(),
        )
        .await
}

fn key(id: &str) -> SandboxKey {
    SandboxKey::new(tid("t"), sid(id))
}

fn denied_rule(e: Error) -> String {
    match e {
        Error::PermissionDenied { rule, .. } => rule,
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
}

#[tokio::test]
async fn tenant_create_is_idempotent_on_id() {
    let env = Env::new().await;
    let a = env
        .tenantd
        .create_tenant(tid("a"), limits(GIB))
        .await
        .unwrap();
    assert_eq!(a.state, TenantState::Ready);
    assert_eq!(a.project, ProjectId(100));
    let again = env
        .tenantd
        .create_tenant(tid("a"), limits(GIB))
        .await
        .unwrap();
    assert_eq!(again, a);
    assert!(matches!(
        env.tenantd.create_tenant(tid("a"), limits(2 * GIB)).await,
        Err(Error::AlreadyExists(_))
    ));
    let b = env
        .tenantd
        .create_tenant(tid("b"), limits(GIB))
        .await
        .unwrap();
    assert_eq!(b.project, ProjectId(101));
    assert_eq!(
        env.host.storage.tenants.lock().unwrap()[&tid("a")],
        FakeTenant {
            project: Some(ProjectId(100)),
            limit: GIB,
            used: 0
        }
    );
}

#[tokio::test]
async fn tenant_create_failure_rolls_back() {
    let env = Env::new().await;
    env.host.faults.fail("storage.set_limit");
    assert!(
        env.tenantd
            .create_tenant(tid("a"), limits(GIB))
            .await
            .is_err()
    );
    assert!(env.tenantd.list_tenants().await.unwrap().is_empty());
    assert!(env.host.storage.tenants.lock().unwrap().is_empty());
}

#[tokio::test]
async fn crash_during_tenant_create_is_finished_by_reconcile() {
    let mut env = Env::new().await;
    // Quota call fails and so does the rollback: the row stays provisioning,
    // as if the daemon died between steps.
    env.host.faults.fail("storage.set_limit");
    env.host.faults.fail("storage.delete_tenant");
    assert!(
        env.tenantd
            .create_tenant(tid("a"), limits(GIB))
            .await
            .is_err()
    );
    assert_eq!(
        env.tenantd.list_tenants().await.unwrap()[0].state,
        TenantState::Provisioning
    );

    env.restart().await;
    let rep = env.tenantd.reconcile().await;
    assert!(
        rep.actions.iter().any(|a| a.0 == "finish_create"),
        "{rep:?}"
    );
    let info = env.tenantd.get_tenant(&tid("a")).await.unwrap();
    assert_eq!(info.record.state, TenantState::Ready);
    assert_eq!(info.usage.unwrap().limit, GIB);
}

#[tokio::test]
async fn update_tenant_applies_limit() {
    let env = env_with_tenant(limits(GIB)).await;
    let rec = env
        .tenantd
        .update_tenant(&tid("t"), limits(GIB / 2))
        .await
        .unwrap();
    assert_eq!(rec.limits.storage, GIB / 2);
    assert_eq!(
        env.tenantd
            .get_tenant(&tid("t"))
            .await
            .unwrap()
            .usage
            .unwrap()
            .limit,
        GIB / 2
    );
    assert!(matches!(
        env.tenantd.update_tenant(&tid("nope"), limits(1)).await,
        Err(Error::NotFound(_))
    ));
}

#[tokio::test]
async fn sandbox_lifecycle() {
    let env = env_with_tenant(limits(GIB)).await;
    let rec = create(&env, "box", "default", "ghcr.io/example/app:1")
        .await
        .unwrap();
    assert_eq!(rec.state, SandboxState::Running);
    assert_eq!(rec.spec.image.reference, "ghcr.io/example/app:1");
    assert_eq!(rec.spec.memory, 4 * GIB);
    let k = key("box");
    assert_eq!(env.host.runtime.state(&k), RuntimeState::Running);
    assert_eq!(
        env.host.network.namespaces.lock().unwrap()[&k],
        NetworkMode::Egress
    );
    assert!(
        env.host
            .runtime
            .watched
            .lock()
            .unwrap()
            .contains(&RuntimeHandle::for_key(&k))
    );
    assert_eq!(env.host.layer_dirs.lock().unwrap().len(), 1);
    assert_eq!(
        env.tenantd
            .get_tenant(&tid("t"))
            .await
            .unwrap()
            .sandbox_count,
        1
    );

    // host-overlay survives stop.
    let stopped = env
        .tenantd
        .stop_sandbox(&tid("t"), &sid("box"))
        .await
        .unwrap();
    assert_eq!(stopped.state, SandboxState::Stopped);
    assert_eq!(env.host.runtime.state(&k), RuntimeState::Missing);
    assert!(env.host.network.namespaces.lock().unwrap().is_empty());
    assert_eq!(env.host.layer_dirs.lock().unwrap().len(), 1);
    env.tenantd
        .stop_sandbox(&tid("t"), &sid("box"))
        .await
        .unwrap();

    let started = env
        .tenantd
        .start_sandbox(&tid("t"), &sid("box"))
        .await
        .unwrap();
    assert_eq!(started.state, SandboxState::Running);
    assert_eq!(env.host.runtime.state(&k), RuntimeState::Running);

    env.tenantd
        .destroy_sandbox(&tid("t"), &sid("box"))
        .await
        .unwrap();
    assert!(matches!(
        env.tenantd.get_sandbox(&tid("t"), &sid("box")).await,
        Err(Error::NotFound(_))
    ));
    assert_eq!(env.host.runtime.state(&k), RuntimeState::Missing);
    assert!(env.host.layer_dirs.lock().unwrap().is_empty());
    env.tenantd
        .destroy_sandbox(&tid("t"), &sid("box"))
        .await
        .unwrap();
}

#[tokio::test]
async fn memory_layer_is_dropped_on_stop() {
    let env = env_with_tenant(limits(GIB)).await;
    let rec = create(&env, "m", "scratch", "alpine").await.unwrap();
    assert_eq!(rec.spec.image.reference, "docker.io/library/alpine:latest");
    assert_eq!(
        env.host.network.namespaces.lock().unwrap()[&key("m")],
        NetworkMode::None
    );
    assert!(!env.tenantd.layer_survives_stop(rec.spec.rootfs));
    env.tenantd
        .stop_sandbox(&tid("t"), &sid("m"))
        .await
        .unwrap();
    assert!(env.host.layer_dirs.lock().unwrap().is_empty());
}

#[tokio::test]
async fn sandbox_create_is_idempotent_on_id() {
    let env = env_with_tenant(limits(GIB)).await;
    let a = create(&env, "box", "default", "ghcr.io/example/app:1")
        .await
        .unwrap();
    let b = create(&env, "box", "default", "ghcr.io/example/app:1")
        .await
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(env.host.runtime.created_specs.lock().unwrap().len(), 1);
    assert!(matches!(
        create(&env, "box", "default", "ghcr.io/example/app:2").await,
        Err(Error::AlreadyExists(_))
    ));
}

#[tokio::test]
async fn policy_denials_name_their_rule() {
    let env = env_with_tenant(limits(GIB)).await;
    let e = create(&env, "x", "default", "quay.io/evil/app")
        .await
        .unwrap_err();
    assert_eq!(denied_rule(e), "profiles.default.images");
    let e = create(&env, "x", "nope", "alpine").await.unwrap_err();
    assert_eq!(denied_rule(e), "profiles");

    let raise = Overrides {
        memory: Some(8 * GIB),
        ..Default::default()
    };
    let e = env
        .tenantd
        .create_sandbox(tid("t"), sid("x"), "default".into(), "alpine".into(), raise)
        .await
        .unwrap_err();
    assert_eq!(denied_rule(e), "profiles.default.memory");
    let raise = Overrides {
        pids: Some(4096),
        ..Default::default()
    };
    let e = env
        .tenantd
        .create_sandbox(tid("t"), sid("x"), "default".into(), "alpine".into(), raise)
        .await
        .unwrap_err();
    assert_eq!(denied_rule(e), "profiles.default.pids");

    let tighten = Overrides {
        memory: Some(GIB),
        cpus: Some(0.5),
        pids: Some(64),
        size: None,
    };
    let rec = env
        .tenantd
        .create_sandbox(
            tid("t"),
            sid("x"),
            "default".into(),
            "alpine".into(),
            tighten,
        )
        .await
        .unwrap();
    assert_eq!(
        (rec.spec.memory, rec.spec.cpus, rec.spec.pids),
        (GIB, 0.5, 64)
    );
    // Nothing was pulled or created for the refused requests.
    assert_eq!(env.host.images.pulled.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn tenant_ceilings_are_admission_checked() {
    let env = env_with_tenant(TenantLimits {
        storage: GIB,
        cpus: Some(2.5),
        memory: Some(6 * GIB),
    })
    .await;
    create(&env, "a", "default", "alpine").await.unwrap();
    let e = create(&env, "b", "default", "alpine").await.unwrap_err();
    assert_eq!(denied_rule(e), "tenant.t.memory");
    // Stopped sandboxes hold no memory.
    env.tenantd
        .stop_sandbox(&tid("t"), &sid("a"))
        .await
        .unwrap();
    create(&env, "b", "default", "alpine").await.unwrap();
    let e = env
        .tenantd
        .start_sandbox(&tid("t"), &sid("a"))
        .await
        .unwrap_err();
    assert_eq!(denied_rule(e), "tenant.t.memory");
    let e = create(&env, "c", "scratch", "alpine").await.unwrap_err();
    assert_eq!(denied_rule(e), "tenant.t.cpus");
}

#[tokio::test]
async fn sandbox_create_failure_rolls_back() {
    let env = env_with_tenant(limits(GIB)).await;
    env.host.faults.fail("runtime.start");
    assert!(create(&env, "box", "default", "alpine").await.is_err());
    assert!(
        env.tenantd
            .list_sandboxes(&tid("t"))
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(env.host.runtime.state(&key("box")), RuntimeState::Missing);
    assert!(env.host.network.namespaces.lock().unwrap().is_empty());
    assert!(env.host.layer_dirs.lock().unwrap().is_empty());
    // And the ID is free again.
    create(&env, "box", "default", "alpine").await.unwrap();
}

#[tokio::test]
async fn crash_during_sandbox_create_is_finished_by_reconcile() {
    let mut env = env_with_tenant(limits(GIB)).await;
    env.host.faults.fail("runtime.start");
    env.host.faults.fail("layer.teardown");
    assert!(create(&env, "box", "default", "alpine").await.is_err());
    let rows = env.tenantd.list_sandboxes(&tid("t")).await.unwrap();
    assert_eq!(rows[0].state, SandboxState::Creating);

    env.restart().await;
    let rep = env.tenantd.reconcile().await;
    assert!(
        rep.actions.iter().any(|a| a.0 == "finish_create"),
        "{rep:?}"
    );
    assert_eq!(
        env.tenantd
            .get_sandbox(&tid("t"), &sid("box"))
            .await
            .unwrap()
            .state,
        SandboxState::Running
    );
    assert_eq!(env.host.runtime.state(&key("box")), RuntimeState::Running);
}

#[tokio::test]
async fn crash_during_create_rolls_back_when_it_cannot_finish() {
    let mut env = env_with_tenant(limits(GIB)).await;
    env.host.faults.fail("runtime.start");
    env.host.faults.fail("layer.teardown");
    assert!(create(&env, "box", "default", "alpine").await.is_err());
    env.restart().await;
    env.host.faults.fail("network.setup");
    let rep = env.tenantd.reconcile().await;
    assert!(
        rep.actions.iter().any(|a| a.0 == "rollback_create"),
        "{rep:?}"
    );
    assert!(
        env.tenantd
            .list_sandboxes(&tid("t"))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(env.host.layer_dirs.lock().unwrap().is_empty());
    assert_eq!(env.host.runtime.state(&key("box")), RuntimeState::Missing);
}

#[tokio::test]
async fn crash_during_stop_and_destroy_is_finished() {
    let mut env = env_with_tenant(limits(GIB)).await;
    create(&env, "a", "default", "alpine").await.unwrap();
    create(&env, "b", "default", "alpine").await.unwrap();
    env.host.faults.fail("runtime.destroy");
    assert!(
        env.tenantd
            .stop_sandbox(&tid("t"), &sid("a"))
            .await
            .is_err()
    );
    env.host.faults.fail("runtime.destroy");
    assert!(
        env.tenantd
            .destroy_sandbox(&tid("t"), &sid("b"))
            .await
            .is_err()
    );

    env.restart().await;
    let rep = env.tenantd.reconcile().await;
    assert!(rep.errors.is_empty(), "{rep:?}");
    assert_eq!(
        env.tenantd
            .get_sandbox(&tid("t"), &sid("a"))
            .await
            .unwrap()
            .state,
        SandboxState::Stopped
    );
    assert!(env.tenantd.get_sandbox(&tid("t"), &sid("b")).await.is_err());
    assert!(env.host.runtime.containers.lock().unwrap().is_empty());
}

#[tokio::test]
async fn exits_are_recorded_and_reported() {
    let env = env_with_tenant(limits(GIB)).await;
    let mut events = env.tenantd.subscribe();
    env.tenantd.spawn_event_pump();
    create(&env, "box", "default", "alpine").await.unwrap();
    env.host.runtime.exit(&key("box"), 3, true);

    let mut saw = (false, false);
    while saw != (true, true) {
        let ev = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .unwrap()
            .unwrap();
        match ev.kind {
            EventKind::SandboxOom { key: k } if k == key("box") => saw.0 = true,
            EventKind::SandboxExited { key: k, exit_code } if k == key("box") => {
                assert_eq!(exit_code, Some(3));
                saw.1 = true;
            }
            _ => {}
        }
    }
    let rec = env
        .tenantd
        .get_sandbox(&tid("t"), &sid("box"))
        .await
        .unwrap();
    assert_eq!((rec.state, rec.exit_code), (SandboxState::Exited, Some(3)));
    assert_eq!(env.host.runtime.state(&key("box")), RuntimeState::Missing);
    assert_eq!(
        env.host.layer_dirs.lock().unwrap().len(),
        1,
        "host-overlay layer kept after exit"
    );
    // An exited sandbox can be started again.
    let rec = env
        .tenantd
        .start_sandbox(&tid("t"), &sid("box"))
        .await
        .unwrap();
    assert_eq!((rec.state, rec.exit_code), (SandboxState::Running, None));
}

#[tokio::test]
async fn reconcile_repairs_host_drift() {
    let mut env = env_with_tenant(limits(GIB)).await;
    create(&env, "gone", "default", "alpine").await.unwrap();
    create(&env, "live", "default", "alpine").await.unwrap();

    // Container vanished behind our back.
    env.host
        .runtime
        .containers
        .lock()
        .unwrap()
        .remove(&RuntimeHandle::for_key(&key("gone")));
    // A container and a netns nobody owns.
    let stray = SandboxKey::new(tid("t"), sid("stray"));
    env.host
        .runtime
        .containers
        .lock()
        .unwrap()
        .insert(RuntimeHandle::for_key(&stray), RuntimeState::Running);
    env.host
        .network
        .namespaces
        .lock()
        .unwrap()
        .insert(stray.clone(), NetworkMode::None);
    // Project ID and limit drifted.
    {
        let mut t = env.host.storage.tenants.lock().unwrap();
        t.get_mut(&tid("t")).unwrap().project = None;
    }
    env.host
        .storage
        .limits
        .lock()
        .unwrap()
        .insert(ProjectId(100), 1);
    // A tenant dir with no row reserves its project ID.
    env.host.storage.tenants.lock().unwrap().insert(
        tid("ghost"),
        FakeTenant {
            project: Some(ProjectId(101)),
            limit: 0,
            used: 0,
        },
    );

    env.restart().await;
    let rep = env.tenantd.reconcile().await;
    let did = |a: &str| rep.actions.iter().any(|x| x.0 == a);
    assert!(
        did("mark_exited") && did("delete_orphan_container") && did("delete_orphan_netns"),
        "{rep:?}"
    );
    assert!(
        did("reapply_project") && did("orphan_tenant_dir"),
        "{rep:?}"
    );
    assert!(rep.errors.is_empty(), "{rep:?}");

    assert_eq!(
        env.tenantd
            .get_sandbox(&tid("t"), &sid("gone"))
            .await
            .unwrap()
            .state,
        SandboxState::Exited
    );
    assert_eq!(env.host.runtime.state(&stray), RuntimeState::Missing);
    assert!(
        !env.host
            .network
            .namespaces
            .lock()
            .unwrap()
            .contains_key(&stray)
    );
    assert_eq!(
        env.host.storage.tenants.lock().unwrap()[&tid("t")].project,
        Some(ProjectId(100))
    );
    assert_eq!(
        env.host.storage.limits.lock().unwrap()[&ProjectId(100)],
        GIB
    );
    // Re-attached to the running one after the restart.
    assert!(
        env.host
            .runtime
            .watched
            .lock()
            .unwrap()
            .contains(&RuntimeHandle::for_key(&key("live")))
    );
    // The orphan's project ID is not handed out.
    let n = env
        .tenantd
        .create_tenant(tid("n"), limits(GIB))
        .await
        .unwrap();
    assert_eq!(n.project, ProjectId(102));
}

#[tokio::test]
async fn quota_exceeded_is_reported() {
    let env = env_with_tenant(limits(GIB)).await;
    let mut events = env.tenantd.subscribe();
    env.host
        .storage
        .tenants
        .lock()
        .unwrap()
        .get_mut(&tid("t"))
        .unwrap()
        .used = GIB;
    env.tenantd.reconcile().await;
    loop {
        let ev = events.try_recv().unwrap();
        if let EventKind::QuotaExceeded {
            tenant,
            used,
            limit,
        } = ev.kind
        {
            assert_eq!((tenant, used, limit), (tid("t"), GIB, GIB));
            break;
        }
    }
}

#[tokio::test]
async fn delete_tenant_requires_force_with_sandboxes() {
    let env = env_with_tenant(limits(GIB)).await;
    create(&env, "a", "default", "alpine").await.unwrap();
    create(&env, "b", "scratch", "alpine").await.unwrap();
    assert!(matches!(
        env.tenantd.delete_tenant(&tid("t"), false).await,
        Err(Error::FailedPrecondition(_))
    ));
    env.tenantd.delete_tenant(&tid("t"), true).await.unwrap();
    assert!(env.tenantd.list_tenants().await.unwrap().is_empty());
    assert!(env.host.runtime.containers.lock().unwrap().is_empty());
    assert!(env.host.layer_dirs.lock().unwrap().is_empty());
    assert!(env.host.storage.tenants.lock().unwrap().is_empty());
    env.tenantd.delete_tenant(&tid("t"), false).await.unwrap();
}

#[tokio::test]
async fn fails_closed_without_enforcement() {
    let env = env_with_tenant(limits(GIB)).await;
    env.host
        .storage
        .enforcing
        .store(false, std::sync::atomic::Ordering::SeqCst);
    env.tenantd.check_health().await;
    assert!(matches!(
        env.tenantd.create_tenant(tid("b"), limits(GIB)).await,
        Err(Error::Unavailable(_))
    ));
    assert!(matches!(
        create(&env, "x", "default", "alpine").await,
        Err(Error::Unavailable(_))
    ));
    env.host
        .storage
        .enforcing
        .store(true, std::sync::atomic::Ordering::SeqCst);
    env.tenantd.check_health().await;
    create(&env, "x", "default", "alpine").await.unwrap();
}

#[tokio::test]
async fn unused_images_are_collected() {
    let env = env_with_tenant(limits(GIB)).await;
    create(&env, "a", "default", "alpine").await.unwrap();
    create(&env, "b", "default", "busybox").await.unwrap();
    env.tenantd
        .destroy_sandbox(&tid("t"), &sid("b"))
        .await
        .unwrap();
    let rep = env.tenantd.reconcile().await;
    let gc: Vec<_> = rep.actions.iter().filter(|a| a.0 == "gc_image").collect();
    assert_eq!(gc.len(), 1, "{rep:?}");
    assert_eq!(env.host.images.pulled.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn config_reload_rejects_bad_config() {
    let env = Env::new().await;
    let bad = tenantd_testkit::TEST_CONFIG.replace("rootfs = \"memory\"", "rootfs = \"filestore\"");
    let cfg = tenantd_core::config::Config::from_toml(&bad).unwrap();
    assert!(env.tenantd.reload_config(cfg).is_err());
    assert_eq!(
        env.tenantd.config().profiles["scratch"].rootfs,
        tenantd_core::model::LayerKind::Memory
    );
}
