//! Volumes, their slots in containers, and containers' FUSE connections.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use tenantd_core::backend::{BindMount, FuseBackend, RuntimeBackend, RuntimeHandle, RuntimeState};
use tenantd_core::model::{
    ContainerSpec, ContainerState, Overrides, ProcessSpec, TenantLimits, VolumeOwner, VolumeRecord,
    VolumeState,
};
use tenantd_core::state::StateStore;
use tenantd_core::{
    ContainerId, ContainerKey, Error, ProcessId, ProcessKey, SandboxId, SandboxKey, TenantId,
    VolumeId, VolumeKey,
};
use tenantd_testkit::{Env, same_file};

fn tid(s: &str) -> TenantId {
    TenantId::new(s).unwrap()
}

fn sk(s: &str) -> SandboxKey {
    SandboxKey::new(tid("t"), SandboxId::new(s).unwrap())
}

fn ck(s: &str, c: &str) -> ContainerKey {
    ContainerKey::new(sk(s), ContainerId::new(c).unwrap())
}

fn vk(v: &str) -> VolumeKey {
    VolumeKey::new(tid("t"), VolumeId::new(v).unwrap())
}

fn vid(v: &str) -> VolumeId {
    VolumeId::new(v).unwrap()
}

fn tenant_dir() -> PathBuf {
    PathBuf::from("/data/tenants/t")
}

fn owner(uid: u32, mode: u32) -> VolumeOwner {
    VolumeOwner {
        uid,
        gid: uid,
        mode,
    }
}

fn bind(slots: &[(&str, &str)]) -> ContainerSpec {
    ContainerSpec {
        volumes: slots
            .iter()
            .map(|(s, v)| (s.parse().unwrap(), vid(v)))
            .collect::<BTreeMap<_, _>>(),
        ..Default::default()
    }
}

fn with_fuse() -> ContainerSpec {
    ContainerSpec {
        fuse: true,
        ..Default::default()
    }
}

fn rule(e: Error) -> String {
    match e {
        Error::PermissionDenied { rule, .. } => rule,
        other => panic!("expected a denial, got {other:?}"),
    }
}

/// A tenant with a running sandbox `box` on `profile` and ready volumes
/// `ws` and `tmp`.
async fn env_with(profile: &str) -> Env {
    let env = Env::new().await;
    env.tenantd
        .create_tenant(
            tid("t"),
            TenantLimits {
                storage: 1 << 30,
                cpus: None,
                memory: None,
            },
        )
        .await
        .unwrap();
    env.tenantd
        .create_sandbox(
            tid("t"),
            SandboxId::new("box").unwrap(),
            profile.into(),
            "alpine".into(),
            Overrides::default(),
        )
        .await
        .unwrap();
    for v in ["ws", "tmp"] {
        env.tenantd
            .create_volume(vk(v), owner(1000, 0o1777))
            .await
            .unwrap();
    }
    env
}

async fn env() -> Env {
    env_with("default").await
}

fn binds_of(env: &Env, k: &ContainerKey) -> Vec<BindMount> {
    env.host
        .runtime
        .created_containers
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(c, ..)| c == k)
        .map(|(.., b)| b.clone())
        .expect("container was created in the runtime")
}

#[tokio::test]
async fn volume_lifecycle_and_owner_policy() {
    let env = env().await;
    let t = &env.tenantd;
    let v = t.get_volume(&vk("ws")).await.unwrap();
    assert_eq!(v.state, VolumeState::Ready);
    assert_eq!(v.owner, owner(1000, 0o1777));
    assert_eq!(t.volume_path(&v), tenant_dir().join("volumes/ws"));
    assert_eq!(
        env.host.volumes.dirs.lock().unwrap()[&(tenant_dir(), vid("ws"))].owner,
        Some(owner(1000, 0o1777))
    );

    // Idempotent on the key; a different owner or mode is a conflict.
    assert_eq!(
        t.create_volume(vk("ws"), owner(1000, 0o1777))
            .await
            .unwrap(),
        v
    );
    assert!(matches!(
        t.create_volume(vk("ws"), owner(1000, 0o755)).await,
        Err(Error::AlreadyExists(_))
    ));

    // Root or a caller UID only; no setuid/setgid bits.
    assert_eq!(
        rule(
            t.create_volume(vk("x"), owner(1234, 0o755))
                .await
                .unwrap_err()
        ),
        "server.callers"
    );
    assert!(matches!(
        t.create_volume(vk("x"), owner(0, 0o4755)).await,
        Err(Error::InvalidArgument(_))
    ));
    assert!(matches!(
        t.create_volume(
            VolumeKey::new(tid("nobody"), vid("x")),
            VolumeOwner::default()
        )
        .await,
        Err(Error::NotFound(_))
    ));

    let ids: Vec<_> = t
        .list_volumes(&tid("t"))
        .await
        .unwrap()
        .into_iter()
        .map(|v| v.id.to_string())
        .collect();
    assert_eq!(ids, ["tmp", "ws"]);

    t.delete_volume(&vk("ws")).await.unwrap();
    t.delete_volume(&vk("ws")).await.unwrap();
    assert!(matches!(
        t.get_volume(&vk("ws")).await,
        Err(Error::NotFound(_))
    ));
    assert!(
        !env.host
            .volumes
            .dirs
            .lock()
            .unwrap()
            .contains_key(&(tenant_dir(), vid("ws")))
    );
}

#[tokio::test]
async fn prune_by_prefix_and_age() {
    let env = env().await;
    let (t, vols) = (&env.tenantd, &env.host.volumes);
    let now = tenantd_core::now();
    for (path, used) in [
        ("s-1/notes", now),
        ("s-1/old", now - 7200),
        ("s-2/old", now - 7200),
        ("handoff", now - 100_000),
        ("fresh", now),
    ] {
        vols.write(&tenant_dir(), &vid("tmp"), path, used);
    }
    // A session goes idle: its TMPDIR goes whatever its age.
    let r = t.prune_volume(&vk("tmp"), "s-1/", 0).await.unwrap();
    assert_eq!(r.entries, 2);
    // The sweep: anything not used for a day.
    let r = t.prune_volume(&vk("tmp"), "", 86400).await.unwrap();
    assert_eq!(r.entries, 1);
    assert_eq!(
        vols.files(&tenant_dir(), &vid("tmp")),
        [PathBuf::from("fresh"), PathBuf::from("s-2/old")]
    );
    for bad in ["/etc", "../x", "a/../../b"] {
        assert!(matches!(
            t.prune_volume(&vk("tmp"), bad, 0).await,
            Err(Error::InvalidArgument(_))
        ));
    }
    assert!(matches!(
        t.prune_volume(&vk("nope"), "", 0).await,
        Err(Error::NotFound(_))
    ));
}

#[tokio::test]
async fn containers_mount_the_volumes_their_slots_bind() {
    let env = env().await;
    let t = &env.tenantd;
    t.create_volume(vk("cache"), VolumeOwner::default())
        .await
        .unwrap();
    let k = ck("box", "s1");
    let spec = bind(&[("workspace", "ws"), ("tmp", "tmp"), ("cache", "cache")]);
    let rec = t.create_container(k.clone(), spec.clone()).await.unwrap();
    assert_eq!(rec.state, ContainerState::Running);
    assert_eq!(rec.spec(), spec);
    let volumes = |p: &str| tenant_dir().join("volumes").join(p);
    let mut binds = binds_of(&env, &k);
    binds.sort_by(|a, b| a.destination.cmp(&b.destination));
    assert_eq!(
        binds,
        vec![
            BindMount {
                source: volumes("cache"),
                destination: "/cache".into(),
                read_only: true
            },
            BindMount {
                source: volumes("tmp"),
                destination: "/tmp".into(),
                read_only: false
            },
            BindMount {
                source: volumes("ws"),
                destination: "/workspace".into(),
                read_only: false
            },
        ]
    );

    // Idempotent on the bindings, like on the command.
    assert_eq!(t.create_container(k.clone(), spec).await.unwrap(), rec);
    assert!(matches!(
        t.create_container(k.clone(), bind(&[("workspace", "tmp")]))
            .await,
        Err(Error::AlreadyExists(_))
    ));

    // A second session shares the workspace.
    t.create_container(ck("box", "s2"), bind(&[("workspace", "ws")]))
        .await
        .unwrap();

    // Only the profile's slots, only the tenant's ready volumes.
    assert_eq!(
        rule(
            t.create_container(ck("box", "s3"), bind(&[("etc", "ws")]))
                .await
                .unwrap_err()
        ),
        "profiles.default.volumes"
    );
    assert!(matches!(
        t.create_container(ck("box", "s3"), bind(&[("workspace", "nope")]))
            .await,
        Err(Error::NotFound(_))
    ));
    let mut deleting = t.get_volume(&vk("cache")).await.unwrap();
    deleting.state = VolumeState::Deleting;
    env.host.state.update_volume(&deleting).await.unwrap();
    assert!(matches!(
        t.create_container(ck("box", "s3"), bind(&[("cache", "cache")]))
            .await,
        Err(Error::FailedPrecondition(_))
    ));
    // Nothing was left behind by the refusals.
    assert!(t.get_container(&ck("box", "s3")).await.is_err());
}

#[tokio::test]
async fn required_slots_must_be_bound() {
    let env = env_with("pinned").await;
    let t = &env.tenantd;
    assert!(matches!(
        t.create_container(ck("box", "s1"), vec![]).await,
        Err(Error::InvalidArgument(_))
    ));
    t.create_container(ck("box", "s1"), bind(&[("workspace", "ws")]))
        .await
        .unwrap();
    // No FUSE slot in this profile.
    assert_eq!(
        rule(
            t.create_container(
                ck("box", "s2"),
                ContainerSpec {
                    fuse: true,
                    ..bind(&[("workspace", "ws")])
                }
            )
            .await
            .unwrap_err()
        ),
        "profiles.pinned.fuse"
    );
}

#[tokio::test]
async fn bound_volumes_are_not_deleted() {
    let env = env().await;
    let t = &env.tenantd;
    let k = ck("box", "s1");
    t.create_container(k.clone(), bind(&[("workspace", "ws")]))
        .await
        .unwrap();
    let e = t.delete_volume(&vk("ws")).await.unwrap_err();
    assert!(
        matches!(&e, Error::FailedPrecondition(m) if m.contains("t.box.s1")),
        "{e:?}"
    );
    // An exited container still binds it: its root and mounts stay with it.
    t.stop_sandbox(&tid("t"), &SandboxId::new("box").unwrap())
        .await
        .unwrap();
    assert!(t.delete_volume(&vk("ws")).await.is_err());
    t.delete_container(&k).await.unwrap();
    t.delete_volume(&vk("ws")).await.unwrap();
}

#[tokio::test]
async fn tenant_delete_takes_volumes_only_with_force() {
    let env = env().await;
    let t = &env.tenantd;
    t.destroy_sandbox(&tid("t"), &SandboxId::new("box").unwrap())
        .await
        .unwrap();
    assert!(matches!(
        t.delete_tenant(&tid("t"), false).await,
        Err(Error::FailedPrecondition(_))
    ));
    t.delete_tenant(&tid("t"), true).await.unwrap();
    assert!(env.host.volumes.dirs.lock().unwrap().is_empty());
    assert!(env.host.state.list_volumes(None).await.unwrap().is_empty());
}

#[tokio::test]
async fn reconcile_finishes_volume_intents_and_reports_orphans() {
    let mut env = env().await;
    let now = tenantd_core::now();
    let row = |id: &str, state| VolumeRecord {
        tenant: tid("t"),
        id: vid(id),
        owner: VolumeOwner::default(),
        state,
        created_at: now,
        updated_at: now,
    };
    // Crashes after each intent, before the host work.
    env.host
        .state
        .insert_volume(&row("half", VolumeState::Creating))
        .await
        .unwrap();
    let mut going = env.tenantd.get_volume(&vk("tmp")).await.unwrap();
    going.state = VolumeState::Deleting;
    env.host.state.update_volume(&going).await.unwrap();
    // A directory with no row.
    env.host
        .volumes
        .dirs
        .lock()
        .unwrap()
        .insert((tenant_dir(), vid("stray")), Default::default());
    env.restart().await;
    let rep = env.tenantd.reconcile().await;
    let acted = |a: &str, target: &str| rep.actions.iter().any(|(x, t, _)| x == a && t == target);
    assert!(acted("finish_create", "volume/t.half"), "{rep:?}");
    assert!(acted("finish_delete", "volume/t.tmp"), "{rep:?}");
    assert!(acted("orphan_volume_dir", "volume-dir/t.stray"), "{rep:?}");
    assert_eq!(
        env.tenantd.get_volume(&vk("half")).await.unwrap().state,
        VolumeState::Ready
    );
    assert!(env.tenantd.get_volume(&vk("tmp")).await.is_err());
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
}

#[tokio::test]
async fn fuse_container_waits_for_its_server() {
    let env = env().await;
    let t = &env.tenantd;
    let k = ck("box", "s1");
    let h = RuntimeHandle::for_container(&k);
    let spec = ContainerSpec {
        fuse: true,
        ..bind(&[("workspace", "ws")])
    };
    let rec = t.create_container(k.clone(), spec.clone()).await.unwrap();
    assert_eq!(rec.state, ContainerState::Created);
    assert_eq!(rec.fuse.as_deref(), Some("/mnt"));
    assert!(env.host.fuse.is_mounted(&k));
    assert_eq!(
        env.host.runtime.inspect(&h).await.unwrap(),
        RuntimeState::Missing,
        "nothing runs until the server is there"
    );
    assert_eq!(t.create_container(k.clone(), spec).await.unwrap(), rec);

    // No start before the attach; no processes before the start.
    assert!(matches!(
        t.start_container(&k).await,
        Err(Error::FailedPrecondition(_))
    ));
    let p = ProcessKey::new(sk("box"), ProcessId::new("p").unwrap());
    let ps = ProcessSpec {
        args: vec!["true".into()],
        ..Default::default()
    };
    assert!(matches!(
        t.start_process(p.clone(), ps.clone(), Some(k.id.clone()))
            .await,
        Err(Error::FailedPrecondition(_))
    ));

    // Every attach hands out the connection tenantd holds.
    let fd = t.attach_fuse(&k).await.unwrap();
    let held = env.host.fuse.connection(&k).unwrap().unwrap();
    assert!(same_file(&fd, &held));
    assert!(same_file(&t.attach_fuse(&k).await.unwrap(), &held));

    let rec = t.start_container(&k).await.unwrap();
    assert_eq!(rec.state, ContainerState::Running);
    assert_eq!(t.start_container(&k).await.unwrap(), rec);
    let binds = binds_of(&env, &k);
    assert!(binds.contains(&BindMount {
        source: Path::new("/run/fake/fuse").join("t.box.s1"),
        destination: "/mnt".into(),
        read_only: false,
    }));
    assert!(binds.iter().any(|b| b.destination == "/workspace"));
    t.start_process(p, ps, Some(k.id.clone())).await.unwrap();
    // A server that restarts attaches again to the same connection.
    assert!(same_file(&t.attach_fuse(&k).await.unwrap(), &held));

    t.delete_container(&k).await.unwrap();
    assert!(!env.host.fuse.is_mounted(&k));
    assert!(matches!(t.attach_fuse(&k).await, Err(Error::NotFound(_))));
}

#[tokio::test]
async fn fuse_needs_a_slot_and_a_failed_start_can_be_retried() {
    let env = env().await;
    let t = &env.tenantd;
    let plain = ck("box", "plain");
    t.create_container(plain.clone(), vec![]).await.unwrap();
    assert!(matches!(
        t.attach_fuse(&plain).await,
        Err(Error::FailedPrecondition(_))
    ));

    let k = ck("box", "s1");
    t.create_container(k.clone(), with_fuse()).await.unwrap();
    t.attach_fuse(&k).await.unwrap();
    env.host.faults.fail("runtime.start");
    assert!(t.start_container(&k).await.is_err());
    assert_eq!(
        t.get_container(&k).await.unwrap().state,
        ContainerState::Created
    );
    assert!(env.host.fuse.is_mounted(&k), "the connection is kept");
    assert_eq!(
        env.host
            .runtime
            .inspect(&RuntimeHandle::for_container(&k))
            .await
            .unwrap(),
        RuntimeState::Missing
    );
    t.start_container(&k).await.unwrap();
}

#[tokio::test]
async fn stopping_the_sandbox_ends_waiting_fuse_containers() {
    let env = env().await;
    let t = &env.tenantd;
    let k = ck("box", "s1");
    t.create_container(k.clone(), with_fuse()).await.unwrap();
    t.attach_fuse(&k).await.unwrap();
    t.stop_sandbox(&tid("t"), &SandboxId::new("box").unwrap())
        .await
        .unwrap();
    assert_eq!(
        t.get_container(&k).await.unwrap().state,
        ContainerState::Exited
    );
    assert!(!env.host.fuse.is_mounted(&k));
    assert!(matches!(
        t.start_container(&k).await,
        Err(Error::FailedPrecondition(_))
    ));
    assert!(matches!(
        t.attach_fuse(&k).await,
        Err(Error::FailedPrecondition(_))
    ));
}

#[tokio::test]
async fn fuse_connections_after_a_restart() {
    let mut env = env().await;
    let (waiting, running) = (ck("box", "waiting"), ck("box", "running"));
    for k in [&waiting, &running] {
        env.tenantd
            .create_container(k.clone(), with_fuse())
            .await
            .unwrap();
        env.tenantd.attach_fuse(k).await.unwrap();
    }
    env.tenantd.start_container(&running).await.unwrap();
    // A FUSE mount whose container is gone.
    let stray = ck("box", "stray");
    env.host.fuse.mount(&stray).await.unwrap();
    env.host.state.delete_container(&stray).await.unwrap();

    env.restart().await;
    let rep = env.tenantd.reconcile().await;
    let acted = |a: &str, target: &str| rep.actions.iter().any(|(x, t, _)| x == a && t == target);
    assert!(
        acted("resume_created", "container/t.box.waiting"),
        "{rep:?}"
    );
    assert!(
        acted("delete_orphan_fuse_mount", "fuse/t.box.stray"),
        "{rep:?}"
    );
    assert!(!env.host.fuse.is_mounted(&stray));

    // The waiting one has a fresh connection; its server attaches again
    // before it can start.
    assert!(matches!(
        env.tenantd.start_container(&waiting).await,
        Err(Error::FailedPrecondition(_))
    ));
    env.tenantd.attach_fuse(&waiting).await.unwrap();
    env.tenantd.start_container(&waiting).await.unwrap();

    // The running one keeps running on the connection its server holds,
    // but tenantd can't hand that out again.
    assert_eq!(
        env.tenantd.get_container(&running).await.unwrap().state,
        ContainerState::Running
    );
    assert!(matches!(
        env.tenantd.attach_fuse(&running).await,
        Err(Error::FailedPrecondition(m)) if m.contains("recreate")
    ));
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
}
