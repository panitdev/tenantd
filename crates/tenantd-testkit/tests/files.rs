//! Admission of file calls on a container's root.

use std::path::PathBuf;

use tenantd_core::files::{HELPER_PATH, HostRoot};
use tenantd_core::model::{ContainerSpec, Overrides, TenantLimits, VolumeOwner};
use tenantd_core::{
    ContainerId, ContainerKey, Error, SandboxId, SandboxKey, SlotName, TenantId, VolumeId,
    VolumeKey,
};
use tenantd_testkit::Env;

fn tid(s: &str) -> TenantId {
    TenantId::new(s).unwrap()
}

fn ck(s: &str, c: &str) -> ContainerKey {
    ContainerKey::new(
        SandboxKey::new(tid("t"), SandboxId::new(s).unwrap()),
        ContainerId::new(c).unwrap(),
    )
}

async fn env() -> Env {
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
    for (id, profile) in [("box", "default"), ("mem", "scratch")] {
        env.tenantd
            .create_sandbox(
                tid("t"),
                SandboxId::new(id).unwrap(),
                profile.into(),
                "alpine".into(),
                Overrides::default(),
            )
            .await
            .unwrap();
    }
    env
}

fn root(c: &str) -> PathBuf {
    PathBuf::from("/data/tenants/t/sandboxes/box/containers")
        .join(c)
        .join("rootfs")
}

#[tokio::test]
async fn running_containers() {
    let env = env().await;
    let t = &env.tenantd;
    t.spawn_event_pump();
    let k = ck("box", "c1");
    let e = t.file_access(&k, None, false).await.unwrap_err();
    assert!(matches!(e, Error::NotFound(_)), "{e}");

    let vol = VolumeKey::new(tid("t"), VolumeId::new("ws").unwrap());
    t.create_volume(vol, VolumeOwner::default()).await.unwrap();
    let spec = ContainerSpec {
        volumes: [(
            SlotName::new("workspace").unwrap(),
            VolumeId::new("ws").unwrap(),
        )]
        .into(),
        fuse: true,
        ..Default::default()
    };
    t.create_container(k.clone(), spec).await.unwrap();
    // Waiting for its FUSE server: not running yet.
    let e = t.file_access(&k, None, false).await.unwrap_err();
    assert!(matches!(e, Error::FailedPrecondition(_)), "{e}");

    let k2 = ck("box", "c2");
    let spec = ContainerSpec {
        volumes: [(
            SlotName::new("workspace").unwrap(),
            VolumeId::new("ws").unwrap(),
        )]
        .into(),
        host_file_access: true,
        ..Default::default()
    };
    t.create_container(k2.clone(), spec).await.unwrap();
    assert!(
        env.host
            .runtime
            .host_file_access
            .lock()
            .unwrap()
            .contains(&k2)
    );
    let a = t.file_access(&k2, None, true).await.unwrap();
    assert_eq!(
        a.host,
        Some(HostRoot {
            root: root("c2"),
            mounts: vec!["/proc".into(), "/dev".into(), "/workspace".into()],
        })
    );
    assert_eq!(
        (
            a.helper.args.as_slice(),
            a.helper.user.as_deref(),
            a.helper.cwd.as_str()
        ),
        (&[HELPER_PATH.to_string()][..], None, "/")
    );
    assert_eq!(
        t.file_access(&k2, Some("1000"), false)
            .await
            .unwrap()
            .helper
            .user,
        Some("1000".into())
    );

    env.host.runtime.exit_container(&k2, 0);
    for _ in 0..100 {
        if t.get_container(&k2).await.unwrap().state.as_str() == "exited" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let e = t.file_access(&k2, None, false).await.unwrap_err();
    assert!(matches!(e, Error::FailedPrecondition(_)), "{e}");
}

#[tokio::test]
async fn the_helper_by_default_and_on_memory_layers() {
    let env = env().await;
    let t = &env.tenantd;
    let k = ck("box", "c");
    t.create_container(k.clone(), vec![]).await.unwrap();
    assert!(env.host.runtime.host_file_access.lock().unwrap().is_empty());
    assert_eq!(t.file_access(&k, None, false).await.unwrap().host, None);

    let mut cfg = tenantd_core::config::Config::from_toml(tenantd_testkit::TEST_CONFIG).unwrap();
    cfg.profiles.get_mut("scratch").unwrap().exec.enabled = true;
    t.reload_config(cfg).unwrap();
    let k = ck("mem", "c");
    t.create_container(k.clone(), vec![]).await.unwrap();
    assert_eq!(t.file_access(&k, None, false).await.unwrap().host, None);
    // Host access needs the root on the host.
    let spec = ContainerSpec {
        host_file_access: true,
        ..Default::default()
    };
    let e = t.create_container(ck("mem", "h"), spec).await.unwrap_err();
    assert!(
        matches!(&e, Error::FailedPrecondition(m) if m.contains("memory")),
        "{e}"
    );
}

#[tokio::test]
async fn exec_policy_applies() {
    let env = env().await;
    let t = &env.tenantd;
    let k = ck("box", "c");
    t.create_container(k.clone(), vec![]).await.unwrap();
    let rule = |e: Error| match e {
        Error::PermissionDenied { rule, .. } => rule,
        e => panic!("{e}"),
    };
    assert_eq!(
        rule(t.file_access(&k, Some("0"), false).await.unwrap_err()),
        "profiles.default.exec.users"
    );
    // "image" is the image's user, here unset: root.
    assert_eq!(
        t.file_access(&k, Some("image"), false)
            .await
            .unwrap()
            .helper
            .user,
        None
    );

    let mut cfg = tenantd_core::config::Config::from_toml(tenantd_testkit::TEST_CONFIG).unwrap();
    cfg.profiles.get_mut("default").unwrap().exec.enabled = false;
    t.reload_config(cfg).unwrap();
    assert_eq!(
        rule(t.file_access(&k, None, false).await.unwrap_err()),
        "profiles.default.exec"
    );
}

#[tokio::test]
async fn writes_need_enforcement() {
    let env = env().await;
    let t = &env.tenantd;
    let k = ck("box", "c");
    t.create_container(k.clone(), vec![]).await.unwrap();
    env.host
        .storage
        .enforcing
        .store(false, std::sync::atomic::Ordering::SeqCst);
    t.check_health().await;
    let e = t.file_access(&k, None, true).await.unwrap_err();
    assert!(matches!(e, Error::Unavailable(_)), "{e}");
    t.file_access(&k, None, false).await.unwrap();
}
