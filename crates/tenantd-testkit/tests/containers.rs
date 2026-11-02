use std::path::PathBuf;
use std::time::Duration;

use tenantd_core::backend::{RootfsSpec, RuntimeHandle, RuntimeState};
use tenantd_core::events::EventKind;
use tenantd_core::model::{
    ContainerRecord, ContainerState, Overrides, ProcessSpec, ProcessState, Signal, TenantLimits,
};
use tenantd_core::state::StateStore;
use tenantd_core::{
    ContainerId, ContainerKey, Error, ProcessId, ProcessKey, SandboxId, SandboxKey, TenantId,
};
use tenantd_testkit::Env;

fn tid(s: &str) -> TenantId {
    TenantId::new(s).unwrap()
}

fn sk(s: &str) -> SandboxKey {
    SandboxKey::new(tid("t"), SandboxId::new(s).unwrap())
}

fn ck(s: &str, c: &str) -> ContainerKey {
    ContainerKey::new(sk(s), ContainerId::new(c).unwrap())
}

fn cid(c: &str) -> Option<ContainerId> {
    Some(ContainerId::new(c).unwrap())
}

fn pk(s: &str, p: &str) -> ProcessKey {
    ProcessKey::new(sk(s), ProcessId::new(p).unwrap())
}

fn spec(args: &[&str]) -> ProcessSpec {
    ProcessSpec {
        args: args.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

/// A tenant with one running sandbox `box` on `profile`.
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
    env
}

async fn env() -> Env {
    env_with("default").await
}

fn has_root(env: &Env, k: &ContainerKey) -> bool {
    env.host.container_dirs.lock().unwrap().contains(&(
        PathBuf::from("/data/tenants/t"),
        k.sandbox.clone(),
        k.id.clone(),
    ))
}

async fn next_event(
    rx: &mut tokio::sync::broadcast::Receiver<tenantd_core::events::Event>,
    want: impl Fn(&EventKind) -> bool,
) -> EventKind {
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        if want(&ev.kind) {
            return ev.kind;
        }
    }
}

#[tokio::test]
async fn container_lifecycle() {
    let env = env().await;
    let k = ck("box", "s1");
    let rec = env
        .tenantd
        .create_container(k.clone(), vec![])
        .await
        .unwrap();
    assert_eq!(rec.state, ContainerState::Running);
    assert_eq!(env.host.runtime.container_state(&k), RuntimeState::Running);
    assert!(
        env.host
            .runtime
            .watched
            .lock()
            .unwrap()
            .contains(&RuntimeHandle::for_container(&k))
    );
    // Its own root, inside the sandbox's directory, on the sandbox's layer.
    assert!(has_root(&env, &k));
    let (created, args, root, _) = env.host.runtime.created_containers.lock().unwrap()[0].clone();
    assert_eq!(created, k);
    assert!(args.is_empty(), "the image's own command");
    assert_eq!(
        root,
        RootfsSpec::Path("/data/tenants/t/sandboxes/box/containers/s1/rootfs".into())
    );
    // Many containers, one sandbox.
    assert_eq!(env.host.runtime.created_specs.lock().unwrap().len(), 1);

    // Idempotent.
    assert_eq!(
        env.tenantd
            .create_container(k.clone(), vec![])
            .await
            .unwrap(),
        rec
    );
    assert_eq!(env.host.runtime.created_containers.lock().unwrap().len(), 1);
    env.tenantd
        .create_container(ck("box", "s2"), vec![])
        .await
        .unwrap();
    let ids: Vec<_> = env
        .tenantd
        .list_containers(&sk("box"))
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.id.to_string())
        .collect();
    assert_eq!(ids, vec!["s1", "s2"]);

    env.tenantd.delete_container(&k).await.unwrap();
    assert!(matches!(
        env.tenantd.get_container(&k).await,
        Err(Error::NotFound(_))
    ));
    assert_eq!(env.host.runtime.container_state(&k), RuntimeState::Missing);
    assert!(!has_root(&env, &k));
    // The other one and the sandbox are untouched; a second delete is fine.
    assert_eq!(
        env.host.runtime.container_state(&ck("box", "s2")),
        RuntimeState::Running
    );
    assert_eq!(env.host.runtime.state(&sk("box")), RuntimeState::Running);
    env.tenantd.delete_container(&k).await.unwrap();
}

#[tokio::test]
async fn needs_a_running_sandbox() {
    let env = env().await;
    assert!(matches!(
        env.tenantd.create_container(ck("nope", "s1"), vec![]).await,
        Err(Error::NotFound(_))
    ));
    env.tenantd
        .stop_sandbox(&tid("t"), &SandboxId::new("box").unwrap())
        .await
        .unwrap();
    assert!(matches!(
        env.tenantd.create_container(ck("box", "s1"), vec![]).await,
        Err(Error::FailedPrecondition(_))
    ));
    assert!(
        env.host
            .state
            .list_containers(None)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn processes_run_in_their_container() {
    let env = env().await;
    let mut events = env.tenantd.subscribe();
    env.tenantd.spawn_event_pump();
    let k = ck("box", "s1");
    env.tenantd
        .create_container(k.clone(), vec![])
        .await
        .unwrap();

    let p = env
        .tenantd
        .start_process(pk("box", "p1"), spec(&["make"]), cid("s1"))
        .await
        .unwrap();
    assert_eq!(p.container, cid("s1"));
    let pid = p.pid.unwrap();
    assert!(env.host.runtime.container_alive(&k, pid));
    assert!(!env.host.runtime.alive(&sk("box"), pid));

    // Same ID, same spec, other container: a different request.
    assert!(matches!(
        env.tenantd
            .start_process(pk("box", "p1"), spec(&["make"]), None)
            .await,
        Err(Error::AlreadyExists(_))
    ));
    assert_eq!(
        env.tenantd
            .start_process(pk("box", "p1"), spec(&["make"]), cid("s1"))
            .await
            .unwrap()
            .pid,
        Some(pid)
    );
    // Missing containers are refused before anything runs.
    assert!(matches!(
        env.tenantd
            .start_process(pk("box", "p2"), spec(&["x"]), cid("none"))
            .await,
        Err(Error::NotFound(_))
    ));

    // Signals go to the container, and the exit comes back to the row.
    env.tenantd
        .signal_process(&pk("box", "p1"), Signal::Term)
        .await
        .unwrap();
    let (h, _, _) = env.host.runtime.signals.lock().unwrap()[0].clone();
    assert_eq!(h, RuntimeHandle::for_container(&k));
    next_event(&mut events, |e| {
        matches!(e, EventKind::ProcessExited { .. })
    })
    .await;
    let p = env.tenantd.get_process(&pk("box", "p1")).await.unwrap();
    assert_eq!((p.state, p.signal), (ProcessState::Exited, Some(15)));
}

#[tokio::test]
async fn deleting_a_container_ends_its_processes_only() {
    let env = env().await;
    let k = ck("box", "s1");
    env.tenantd
        .create_container(k.clone(), vec![])
        .await
        .unwrap();
    let inside = env
        .tenantd
        .start_process(pk("box", "in"), spec(&["sleep"]), cid("s1"))
        .await
        .unwrap();
    let outside = env
        .tenantd
        .start_process(pk("box", "out"), spec(&["sleep"]), None)
        .await
        .unwrap();
    env.tenantd.delete_container(&k).await.unwrap();
    let inside = env.tenantd.get_process(&inside.key()).await.unwrap();
    assert_eq!(inside.state, ProcessState::Exited);
    assert!(!env.host.runtime.container_alive(&k, inside.pid.unwrap()));
    let outside = env.tenantd.get_process(&outside.key()).await.unwrap();
    assert_eq!(outside.state, ProcessState::Running);
}

#[tokio::test]
async fn a_container_exiting_on_its_own_keeps_its_root() {
    let env = env().await;
    let mut events = env.tenantd.subscribe();
    env.tenantd.spawn_event_pump();
    let k = ck("box", "s1");
    env.tenantd
        .create_container(k.clone(), vec![])
        .await
        .unwrap();
    let p = env
        .tenantd
        .start_process(pk("box", "p1"), spec(&["sleep"]), cid("s1"))
        .await
        .unwrap();

    env.host.runtime.exit_container(&k, 3);
    let ev = next_event(&mut events, |e| {
        matches!(e, EventKind::ContainerExited { .. })
    })
    .await;
    assert_eq!(
        ev,
        EventKind::ContainerExited {
            key: k.clone(),
            exit_code: Some(3)
        }
    );
    let rec = env.tenantd.get_container(&k).await.unwrap();
    assert_eq!(
        (rec.state, rec.exit_code),
        (ContainerState::Exited, Some(3))
    );
    assert_eq!(env.host.runtime.container_state(&k), RuntimeState::Missing);
    assert!(has_root(&env, &k));
    assert_eq!(
        env.tenantd.get_process(&p.key()).await.unwrap().state,
        ProcessState::Exited
    );
    assert!(matches!(
        env.tenantd
            .start_process(pk("box", "p2"), spec(&["x"]), cid("s1"))
            .await,
        Err(Error::FailedPrecondition(_))
    ));
    // Not restarted by a repeated create; delete clears it.
    assert_eq!(
        env.tenantd
            .create_container(k.clone(), vec![])
            .await
            .unwrap()
            .state,
        ContainerState::Exited
    );
    env.tenantd.delete_container(&k).await.unwrap();
    assert!(!has_root(&env, &k));
}

#[tokio::test]
async fn sandbox_stop_and_destroy_take_containers_along() {
    let env = env().await;
    let k = ck("box", "s1");
    env.tenantd
        .create_container(k.clone(), vec![])
        .await
        .unwrap();
    let p = env
        .tenantd
        .start_process(pk("box", "p1"), spec(&["sleep"]), cid("s1"))
        .await
        .unwrap();
    let id = SandboxId::new("box").unwrap();

    // host-overlay survives a stop, and so do container roots.
    env.tenantd.stop_sandbox(&tid("t"), &id).await.unwrap();
    assert_eq!(
        env.tenantd.get_container(&k).await.unwrap().state,
        ContainerState::Exited
    );
    assert_eq!(env.host.runtime.container_state(&k), RuntimeState::Missing);
    assert!(has_root(&env, &k));
    assert_eq!(
        env.tenantd.get_process(&p.key()).await.unwrap().state,
        ProcessState::Exited
    );

    // Containers aren't brought back with their sandbox.
    env.tenantd.start_sandbox(&tid("t"), &id).await.unwrap();
    assert_eq!(env.host.runtime.container_state(&k), RuntimeState::Missing);

    env.tenantd.destroy_sandbox(&tid("t"), &id).await.unwrap();
    assert!(
        env.host
            .state
            .list_containers(None)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(!has_root(&env, &k));
}

#[tokio::test]
async fn roots_go_with_a_layer_that_does_not_survive_stop() {
    let env = env_with("scratch").await;
    let k = ck("box", "s1");
    let rec = env
        .tenantd
        .create_container(k.clone(), vec![])
        .await
        .unwrap();
    assert_eq!(rec.state, ContainerState::Running);
    let (_, _, root, _) = env.host.runtime.created_containers.lock().unwrap()[0].clone();
    assert!(matches!(root, RootfsSpec::Memory(_)));
    env.tenantd
        .stop_sandbox(&tid("t"), &SandboxId::new("box").unwrap())
        .await
        .unwrap();
    assert!(!has_root(&env, &k));
    assert_eq!(
        env.tenantd.get_container(&k).await.unwrap().state,
        ContainerState::Exited
    );
}

#[tokio::test]
async fn failed_create_rolls_back() {
    let env = env().await;
    let k = ck("box", "s1");
    env.host.faults.fail("runtime.create_container");
    assert!(
        env.tenantd
            .create_container(k.clone(), vec![])
            .await
            .is_err()
    );
    assert!(env.host.state.get_container(&k).await.unwrap().is_none());
    assert!(!has_root(&env, &k));
    assert_eq!(env.host.runtime.container_state(&k), RuntimeState::Missing);

    env.host.faults.fail("runtime.start");
    assert!(
        env.tenantd
            .create_container(k.clone(), vec![])
            .await
            .is_err()
    );
    assert!(env.host.state.get_container(&k).await.unwrap().is_none());
    assert_eq!(env.host.runtime.container_state(&k), RuntimeState::Missing);
    // And it works afterwards.
    env.tenantd
        .create_container(k.clone(), vec![])
        .await
        .unwrap();
}

#[tokio::test]
async fn reconcile_keeps_finishes_and_ends_containers() {
    let mut env = env().await;
    let running = ck("box", "run");
    env.tenantd
        .create_container(running.clone(), vec![])
        .await
        .unwrap();
    let gone = ck("box", "gone");
    env.tenantd
        .create_container(gone.clone(), vec![])
        .await
        .unwrap();

    // Crash after the intent of a create, before any host work.
    let half = ck("box", "half");
    env.host
        .state
        .insert_container(&ContainerRecord {
            tenant: tid("t"),
            sandbox: SandboxId::new("box").unwrap(),
            id: half.id.clone(),
            args: vec![],
            volumes: vec![],
            fuse: None,
            state: ContainerState::Creating,
            exit_code: None,
            created_at: 1,
            updated_at: 1,
        })
        .await
        .unwrap();
    // A runtime container lost while the daemon was down.
    env.host
        .runtime
        .containers
        .lock()
        .unwrap()
        .remove(&RuntimeHandle::for_container(&gone));
    // One the runtime has with no row.
    let stray = RuntimeHandle("t.box.stray".into());
    env.host
        .runtime
        .containers
        .lock()
        .unwrap()
        .insert(stray.clone(), RuntimeState::Running);
    env.restart().await;

    let rep = env.tenantd.reconcile().await;
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    let did = |a: &str, t: &str| rep.actions.iter().any(|x| x.0 == a && x.1 == t);
    assert!(did("finish_create", &format!("container/{half}")));
    assert!(did("mark_exited", &format!("container/{gone}")));
    assert!(did("delete_orphan_container", "container/t.box.stray"));
    assert!(!rep.actions.iter().any(|x| x.1.contains("t.box.run")));

    assert_eq!(
        env.host.runtime.container_state(&running),
        RuntimeState::Running
    );
    assert_eq!(
        env.tenantd.get_container(&half).await.unwrap().state,
        ContainerState::Running
    );
    assert_eq!(
        env.tenantd.get_container(&gone).await.unwrap().state,
        ContainerState::Exited
    );
    assert!(
        !env.host
            .runtime
            .containers
            .lock()
            .unwrap()
            .contains_key(&stray)
    );

    // A second pass has nothing left to do for containers.
    let rep = env.tenantd.reconcile().await;
    assert!(
        !rep.actions.iter().any(|x| x.1.starts_with("container/")),
        "{:?}",
        rep.actions
    );
}

#[tokio::test]
async fn reconcile_ends_processes_of_an_exited_container() {
    let mut env = env().await;
    let k = ck("box", "s1");
    env.tenantd
        .create_container(k.clone(), vec![])
        .await
        .unwrap();
    let p = env
        .tenantd
        .start_process(pk("box", "p1"), spec(&["sleep"]), cid("s1"))
        .await
        .unwrap();
    // The container died while the daemon was down.
    env.host
        .runtime
        .containers
        .lock()
        .unwrap()
        .remove(&RuntimeHandle::for_container(&k));
    env.restart().await;
    let rep = env.tenantd.reconcile().await;
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(
        env.tenantd.get_process(&p.key()).await.unwrap().state,
        ProcessState::Exited
    );
}

#[tokio::test]
async fn an_init_command_needs_exec_rights() {
    // `scratch` has no exec table: only the image's own command.
    let scratch = env_with("scratch").await;
    let sleep = || vec!["sleep".to_string(), "infinity".to_string()];
    match scratch
        .tenantd
        .create_container(ck("box", "s1"), sleep())
        .await
    {
        Err(Error::PermissionDenied { rule, .. }) => assert_eq!(rule, "profiles.scratch.exec"),
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
    assert!(
        scratch
            .host
            .state
            .list_containers(None)
            .await
            .unwrap()
            .is_empty()
    );
    scratch
        .tenantd
        .create_container(ck("box", "s1"), vec![])
        .await
        .unwrap();

    let env = env().await;
    let k = ck("box", "s1");
    let rec = env
        .tenantd
        .create_container(k.clone(), sleep())
        .await
        .unwrap();
    assert_eq!(rec.args, sleep());
    let (_, args, _, _) = env.host.runtime.created_containers.lock().unwrap()[0].clone();
    assert_eq!(args, sleep());
    // Same command: the same container; another: a conflict.
    assert_eq!(
        env.tenantd
            .create_container(k.clone(), sleep())
            .await
            .unwrap(),
        rec
    );
    assert!(matches!(
        env.tenantd.create_container(k.clone(), vec![]).await,
        Err(Error::AlreadyExists(_))
    ));
    assert!(matches!(
        env.tenantd
            .create_container(ck("box", "s2"), vec!["".into()])
            .await,
        Err(Error::InvalidArgument(_))
    ));
}
