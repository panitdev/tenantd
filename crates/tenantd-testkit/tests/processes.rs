use std::time::Duration;

use futures::StreamExt;
use tenantd_core::backend::RuntimeHandle;
use tenantd_core::events::EventKind;
use tenantd_core::model::{
    Overrides, ProcessSpec, ProcessState, ProcessTombstone, Signal, Stream, TenantLimits,
};
use tenantd_core::process::OutputChunk;
use tenantd_core::state::StateStore;
use tenantd_core::{Error, ProcessId, ProcessKey, SandboxId, SandboxKey, TenantId};
use tenantd_testkit::{Env, TEST_CONFIG};

fn tid(s: &str) -> TenantId {
    TenantId::new(s).unwrap()
}

fn sk(s: &str) -> SandboxKey {
    SandboxKey::new(tid("t"), SandboxId::new(s).unwrap())
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

fn denied_rule(e: Error) -> String {
    match e {
        Error::PermissionDenied { rule, .. } => rule,
        other => panic!("expected PermissionDenied, got {other:?}"),
    }
}

/// A tenant with one running sandbox `box` on the `default` profile.
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
    sandbox(&env, "box", "default").await;
    env
}

async fn sandbox(env: &Env, id: &str, profile: &str) {
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

async fn chunks(env: &Env, k: &ProcessKey, s: Stream, offset: u64) -> Vec<OutputChunk> {
    env.tenantd
        .read_output(k.clone(), s, offset, false)
        .await
        .unwrap()
        .map(|c| c.unwrap())
        .collect()
        .await
}

async fn next_exit(
    rx: &mut tokio::sync::broadcast::Receiver<tenantd_core::events::Event>,
) -> EventKind {
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        if matches!(ev.kind, EventKind::ProcessExited { .. }) {
            return ev.kind;
        }
    }
}

#[tokio::test]
async fn process_lifecycle() {
    let env = env().await;
    let mut events = env.tenantd.subscribe();
    env.tenantd.spawn_event_pump();
    let k = pk("box", "p1");
    let mut sp = spec(&["make", "test"]);
    sp.env = vec!["CI=1".into()];
    let rec = env
        .tenantd
        .start_process(k.clone(), sp.clone())
        .await
        .unwrap();
    assert_eq!(rec.state, ProcessState::Running);
    let pid = rec.pid.unwrap();
    assert!(env.host.runtime.alive(&sk("box"), pid));
    let h = RuntimeHandle::for_key(&sk("box"));
    assert!(
        env.host
            .runtime
            .watched_processes
            .lock()
            .unwrap()
            .contains(&(h.clone(), pid))
    );
    assert_eq!(env.host.output.watched.lock().unwrap()[&rec.io.dir], 16);
    assert!(
        rec.io
            .dir
            .starts_with("/data/tenants/t/sandboxes/box/processes/p1")
    );

    // The runtime got the sandbox's capabilities, the image env, defaults
    // and the caller's env, in that order.
    let ran = env.host.runtime.execs.lock().unwrap()[0].clone();
    assert_eq!(ran.args, vec!["make", "test"]);
    assert!(ran.capabilities.is_empty());
    assert_eq!(ran.cwd, "/");
    assert_eq!(ran.user, None);
    assert!(ran.env[0].starts_with("PATH="));
    assert_eq!(ran.env.last().unwrap(), "CI=1");
    assert!(ran.env.contains(&"HOSTNAME=box".to_string()));

    // Idempotent on the key.
    let again = env
        .tenantd
        .start_process(k.clone(), sp.clone())
        .await
        .unwrap();
    assert_eq!((again.pid, again.created_at), (rec.pid, rec.created_at));
    assert_eq!(env.host.runtime.execs.lock().unwrap().len(), 1);
    assert!(matches!(
        env.tenantd.start_process(k.clone(), spec(&["other"])).await,
        Err(Error::AlreadyExists(_))
    ));
    assert_eq!(
        env.tenantd.list_processes(&sk("box")).await.unwrap().len(),
        1
    );

    // Live processes can't be deleted without force.
    assert!(matches!(
        env.tenantd.delete_process(&k, false).await,
        Err(Error::FailedPrecondition(_))
    ));

    env.host.runtime.exit_process(&sk("box"), pid, 3);
    let done = env
        .tenantd
        .wait_process(&k, Some(Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(
        (done.state, done.exit_code, done.signal),
        (ProcessState::Exited, Some(3), None)
    );
    assert!(done.exited_at.is_some());
    match next_exit(&mut events).await {
        EventKind::ProcessExited { key, exit_code, .. } => {
            assert_eq!((key, exit_code), (k.clone(), Some(3)))
        }
        _ => unreachable!(),
    }
    assert!(
        !env.host
            .output
            .watched
            .lock()
            .unwrap()
            .contains_key(&rec.io.dir)
    );
    assert!(matches!(
        env.tenantd.signal_process(&k, Signal::Term).await,
        Err(Error::FailedPrecondition(_))
    ));

    // Delete leaves a tombstone: the ID can't run again, with any spec.
    env.tenantd.delete_process(&k, false).await.unwrap();
    env.tenantd.delete_process(&k, false).await.unwrap();
    assert!(matches!(
        env.tenantd.get_process(&k).await,
        Err(Error::NotFound(_))
    ));
    assert!(env.host.output.files.lock().unwrap().is_empty());
    for s in [sp, spec(&["other"])] {
        assert!(matches!(
            env.tenantd.start_process(k.clone(), s).await,
            Err(Error::AlreadyExists(_))
        ));
    }
}

#[tokio::test]
async fn exec_policy_denials_name_their_rule() {
    let env = env().await;
    sandbox(&env, "scratch", "scratch").await;
    let e = env
        .tenantd
        .start_process(pk("scratch", "p"), spec(&["true"]))
        .await
        .unwrap_err();
    assert_eq!(denied_rule(e), "profiles.scratch.exec");

    let as_user = |u: &str| ProcessSpec {
        user: Some(u.into()),
        ..spec(&["id"])
    };
    let e = env
        .tenantd
        .start_process(pk("box", "root"), as_user("0"))
        .await
        .unwrap_err();
    assert_eq!(denied_rule(e), "profiles.default.exec.users");
    let ok = env
        .tenantd
        .start_process(pk("box", "u"), as_user("1000"))
        .await
        .unwrap();
    assert_eq!(
        env.host.runtime.execs.lock().unwrap()[0].user.as_deref(),
        Some("1000")
    );

    let tty = ProcessSpec {
        tty: true,
        ..spec(&["sh"])
    };
    let e = env
        .tenantd
        .start_process(pk("box", "tty"), tty)
        .await
        .unwrap_err();
    assert_eq!(denied_rule(e), "profiles.default.exec.tty");

    for bad in [
        spec(&[]),
        ProcessSpec {
            env: vec!["NOEQUALS".into()],
            ..spec(&["true"])
        },
        ProcessSpec {
            cwd: Some("rel".into()),
            ..spec(&["true"])
        },
        spec(&["a\0b"]),
        spec(&vec!["x"; 257]),
    ] {
        assert!(matches!(
            env.tenantd.start_process(pk("box", "bad"), bad).await,
            Err(Error::InvalidArgument(_))
        ));
    }

    // max_processes = 2 counts live processes only.
    let p2 = env
        .tenantd
        .start_process(pk("box", "p2"), spec(&["sleep"]))
        .await
        .unwrap();
    let e = env
        .tenantd
        .start_process(pk("box", "p3"), spec(&["sleep"]))
        .await
        .unwrap_err();
    assert_eq!(denied_rule(e), "profiles.default.exec.max_processes");
    env.tenantd
        .signal_process(&ok.key(), Signal::Kill)
        .await
        .unwrap();
    env.tenantd
        .on_runtime_event(tenantd_core::backend::RuntimeEvent::ProcessExited {
            handle: RuntimeHandle::for_key(&sk("box")),
            pid: ok.pid.unwrap(),
            exit_code: None,
            signal: Some(9),
        })
        .await;
    env.tenantd
        .start_process(pk("box", "p3"), spec(&["sleep"]))
        .await
        .unwrap();
    assert!(env.host.runtime.alive(&sk("box"), p2.pid.unwrap()));

    // A stopped sandbox takes no processes.
    env.tenantd
        .stop_sandbox(&tid("t"), &SandboxId::new("box").unwrap())
        .await
        .unwrap();
    assert!(matches!(
        env.tenantd
            .start_process(pk("box", "p4"), spec(&["true"]))
            .await,
        Err(Error::FailedPrecondition(_))
    ));
}

#[tokio::test]
async fn reload_that_removes_exec_applies_to_new_starts_only() {
    let env = env().await;
    let p = env
        .tenantd
        .start_process(pk("box", "p"), spec(&["sleep"]))
        .await
        .unwrap();
    let cfg = TEST_CONFIG.replacen("enabled = true", "enabled = false", 1);
    env.tenantd
        .reload_config(tenantd_core::config::Config::from_toml(&cfg).unwrap())
        .unwrap();
    let e = env
        .tenantd
        .start_process(pk("box", "q"), spec(&["sleep"]))
        .await
        .unwrap_err();
    assert_eq!(denied_rule(e), "profiles.default.exec");
    assert!(env.host.runtime.alive(&sk("box"), p.pid.unwrap()));
    assert_eq!(
        env.tenantd.get_process(&p.key()).await.unwrap().state,
        ProcessState::Running
    );
}

#[tokio::test]
async fn output_keeps_the_head_and_reports_what_was_dropped() {
    let env = env().await;
    env.tenantd.spawn_event_pump();
    let p = env
        .tenantd
        .start_process(pk("box", "p"), spec(&["yes"]))
        .await
        .unwrap();
    let k = p.key();
    env.host.output.write(&p.io, Stream::Stdout, &[b'a'; 40]);
    env.host.output.write(&p.io, Stream::Stderr, b"oops\n");

    let live = env.tenantd.get_process(&k).await.unwrap();
    assert_eq!((live.stdout_dropped, live.stderr_dropped), (24, 0));
    assert_eq!(
        chunks(&env, &k, Stream::Stdout, 0).await,
        vec![
            OutputChunk::Data {
                offset: 0,
                bytes: vec![b'a'; 16]
            },
            OutputChunk::Truncated {
                offset: 16,
                dropped: 24
            }
        ]
    );
    assert_eq!(
        chunks(&env, &k, Stream::Stdout, 10).await[0],
        OutputChunk::Data {
            offset: 10,
            bytes: vec![b'a'; 6]
        }
    );
    assert_eq!(
        chunks(&env, &k, Stream::Stdout, 30).await,
        vec![OutputChunk::Truncated {
            offset: 16,
            dropped: 24
        }]
    );
    // stderr has its own budget.
    assert_eq!(
        chunks(&env, &k, Stream::Stderr, 0).await,
        vec![OutputChunk::Data {
            offset: 0,
            bytes: b"oops\n".to_vec()
        }]
    );

    env.host.output.write(&p.io, Stream::Stdout, &[b'b'; 10]);
    env.host.runtime.exit_process(&sk("box"), p.pid.unwrap(), 0);
    let done = env.tenantd.wait_process(&k, None).await.unwrap();
    assert_eq!((done.stdout_dropped, done.stderr_dropped), (34, 0));
    // Final counts are on the row.
    let row = env.host.state.get_process(&k).await.unwrap().unwrap();
    assert_eq!(row.stdout_dropped, 34);
}

#[tokio::test]
async fn follow_streams_until_exit() {
    let env = env().await;
    env.tenantd.spawn_event_pump();
    let p = env
        .tenantd
        .start_process(pk("box", "p"), spec(&["build"]))
        .await
        .unwrap();
    let mut s = env
        .tenantd
        .read_output(p.key(), Stream::Stdout, 0, true)
        .await
        .unwrap();
    env.host.output.write(&p.io, Stream::Stdout, b"hello ");
    let first = tokio::time::timeout(Duration::from_secs(5), s.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        first,
        OutputChunk::Data {
            offset: 0,
            bytes: b"hello ".to_vec()
        }
    );
    env.host
        .output
        .write(&p.io, Stream::Stdout, b"world, and more past it");
    env.host.runtime.exit_process(&sk("box"), p.pid.unwrap(), 0);
    let rest: Vec<_> = tokio::time::timeout(Duration::from_secs(5), s.collect::<Vec<_>>())
        .await
        .unwrap();
    let rest: Vec<_> = rest.into_iter().map(|c| c.unwrap()).collect();
    assert_eq!(
        rest,
        vec![
            OutputChunk::Data {
                offset: 6,
                bytes: b"world, and".to_vec()
            },
            OutputChunk::Truncated {
                offset: 16,
                dropped: 13
            }
        ]
    );
}

#[tokio::test]
async fn wait_times_out_on_a_running_process() {
    let env = env().await;
    let p = env
        .tenantd
        .start_process(pk("box", "p"), spec(&["sleep"]))
        .await
        .unwrap();
    let r = env
        .tenantd
        .wait_process(&p.key(), Some(Duration::from_millis(50)))
        .await
        .unwrap();
    assert_eq!(r.state, ProcessState::Running);
    assert!(matches!(
        env.tenantd.wait_process(&pk("box", "nope"), None).await,
        Err(Error::NotFound(_))
    ));
}

#[tokio::test]
async fn signals_reach_the_process() {
    let env = env().await;
    let mut events = env.tenantd.subscribe();
    env.tenantd.spawn_event_pump();
    let p = env
        .tenantd
        .start_process(pk("box", "p"), spec(&["sleep"]))
        .await
        .unwrap();
    env.tenantd
        .signal_process(&p.key(), Signal::Usr1)
        .await
        .unwrap();
    assert!(env.host.runtime.alive(&sk("box"), p.pid.unwrap()));
    env.tenantd
        .signal_process(&p.key(), Signal::Term)
        .await
        .unwrap();
    let done = env.tenantd.wait_process(&p.key(), None).await.unwrap();
    assert_eq!((done.exit_code, done.signal), (None, Some(15)));
    match next_exit(&mut events).await {
        EventKind::ProcessExited { signal, .. } => assert_eq!(signal, Some(15)),
        _ => unreachable!(),
    }
    let sent: Vec<_> = env
        .host
        .runtime
        .signals
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.2)
        .collect();
    assert_eq!(sent, vec![Signal::Usr1, Signal::Term]);
}

#[tokio::test]
async fn force_delete_kills_a_live_process() {
    let env = env().await;
    let p = env
        .tenantd
        .start_process(pk("box", "p"), spec(&["sleep"]))
        .await
        .unwrap();
    env.tenantd.delete_process(&p.key(), true).await.unwrap();
    assert!(!env.host.runtime.alive(&sk("box"), p.pid.unwrap()));
    assert_eq!(env.host.runtime.signals.lock().unwrap()[0].2, Signal::Kill);
    assert!(env.tenantd.get_process(&p.key()).await.is_err());
    assert!(
        env.host
            .state
            .get_tombstone(&p.key())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn sandbox_stop_and_destroy_end_its_processes() {
    let env = env().await;
    let mut events = env.tenantd.subscribe();
    let p = env
        .tenantd
        .start_process(pk("box", "p"), spec(&["sleep"]))
        .await
        .unwrap();
    env.host.output.write(&p.io, Stream::Stdout, &[b'x'; 20]);
    let id = SandboxId::new("box").unwrap();
    env.tenantd.stop_sandbox(&tid("t"), &id).await.unwrap();
    let r = env.tenantd.get_process(&p.key()).await.unwrap();
    assert_eq!(
        (r.state, r.exit_code, r.stdout_dropped),
        (ProcessState::Exited, None, 4)
    );
    assert!(matches!(
        next_exit(&mut events).await,
        EventKind::ProcessExited { .. }
    ));

    // Starting the sandbox again doesn't revive it.
    env.tenantd.start_sandbox(&tid("t"), &id).await.unwrap();
    assert_eq!(
        env.tenantd.get_process(&p.key()).await.unwrap().state,
        ProcessState::Exited
    );
    env.tenantd.delete_process(&p.key(), false).await.unwrap();

    // Destroy removes rows, output and tombstones; a new sandbox with the
    // same name starts with a clean process namespace.
    let q = env
        .tenantd
        .start_process(pk("box", "q"), spec(&["sleep"]))
        .await
        .unwrap();
    env.host.output.write(&q.io, Stream::Stdout, b"x");
    env.tenantd.destroy_sandbox(&tid("t"), &id).await.unwrap();
    assert!(env.tenantd.list_all_processes().await.unwrap().is_empty());
    assert!(env.host.output.files.lock().unwrap().is_empty());
    sandbox(&env, "box", "default").await;
    env.tenantd
        .start_process(p.key(), spec(&["sleep"]))
        .await
        .unwrap();
}

#[tokio::test]
async fn failed_start_rolls_back_and_frees_the_id() {
    let env = env().await;
    env.host.faults.fail("runtime.exec");
    assert!(
        env.tenantd
            .start_process(pk("box", "p"), spec(&["true"]))
            .await
            .is_err()
    );
    assert!(env.tenantd.list_all_processes().await.unwrap().is_empty());
    assert!(env.host.output.files.lock().unwrap().is_empty());

    // Exec failed after the process started: it is killed.
    env.host.faults.fail("runtime.exec.after_start");
    assert!(
        env.tenantd
            .start_process(pk("box", "p"), spec(&["true"]))
            .await
            .is_err()
    );
    assert!(env.host.runtime.processes.lock().unwrap().is_empty());
    assert!(env.tenantd.list_all_processes().await.unwrap().is_empty());

    env.tenantd
        .start_process(pk("box", "p"), spec(&["true"]))
        .await
        .unwrap();
}

#[tokio::test]
async fn crash_before_exec_ran_marks_the_process_lost() {
    let mut env = env().await;
    // Exec fails and so does the rollback: the row stays `starting`.
    env.host.faults.fail("runtime.exec");
    env.host.faults.fail("output.remove");
    assert!(
        env.tenantd
            .start_process(pk("box", "p"), spec(&["true"]))
            .await
            .is_err()
    );
    assert_eq!(
        env.tenantd.list_all_processes().await.unwrap()[0].state,
        ProcessState::Starting
    );

    env.restart().await;
    let rep = env.tenantd.reconcile().await;
    assert!(
        rep.actions.iter().any(|a| a.0 == "mark_process_lost"),
        "{rep:?}"
    );
    assert!(rep.errors.is_empty(), "{rep:?}");
    let r = env.tenantd.get_process(&pk("box", "p")).await.unwrap();
    assert_eq!(r.state, ProcessState::Lost);
    assert!(r.exited_at.is_some());
}

#[tokio::test]
async fn crash_after_exec_ran_is_adopted() {
    let mut env = env().await;
    // The process started, exec reported failure, and killing it failed.
    env.host.faults.fail("runtime.exec.after_start");
    env.host.faults.fail("runtime.signal");
    assert!(
        env.tenantd
            .start_process(pk("box", "p"), spec(&["true"]))
            .await
            .is_err()
    );
    let row = &env.tenantd.list_all_processes().await.unwrap()[0];
    assert_eq!((row.state, row.pid), (ProcessState::Starting, None));

    env.restart().await;
    let rep = env.tenantd.reconcile().await;
    assert!(
        rep.actions.iter().any(|a| a.0 == "adopt_process"),
        "{rep:?}"
    );
    let r = env.tenantd.get_process(&pk("box", "p")).await.unwrap();
    let pid = r.pid.unwrap();
    assert_eq!(r.state, ProcessState::Running);
    assert!(env.host.runtime.alive(&sk("box"), pid));
    assert!(
        env.host
            .runtime
            .watched_processes
            .lock()
            .unwrap()
            .contains(&(RuntimeHandle::for_key(&sk("box")), pid))
    );
    assert!(
        env.host
            .output
            .watched
            .lock()
            .unwrap()
            .contains_key(&r.io.dir)
    );
}

#[tokio::test]
async fn reconcile_rearms_running_processes_and_ends_vanished_ones() {
    let mut env = env().await;
    let live = env
        .tenantd
        .start_process(pk("box", "live"), spec(&["sleep"]))
        .await
        .unwrap();
    let gone = env
        .tenantd
        .start_process(pk("box", "gone"), spec(&["sleep"]))
        .await
        .unwrap();
    // Written while tenantd was down: nothing enforced the limit.
    env.host.output.watched.lock().unwrap().clear();
    env.host.output.write(&live.io, Stream::Stdout, &[b'z'; 30]);
    env.host
        .runtime
        .processes
        .lock()
        .unwrap()
        .remove(&(RuntimeHandle::for_key(&sk("box")), gone.pid.unwrap()));

    env.restart().await;
    let rep = env.tenantd.reconcile().await;
    assert!(
        rep.actions.iter().any(|a| a.0 == "mark_process_exited"),
        "{rep:?}"
    );
    assert!(rep.errors.is_empty(), "{rep:?}");
    let h = RuntimeHandle::for_key(&sk("box"));
    assert!(
        env.host
            .runtime
            .watched_processes
            .lock()
            .unwrap()
            .contains(&(h, live.pid.unwrap()))
    );
    // Re-arming applied the missed trim.
    assert_eq!(
        env.host.output.files.lock().unwrap()[&live.io.stdout]
            .data
            .len(),
        16
    );
    let g = env.tenantd.get_process(&gone.key()).await.unwrap();
    assert_eq!((g.state, g.exit_code), (ProcessState::Exited, None));

    // A sandbox whose container vanished takes its processes with it.
    env.host
        .runtime
        .containers
        .lock()
        .unwrap()
        .remove(&RuntimeHandle::for_key(&sk("box")));
    env.tenantd.reconcile().await;
    assert_eq!(
        env.tenantd.get_process(&live.key()).await.unwrap().state,
        ProcessState::Exited
    );
}

#[tokio::test]
async fn retention_collects_rows_into_tombstones_that_expire() {
    let env = env().await;
    let p = env
        .tenantd
        .start_process(pk("box", "p"), spec(&["true"]))
        .await
        .unwrap();
    env.host.output.write(&p.io, Stream::Stdout, b"out");
    env.tenantd.delete_process(&p.key(), true).await.unwrap();
    let q = env
        .tenantd
        .start_process(pk("box", "q"), spec(&["true"]))
        .await
        .unwrap();
    env.tenantd
        .signal_process(&q.key(), Signal::Kill)
        .await
        .unwrap();
    env.tenantd.reconcile().await;
    let mut row = env.host.state.get_process(&q.key()).await.unwrap().unwrap();
    assert_eq!(row.state, ProcessState::Exited);

    // Not yet past retention (60s).
    let rep = env.tenantd.reconcile().await;
    assert!(!rep.actions.iter().any(|a| a.0 == "gc_process"), "{rep:?}");
    row.exited_at = Some(tenantd_core::now() - 61);
    env.host.state.update_process(&row).await.unwrap();
    let rep = env.tenantd.reconcile().await;
    assert!(rep.actions.iter().any(|a| a.0 == "gc_process"), "{rep:?}");
    assert!(env.tenantd.get_process(&q.key()).await.is_err());
    assert!(matches!(
        env.tenantd.start_process(q.key(), spec(&["true"])).await,
        Err(Error::AlreadyExists(_))
    ));

    // Expired tombstones are dropped and the ID is free again.
    let expired = ProcessTombstone {
        key: q.key(),
        spec_digest: spec(&["true"]).digest(),
        expires_at: tenantd_core::now() - 1,
    };
    env.host
        .state
        .delete_process(&q.key(), Some(&expired))
        .await
        .unwrap();
    let rep = env.tenantd.reconcile().await;
    assert!(
        rep.actions.iter().any(|a| a.0 == "purge_tombstones"),
        "{rep:?}"
    );
    env.tenantd
        .start_process(q.key(), spec(&["true"]))
        .await
        .unwrap();
}
