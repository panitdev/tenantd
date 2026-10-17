use serde::Serialize;

use crate::{Bytes, ProcessKey, SandboxKey, TenantId};

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    SandboxExited {
        key: SandboxKey,
        exit_code: Option<i32>,
    },
    SandboxOom {
        key: SandboxKey,
    },
    ProcessExited {
        key: ProcessKey,
        exit_code: Option<i32>,
        signal: Option<i32>,
        stdout_dropped: Bytes,
        stderr_dropped: Bytes,
    },
    QuotaExceeded {
        tenant: TenantId,
        used: Bytes,
        limit: Bytes,
    },
    Reconcile {
        action: String,
        target: String,
        detail: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Event {
    pub time: i64,
    #[serde(flatten)]
    pub kind: EventKind,
}

impl Event {
    pub fn now(kind: EventKind) -> Self {
        Self {
            time: crate::now(),
            kind,
        }
    }
}
