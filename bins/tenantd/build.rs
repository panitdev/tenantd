//! Records the commit being built so `tenantd version` can name it.

use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    Some(s.trim().to_owned())
}

fn main() {
    // HEAD moves on checkout; logs/HEAD also on a commit to the current
    // branch, which leaves HEAD itself untouched. Cargo always reruns for a
    // path that doesn't exist, so watch only what's there.
    for path in ["HEAD", "logs/HEAD"] {
        if let Some(p) = git(&["rev-parse", "--git-path", path])
            && Path::new(&p).exists()
        {
            println!("cargo:rerun-if-changed={p}");
        }
    }
    let sha = git(&["rev-parse", "--short=8", "HEAD"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=TENANTD_GIT_SHA={sha}");
}
