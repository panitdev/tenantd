#!/usr/bin/env bash
# Git pre-push hook (called from .beads/hooks/pre-push). Runs the cheap part
# of ci's `check` job in a few seconds: formatting and RUSTSEC advisories.
# Clippy and tests stay in CI unless you ask for them.
#
#   TENANTD_PREPUSH_FULL=1   also run clippy and cargo test
#   git push --no-verify     skip the hook once
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

step() { printf '\033[1mpre-push:\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31mpre-push: %s\033[0m\n' "$*" >&2
         echo "  bypass once with: git push --no-verify" >&2; exit 1; }

step "cargo fmt --check"
cargo fmt --all --check || fail "formatting differs; run cargo fmt --all"

command -v cargo-audit >/dev/null 2>&1 ||
  fail "cargo-audit is not installed, and ci fails on advisories. Install it: cargo install cargo-audit --locked"
step "cargo audit"
cargo audit -q || fail "RUSTSEC advisories; ci's Dependency audit will fail (try cargo update -p <crate>)"

if [ "${TENANTD_PREPUSH_FULL:-0}" = 1 ]; then
  export RUSTFLAGS="-D warnings"
  step "cargo clippy"
  cargo clippy --workspace --all-targets --locked -q || fail "clippy failed"
  step "cargo test"
  cargo test --workspace --locked -q || fail "tests failed"
fi
