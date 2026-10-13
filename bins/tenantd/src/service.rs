//! `tenantd service install|uninstall`: the systemd unit from
//! deploy/tenantd.service, pointed at this binary and config.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use clap::Subcommand;

use crate::serve::ConfigPath;

const UNIT: &str = include_str!("../../../deploy/tenantd.service");
const UNIT_BIN: &str = "/usr/local/bin/tenantd";
const UNIT_CONFIG: &str = "/etc/tenantd/tenantd.toml";

#[derive(Subcommand)]
pub enum ServiceCmd {
    /// Write the systemd unit for this binary, then enable and start it.
    Install {
        #[command(flatten)]
        config: ConfigPath,
        /// Where to write the unit.
        #[arg(long, default_value = "/etc/systemd/system/tenantd.service")]
        unit: PathBuf,
        /// Replace an existing unit file.
        #[arg(long)]
        force: bool,
        /// Enable the unit but don't start it now.
        #[arg(long)]
        no_start: bool,
    },
    /// Stop and disable the unit and remove it. Sandboxes keep running.
    Uninstall {
        #[arg(long, default_value = "/etc/systemd/system/tenantd.service")]
        unit: PathBuf,
    },
}

/// Paths go into `ExecStart=` unquoted; refuse anything systemd would
/// split or expand.
fn unit_path(p: &Path) -> anyhow::Result<String> {
    let s = std::path::absolute(p)?
        .to_str()
        .with_context(|| format!("{} is not UTF-8", p.display()))?
        .to_owned();
    if s.chars()
        .any(|c| c.is_whitespace() || "\"'\\%$;".contains(c))
    {
        bail!("{s}: path can't be used in a systemd unit");
    }
    Ok(s)
}

fn render(bin: &Path, config: &Path) -> anyhow::Result<String> {
    Ok(UNIT
        .replace(UNIT_BIN, &unit_path(bin)?)
        .replace(UNIT_CONFIG, &unit_path(config)?))
}

fn unit_name(unit: &Path) -> anyhow::Result<&str> {
    unit.file_name()
        .and_then(|n| n.to_str())
        .filter(|n| n.ends_with(".service"))
        .with_context(|| format!("{}: not a .service file", unit.display()))
}

fn systemctl(args: &[&str]) -> anyhow::Result<()> {
    let st = Command::new("systemctl")
        .args(args)
        .status()
        .context("running systemctl")?;
    if !st.success() {
        bail!("systemctl {} failed: {st}", args.join(" "));
    }
    Ok(())
}

pub fn run(cmd: ServiceCmd) -> anyhow::Result<()> {
    match cmd {
        ServiceCmd::Install {
            config,
            unit,
            force,
            no_start,
        } => {
            let name = unit_name(&unit)?;
            if unit.exists() && !force {
                bail!("{} exists; pass --force to replace it", unit.display());
            }
            let exe = std::env::current_exe().context("locating this binary")?;
            let text = render(&exe, &config.config)?;
            std::fs::write(&unit, text).with_context(|| format!("writing {}", unit.display()))?;
            std::fs::set_permissions(&unit, std::fs::Permissions::from_mode(0o644))?;
            println!("wrote {}", unit.display());
            systemctl(&["daemon-reload"])?;
            if no_start {
                systemctl(&["enable", name])?;
            } else {
                systemctl(&["enable", "--now", name])?;
            }
        }
        ServiceCmd::Uninstall { unit } => {
            let name = unit_name(&unit)?;
            if !unit.exists() {
                bail!("{} is not installed", unit.display());
            }
            systemctl(&["disable", "--now", name])?;
            std::fs::remove_file(&unit).with_context(|| format!("removing {}", unit.display()))?;
            println!("removed {}", unit.display());
            systemctl(&["daemon-reload"])?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_points_at_binary_and_config() {
        let u = render(Path::new("/opt/t/tenantd"), Path::new("/srv/t.toml")).unwrap();
        assert!(
            u.contains("ExecStart=/opt/t/tenantd serve --config /srv/t.toml\n"),
            "{u}"
        );
        assert!(
            u.contains("ExecStartPre=/opt/t/tenantd config check --config /srv/t.toml\n"),
            "{u}"
        );
        assert!(!u.contains(UNIT_BIN) && !u.contains(UNIT_CONFIG), "{u}");
        assert!(render(Path::new("/opt/my bin/tenantd"), Path::new("/c.toml")).is_err());
        assert!(unit_name(Path::new("/etc/systemd/system/x.conf")).is_err());
    }
}
