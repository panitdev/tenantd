//! tenantd: one per host. Holds the root-level permissions a sandbox
//! platform needs and exposes only a fixed set of operations over a Unix
//! socket. One binary: `tenantd serve` is the daemon; the other subcommands
//! operate it.

mod api;
mod cli;
mod metrics;
mod serve;
mod service;

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon (needs root).
    Serve(serve::ServeArgs),
    /// Operator config tools.
    #[command(subcommand)]
    Config(ConfigCmd),
    #[command(flatten)]
    Client(cli::ClientCmd),
    /// Install or remove the systemd unit.
    #[command(subcommand)]
    Service(service::ServiceCmd),
    /// Print the version.
    Version,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Validate the config against this build's backends and exit.
    Check(serve::ConfigPath),
}

#[tokio::main]
async fn main() -> ExitCode {
    let res = match Cli::parse().cmd {
        Cmd::Serve(args) => return serve::main(args).await,
        Cmd::Config(ConfigCmd::Check(c)) => {
            serve::init_tracing(false);
            serve::check_config(&c.config)
        }
        Cmd::Client(c) => cli::run(c).await,
        Cmd::Service(c) => service::run(c),
        Cmd::Version => {
            println!("tenantd {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => cli::report(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("tenantd").chain(args.iter().copied()))
    }

    #[test]
    fn cli_parses() {
        Cli::command().debug_assert();
        match parse(&[
            "tenant",
            "create",
            "acme",
            "--storage",
            "10g",
            "--memory",
            "8g",
        ])
        .unwrap()
        .cmd
        {
            Cmd::Client(cli::ClientCmd::Tenant {
                cmd: cli::TenantCmd::Create { limits, .. },
                ..
            }) => assert_eq!((limits.storage, limits.memory), (10 << 30, Some(8 << 30))),
            _ => panic!(),
        }
        // --socket is accepted before or after the leaf subcommand.
        for args in [
            &["sandbox", "--socket", "/tmp/s", "list", "acme"][..],
            &["sandbox", "list", "acme", "-s", "/tmp/s"][..],
        ] {
            assert!(matches!(
                parse(args).unwrap().cmd,
                Cmd::Client(cli::ClientCmd::Sandbox { .. })
            ));
        }
        match parse(&[
            "exec",
            "acme",
            "box1",
            "-e",
            "A=1",
            "--",
            "sh",
            "-c",
            "make test",
        ])
        .unwrap()
        .cmd
        {
            Cmd::Client(cli::ClientCmd::Exec { args, .. }) => {
                assert_eq!(args.args, ["sh", "-c", "make test"]);
                assert_eq!((args.env, args.detach), (vec!["A=1".to_string()], false));
            }
            _ => panic!(),
        }
        assert!(
            parse(&["exec", "acme", "box1"]).is_err(),
            "a command is required"
        );
        for args in [
            &["process", "ps", "acme", "box1"][..],
            &[
                "process", "kill", "acme", "box1", "b1", "--signal", "SIGINT",
            ][..],
            &["process", "logs", "acme", "box1", "b1", "--stderr", "-f"][..],
            &["process", "wait", "acme", "box1", "b1"][..],
            &["process", "rm", "acme", "box1", "b1", "--force"][..],
        ] {
            assert!(
                matches!(
                    parse(args).unwrap().cmd,
                    Cmd::Client(cli::ClientCmd::Process { .. })
                ),
                "{args:?}"
            );
        }
        assert!(
            parse(&[
                "process", "kill", "acme", "box1", "b1", "--signal", "SIGSEGV"
            ])
            .is_err()
        );
        assert!(matches!(
            parse(&["serve", "-c", "examples/tenantd.toml", "--log-json"])
                .unwrap()
                .cmd,
            Cmd::Serve(_)
        ));
        assert!(matches!(
            parse(&["config", "check"]).unwrap().cmd,
            Cmd::Config(ConfigCmd::Check(_))
        ));
        // The daemon only runs when asked for.
        assert_eq!(
            parse(&[]).err().unwrap().kind(),
            clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
        assert!(parse(&["serve", "--socket", "/tmp/s"]).is_err());
    }
}
