//! `tenantd file`: file access to a running container's root.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use tenantd_client::files::{self, Files, WriteOptions};
use tenantd_client::pb;
use tokio::io::AsyncWriteExt;
use tonic::transport::Channel;

use super::octal;

#[derive(Args)]
pub struct FileArgs {
    /// Act as this user, one of the profile's exec.users; default: the
    /// image's user.
    #[arg(long, short, global = true, default_value = "")]
    user: String,
    #[command(subcommand)]
    cmd: FileCmd,
}

/// The container a file command works in.
#[derive(Args)]
struct Target {
    tenant: String,
    sandbox: String,
    container: String,
}

#[derive(Subcommand)]
enum FileCmd {
    /// Kind, mode, size, owner and path of a file (lstat; --follow: stat).
    Stat {
        #[command(flatten)]
        at: Target,
        path: String,
        /// Follow a final symlink; prints the resolved path.
        #[arg(long, short = 'L')]
        follow: bool,
    },
    /// A directory's entries.
    Ls {
        #[command(flatten)]
        at: Target,
        path: String,
    },
    /// Write a file's bytes to stdout.
    Cat {
        #[command(flatten)]
        at: Target,
        path: String,
        #[arg(long, default_value_t = 0)]
        offset: u64,
        /// Bytes to read; 0 reads to the end.
        #[arg(long, default_value_t = 0)]
        length: u64,
    },
    /// Replace (or create) a file with stdin (or --from), atomically: an
    /// interrupted put leaves the file as it was.
    Put {
        #[command(flatten)]
        at: Target,
        path: String,
        /// Read the body from this host file instead of stdin.
        #[arg(long)]
        from: Option<PathBuf>,
        /// Octal mode; default: the replaced file's, or 0644.
        #[arg(long, value_parser = octal)]
        mode: Option<u32>,
        /// Create missing parent directories.
        #[arg(long, short)]
        parents: bool,
        /// Fail if the file exists.
        #[arg(long)]
        exclusive: bool,
    },
    /// Rename a file or directory.
    Mv {
        #[command(flatten)]
        at: Target,
        from: String,
        to: String,
        /// Fail if the target exists.
        #[arg(long, conflicts_with = "exchange")]
        no_replace: bool,
        /// Swap the two, which must both exist.
        #[arg(long)]
        exchange: bool,
    },
    /// Remove a file, or an empty directory with --dir.
    Rm {
        #[command(flatten)]
        at: Target,
        path: String,
        #[arg(long, short)]
        dir: bool,
    },
}

fn kind(a: &pb::FileAttr) -> &'static str {
    match a.kind() {
        pb::FileKind::File => "file",
        pb::FileKind::Directory => "dir",
        pb::FileKind::Symlink => "link",
        pb::FileKind::Fifo => "fifo",
        pb::FileKind::Socket => "socket",
        pb::FileKind::CharDevice => "chr",
        pb::FileKind::BlockDevice => "blk",
        pb::FileKind::Unspecified => "?",
    }
}

fn print_attr(a: &pb::FileAttr, name: &str) {
    println!(
        "{:<6} {:04o} {:>12} {}:{} {name}",
        kind(a),
        a.mode,
        a.size,
        a.uid,
        a.gid
    );
}

impl Target {
    fn files(self, ch: Channel, user: &str) -> Files {
        Files::new(
            ch,
            pb::ContainerRef {
                tenant: self.tenant,
                sandbox: self.sandbox,
                id: self.container,
            },
        )
        .as_user(user)
    }
}

pub async fn run(ch: Channel, args: FileArgs) -> anyhow::Result<()> {
    let user = args.user;
    match args.cmd {
        FileCmd::Stat { at, path, follow } => {
            let st = at.files(ch, &user).stat(path, follow).await?;
            print_attr(&st.attr, &st.path);
        }
        FileCmd::Ls { at, path } => {
            for e in at.files(ch, &user).read_dir(path).await? {
                print_attr(&e.attr.unwrap_or_default(), &e.name);
            }
        }
        FileCmd::Cat {
            at,
            path,
            offset,
            length,
        } => {
            let mut r = at.files(ch, &user).read_range(path, offset, length).await?;
            let mut out = tokio::io::stdout();
            while let Some((_, d)) = r.chunk().await? {
                out.write_all(&d).await?;
            }
            out.flush().await?;
        }
        FileCmd::Put {
            at,
            path,
            from,
            mode,
            parents,
            exclusive,
        } => {
            let mut opts = WriteOptions {
                mode,
                parents,
                exclusive,
                size: None,
            };
            let mut f = at.files(ch, &user);
            let a = match from {
                Some(p) => {
                    let file = tokio::fs::File::open(&p).await?;
                    // A file that shrinks while it is read fails the put
                    // rather than writing a cut-off copy.
                    opts.size = Some(file.metadata().await?.len());
                    f.write_from(path, file, &opts).await?
                }
                None => f.write_from(path, tokio::io::stdin(), &opts).await?,
            };
            eprintln!("wrote {} bytes", a.size);
        }
        FileCmd::Mv {
            at,
            from,
            to,
            no_replace,
            exchange,
        } => {
            let flags = if exchange {
                files::RENAME_EXCHANGE
            } else if no_replace {
                files::RENAME_NOREPLACE
            } else {
                0
            };
            at.files(ch, &user).rename(from, to, flags).await?;
        }
        FileCmd::Rm { at, path, dir } => {
            let mut f = at.files(ch, &user);
            if dir {
                f.remove_dir(path).await?
            } else {
                f.remove(path).await?
            }
        }
    }
    Ok(())
}
