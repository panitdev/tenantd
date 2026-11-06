//! The file helper: tenantd's own binary, bound into every container at
//! [`HELPER_PATH`] and exec'd there as the caller's user to serve one Files
//! call on the container's `/`.
//!
//! The protocol, over its stdin and stdout, is length-delimited protobuf:
//! tenantd sends one [`Call`], then for a write the body as
//! `FileWriteRequest` data messages and an empty `FileWriteRequest` to
//! commit. The helper answers with the call's response message (a read:
//! its stream of `FileReadResponse`) and exits 0. Its stdin ending before
//! the commit abandons the write, leaving the target as it was.
//!
//! [`HELPER_PATH`]: tenantd_core::files::HELPER_PATH

use std::io::{self, BufReader, BufWriter, Read, Write};
use std::process::ExitCode;

use prost::Message;
use tenantd_client::pb::{self, file_write_request::Msg};
use tenantd_layer::files::Root;

use crate::files_api::ops;

/// Largest message either side takes: a client's `data` up to gRPC's
/// default limit, and some.
pub const MAX_MESSAGE: usize = 8 << 20;

/// One Files call, the helper's first message.
#[derive(Clone, PartialEq, Message)]
pub struct HelperCall {
    #[prost(oneof = "Call", tags = "1, 2, 3, 4, 5, 6")]
    pub call: Option<Call>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum Call {
    #[prost(message, tag = "1")]
    Stat(pb::FileStatRequest),
    #[prost(message, tag = "2")]
    ReadDir(pb::FileReadDirRequest),
    #[prost(message, tag = "3")]
    Read(pb::FileReadRequest),
    #[prost(message, tag = "4")]
    Write(pb::FileWriteHeader),
    #[prost(message, tag = "5")]
    Rename(pb::FileRenameRequest),
    #[prost(message, tag = "6")]
    Remove(pb::FileRemoveRequest),
}

/// Whether this process was started as the helper.
pub fn is_helper() -> bool {
    let name = std::path::Path::new(tenantd_core::files::HELPER_PATH).file_name();
    std::env::args_os()
        .next()
        .is_some_and(|a| std::path::Path::new(&a).file_name() == name)
}

/// The next message, `None` at a clean end of input.
pub fn read_msg<M: Message + Default>(r: &mut impl Read) -> io::Result<Option<M>> {
    let mut len: u64 = 0;
    for i in 0..10 {
        let mut b = [0u8; 1];
        if r.read(&mut b)? == 0 {
            if i == 0 {
                return Ok(None);
            }
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        len |= u64::from(b[0] & 0x7f) << (7 * i);
        if b[0] & 0x80 == 0 {
            if len as usize > MAX_MESSAGE {
                return Err(io::Error::other(format!("a {len}-byte message")));
            }
            let mut buf = vec![0u8; len as usize];
            r.read_exact(&mut buf)?;
            return M::decode(buf.as_slice())
                .map(Some)
                .map_err(io::Error::other);
        }
    }
    Err(io::Error::other("bad message length"))
}

pub fn write_msg(w: &mut impl Write, m: &impl Message) -> io::Result<()> {
    w.write_all(&m.encode_length_delimited_to_vec())
}

/// Serve one call from `input` to `output` on `root`.
pub fn serve(root: &Root, input: &mut impl Read, output: &mut impl Write) -> io::Result<()> {
    let call = read_msg::<HelperCall>(input)?
        .and_then(|c| c.call)
        .ok_or_else(|| io::Error::other("no call"))?;
    // Inside the container nothing is out of view, so `not_served` never
    // comes up; `served` only unwraps.
    match call {
        Call::Stat(r) => write_msg(output, &ops::served(ops::stat(root, &r))?),
        Call::ReadDir(r) => write_msg(output, &ops::served(ops::read_dir(root, &r))?),
        Call::Rename(r) => write_msg(output, &ops::served(ops::rename(root, &r))?),
        Call::Remove(r) => write_msg(output, &ops::served(ops::remove(root, &r))?),
        Call::Read(r) => {
            let mut res = Ok(());
            let opened = ops::served(ops::open_read(root, &r.path))?;
            ops::read(opened, r.offset, r.length, |m| {
                res = write_msg(output, &m).and_then(|_| output.flush());
                res.is_ok()
            });
            res
        }
        Call::Write(h) => {
            let mut body = match ops::served(ops::begin_write(root, &h))? {
                Ok(b) => b,
                Err(e) => return write_msg(output, &ops::write_reply(Err(e))),
            };
            loop {
                match read_msg::<pb::FileWriteRequest>(input)? {
                    Some(pb::FileWriteRequest {
                        msg: Some(Msg::Data(d)),
                    }) => {
                        if let Err(e) = body.push(&d) {
                            return write_msg(output, &ops::write_reply(Err(e)));
                        }
                    }
                    Some(pb::FileWriteRequest { msg: None }) => {
                        return write_msg(output, &ops::write_reply(body.finish()));
                    }
                    Some(_) => return Err(io::Error::other("a second header")),
                    // Abandoned: dropping the body removes its file.
                    None => return Err(io::Error::other("the body ended without a commit")),
                }
            }
        }
    }
}

/// The helper's `main`.
pub fn main() -> ExitCode {
    let root = match Root::inside() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tenantd file helper: {e}");
            return ExitCode::from(1);
        }
    };
    let mut input = BufReader::new(io::stdin().lock());
    let mut output = BufWriter::new(io::stdout().lock());
    match serve(&root, &mut input, &mut output).and_then(|_| output.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("tenantd file helper: {e}");
            ExitCode::from(1)
        }
    }
}
