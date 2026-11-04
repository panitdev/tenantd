//! Network mode: the API over TCP with mutual TLS (`[server.tls]`).
//!
//! A client must present a certificate that chains to `client_ca` and whose
//! subjectAltName is one of `clients`. Both are checked during the
//! handshake, so a refused peer never reaches the gRPC server. Sessions are
//! never resumed: every connection is verified against the current
//! allowlist, which SIGHUP reloads together with the certificate files.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Context as _;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{NoServerSessionStorage, ParsedCertificate, WebPkiClientVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use tenantd_client::tls::{read_certs, read_key};
use tenantd_core::config::TlsListener;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::{Semaphore, mpsc};
use tonic::transport::server::Connected;
use tracing::{info, warn};

/// A handshake that hasn't finished by then is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Handshakes in flight; further TCP connections wait in the accept queue.
const MAX_HANDSHAKES: usize = 128;

/// Build the rustls server config for `[server.tls]`: reads every file now,
/// so a bad path or key fails here and not on the first connection.
pub fn server_config(t: &TlsListener) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let cert = read_certs(&t.cert).context("server.tls.cert")?;
    let key = read_key(&t.key).context("server.tls.key")?;
    let mut roots = rustls::RootCertStore::empty();
    for ca in read_certs(&t.client_ca).context("server.tls.client_ca")? {
        roots.add(ca).context("server.tls.client_ca")?;
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let chain = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .context("server.tls.client_ca")?;
    let names = t
        .clients
        .iter()
        .map(|n| ServerName::try_from(n.clone()).context("server.tls.clients"))
        .collect::<anyhow::Result<_>>()?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(AllowedClients { chain, names }))
        .with_single_cert(cert, key)
        .context("server.tls.cert and server.tls.key")?;
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    // A resumed session skips client verification; never resume, so an
    // allowlist reload applies to every new connection.
    cfg.session_storage = Arc::new(NoServerSessionStorage {});
    cfg.send_tls13_tickets = 0;
    Ok(Arc::new(cfg))
}

/// The CA chain check, then the allowlist on the leaf's subjectAltName.
#[derive(Debug)]
struct AllowedClients {
    chain: Arc<dyn ClientCertVerifier>,
    names: Vec<ServerName<'static>>,
}

impl ClientCertVerifier for AllowedClients {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.chain.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let ok = self
            .chain
            .verify_client_cert(end_entity, intermediates, now)
            .inspect_err(|e| warn!(error = %e, "refused TLS client: certificate not trusted"))?;
        let leaf = ParsedCertificate::try_from(end_entity)?;
        if self
            .names
            .iter()
            .any(|n| rustls::client::verify_server_name(&leaf, n).is_ok())
        {
            Ok(ok)
        } else {
            warn!("refused TLS client: certificate names no listed server.tls.clients entry");
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.chain.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.chain.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.chain.supported_verify_schemes()
    }
}

/// The TCP listener plus the config it serves, swappable on reload.
pub struct NetListener {
    pub tcp: TcpListener,
    pub tls: Arc<TlsReload>,
}

/// The `[server.tls]` a listener was bound for and its current rustls config.
pub struct TlsReload {
    bound: TlsListener,
    current: RwLock<Arc<rustls::ServerConfig>>,
}

impl TlsReload {
    pub fn new(t: &TlsListener) -> anyhow::Result<Self> {
        Ok(Self {
            bound: t.clone(),
            current: RwLock::new(server_config(t)?),
        })
    }

    /// Re-read certificates, key, CA and allowlist. A changed `listen`, or
    /// removing `[server.tls]`, needs a restart; the old listener keeps going.
    pub fn reload(&self, new: Option<&TlsListener>) -> anyhow::Result<()> {
        let Some(new) = new else {
            anyhow::bail!("server.tls was removed; restart tenantd to stop listening");
        };
        if new.listen != self.bound.listen {
            anyhow::bail!(
                "server.tls.listen changed to {}; restart tenantd to move from {}",
                new.listen,
                self.bound.listen
            );
        }
        *self.current.write().unwrap() = server_config(new)?;
        info!(listen = %new.listen, clients = ?new.clients, "TLS config reloaded");
        Ok(())
    }

    fn acceptor(&self) -> tokio_rustls::TlsAcceptor {
        tokio_rustls::TlsAcceptor::from(self.current.read().unwrap().clone())
    }
}

/// One accepted, authorized API connection.
pub enum Conn {
    Unix(UnixStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
}

impl Connected for Conn {
    type ConnectInfo = ();

    fn connect_info(&self) {}
}

macro_rules! delegate {
    ($self:ident, $s:ident => $e:expr) => {
        match $self.get_mut() {
            Conn::Unix($s) => {
                let $s = Pin::new($s);
                $e
            }
            Conn::Tls($s) => {
                let $s = Pin::new($s.as_mut());
                $e
            }
        }
    };
}

impl AsyncRead for Conn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        delegate!(self, s => s.poll_read(cx, buf))
    }
}

impl AsyncWrite for Conn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        delegate!(self, s => s.poll_write(cx, b))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        delegate!(self, s => s.poll_write_vectored(cx, b))
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Unix(s) => s.is_write_vectored(),
            Self::Tls(s) => s.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        delegate!(self, s => s.poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        delegate!(self, s => s.poll_shutdown(cx))
    }
}

/// Accept TCP connections and hand finished handshakes to `tx`. Each
/// handshake runs in its own task, so a slow or silent peer holds one
/// permit, not the accept loop.
pub async fn accept_tls(l: NetListener, tx: mpsc::Sender<io::Result<Conn>>) {
    let permits = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    loop {
        let permit = tokio::select! {
            _ = tx.closed() => return,
            p = permits.clone().acquire_owned() => p.expect("never closed"),
        };
        let (tcp, peer) = tokio::select! {
            _ = tx.closed() => return,
            r = l.tcp.accept() => match r {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "TLS accept failed");
                    // EMFILE and friends: don't spin.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let (acceptor, tx) = (l.tls.acceptor(), tx.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tcp.set_nodelay(true);
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(s)) => {
                    let _ = tx.send(Ok(Conn::Tls(Box::new(s)))).await;
                }
                Ok(Err(e)) => warn!(%peer, error = %e, "refused TLS connection"),
                Err(_) => warn!(%peer, "refused TLS connection: handshake timed out"),
            }
        });
    }
}
