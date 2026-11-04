//! Network mode: connect to tenantd's `[server.tls]` listener over TCP with
//! mutual TLS.
//!
//! ```no_run
//! # async fn f() -> Result<(), Box<dyn std::error::Error>> {
//! use tenantd_client::tls::ClientTls;
//! let tls = ClientTls::from_pem_files("ca.pem", "client.pem", "client.key")?;
//! let ch = tenantd_client::tls::connect("tenantd-1.internal:7443", None, &tls).await?;
//! let mut system = tenantd_client::SystemClient::new(ch);
//! # Ok(()) }
//! ```

use std::io;
use std::path::Path;
use std::sync::Arc;

use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tonic::transport::{Channel, Endpoint, Uri};

/// The client half of mTLS: which CA to trust for the server, and the
/// certificate the client presents.
#[derive(Clone)]
pub struct ClientTls {
    config: Arc<rustls::ClientConfig>,
}

impl ClientTls {
    /// `ca`: PEM CA certificates the server's certificate must chain to.
    /// `cert`: PEM client certificate chain, leaf first. `key`: its PEM
    /// private key.
    pub fn from_pem_files(
        ca: impl AsRef<Path>,
        cert: impl AsRef<Path>,
        key: impl AsRef<Path>,
    ) -> io::Result<Self> {
        let ca = read_certs(ca.as_ref())?;
        let cert = read_certs(cert.as_ref())?;
        let key = read_key(key.as_ref())?;
        Self::new(ca, cert, key)
    }

    pub fn new(
        ca: Vec<CertificateDer<'static>>,
        cert: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> io::Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        for c in ca {
            roots.add(c).map_err(invalid)?;
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(invalid)?
            .with_root_certificates(roots)
            .with_client_auth_cert(cert, key)
            .map_err(invalid)?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Self {
            config: Arc::new(config),
        })
    }
}

/// Connect to `addr` (`host:port`). The server's certificate must name
/// `server_name`, or the host part of `addr` when it is `None`.
pub async fn connect(
    addr: &str,
    server_name: Option<&str>,
    tls: &ClientTls,
) -> Result<Channel, tonic::transport::Error> {
    // The URI only carries the authority for the connector and :authority.
    let endpoint = Endpoint::from_shared(format!("http://{addr}"))?;
    let host = endpoint.uri().host().unwrap_or_default();
    let name = server_name
        .unwrap_or_else(|| host.trim_start_matches('[').trim_end_matches(']'))
        .to_owned();
    let connector = tokio_rustls::TlsConnector::from(tls.config.clone());
    let addr = addr.to_owned();
    endpoint
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let (connector, addr, name) = (connector.clone(), addr.clone(), name.clone());
            async move {
                let name = ServerName::try_from(name).map_err(invalid)?;
                let tcp = tokio::net::TcpStream::connect(&addr).await?;
                tcp.set_nodelay(true)?;
                Ok::<_, io::Error>(TokioIo::new(connector.connect(name, tcp).await?))
            }
        }))
        .await
}

/// Every certificate in a PEM file, in order; at least one.
pub fn read_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .and_then(|i| i.collect::<Result<Vec<_>, _>>())
        .map_err(|e| pem_error(path, e))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: no PEM certificates", path.display()),
        ));
    }
    Ok(certs)
}

/// The first private key in a PEM file (PKCS#8, PKCS#1 or SEC1).
pub fn read_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).map_err(|e| pem_error(path, e))
}

fn pem_error(path: &Path, e: rustls::pki_types::pem::Error) -> io::Error {
    match e {
        rustls::pki_types::pem::Error::Io(e) => {
            io::Error::new(e.kind(), format!("{}: {e}", path.display()))
        }
        e => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: {e}", path.display()),
        ),
    }
}

fn invalid(e: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e)
}
