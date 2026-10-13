//! The host image cache. Images are pulled by digest, layer digests are
//! checked, and each layer is unpacked once into `<cache>/layers/<hex>/`,
//! shared read-only by all tenants. Manifests are recorded in
//! `<cache>/manifests/<hex>.json`.

mod unpack;

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenantd_core::backend::{GcReport, ImageStore};
use tenantd_core::error::Context;
use tenantd_core::model::{ImageConfig, ResolvedImage};
use tenantd_core::{Error, Result};
use tracing::info;

pub use unpack::unpack_layer;

#[derive(Debug, Serialize, Deserialize)]
struct ManifestRecord {
    digest: String,
    reference: String,
    /// Layer digest hex, base first.
    layers: Vec<String>,
    config: ImageConfig,
}

pub struct OciImageStore {
    cache: PathBuf,
    client: Client,
    locks: std::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
}

fn hex_of(digest: &str) -> Result<&str> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| Error::Internal(format!("unsupported digest {digest}")))?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::Internal(format!("malformed digest {digest}")));
    }
    Ok(hex)
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::internal("image task", e))?
}

fn sha256_file(p: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

fn parse_image_config(raw: &str) -> Result<ImageConfig> {
    #[derive(Deserialize, Default)]
    #[serde(rename_all = "PascalCase", default)]
    struct Inner {
        entrypoint: Option<Vec<String>>,
        cmd: Option<Vec<String>>,
        env: Option<Vec<String>>,
        working_dir: Option<String>,
        user: Option<String>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Outer {
        config: Option<Inner>,
    }
    let o: Outer = serde_json::from_str(raw).context("parsing image config")?;
    let c = o.config.unwrap_or_default();
    Ok(ImageConfig {
        entrypoint: c.entrypoint.unwrap_or_default(),
        cmd: c.cmd.unwrap_or_default(),
        env: c.env.unwrap_or_default(),
        working_dir: c.working_dir.filter(|s| !s.is_empty()),
        user: c.user.filter(|s| !s.is_empty()),
    })
}

impl OciImageStore {
    pub fn new(cache: impl Into<PathBuf>, insecure_registries: Vec<String>) -> Self {
        let protocol = if insecure_registries.is_empty() {
            ClientProtocol::Https
        } else {
            ClientProtocol::HttpsExcept(insecure_registries)
        };
        Self {
            cache: cache.into(),
            client: Client::new(ClientConfig {
                protocol,
                ..Default::default()
            }),
            locks: Default::default(),
        }
    }

    fn layers_dir(&self) -> PathBuf {
        self.cache.join("layers")
    }

    fn manifests_dir(&self) -> PathBuf {
        self.cache.join("manifests")
    }

    fn lock(&self, k: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.locks
            .lock()
            .unwrap()
            .entry(k.to_string())
            .or_default()
            .clone()
    }

    fn resolved(&self, m: ManifestRecord, reference: &str) -> ResolvedImage {
        ResolvedImage {
            reference: reference.to_string(),
            digest: m.digest,
            layers: m.layers.iter().map(|h| self.layers_dir().join(h)).collect(),
            config: m.config,
        }
    }

    async fn load_manifest(&self, digest: &str) -> Result<Option<ManifestRecord>> {
        let p = self
            .manifests_dir()
            .join(format!("{}.json", hex_of(digest)?));
        match tokio::fs::read(&p).await {
            Ok(b) => Ok(Some(
                serde_json::from_slice(&b).context("reading manifest record")?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn ensure_layer(
        &self,
        r: &Reference,
        desc: &oci_client::manifest::OciDescriptor,
    ) -> Result<String> {
        let hex = hex_of(&desc.digest)?.to_string();
        let lock = self.lock(&hex);
        let _g = lock.lock().await;
        let final_dir = self.layers_dir().join(&hex);
        if tokio::fs::try_exists(&final_dir).await? {
            return Ok(hex);
        }
        tokio::fs::create_dir_all(self.layers_dir()).await?;
        let blob = self.layers_dir().join(format!(".tmp-{hex}.blob"));
        let tmp = self.layers_dir().join(format!(".tmp-{hex}"));
        let file = tokio::fs::File::create(&blob).await?;
        self.client
            .pull_blob(r, desc, file)
            .await
            .context(format!("pulling layer {}", desc.digest))?;

        let (blob2, tmp2, final2, want) =
            (blob.clone(), tmp.clone(), final_dir.clone(), hex.clone());
        let res = blocking(move || {
            let got = sha256_file(&blob2)?;
            if got != want {
                return Err(Error::Internal(format!(
                    "layer digest mismatch: want {want}, got {got}"
                )));
            }
            let _ = std::fs::remove_dir_all(&tmp2);
            unpack_layer(&blob2, &tmp2).context("unpacking layer")?;
            std::fs::rename(&tmp2, &final2)?;
            Ok(())
        })
        .await;
        let _ = tokio::fs::remove_file(&blob).await;
        if res.is_err() {
            let _ = tokio::fs::remove_dir_all(&tmp).await;
        }
        res?;
        info!(layer = %desc.digest, "layer unpacked");
        Ok(hex)
    }
}

#[async_trait]
impl ImageStore for OciImageStore {
    async fn resolve(&self, reference: &str) -> Result<ResolvedImage> {
        {
            use std::os::unix::fs::DirBuilderExt;
            // Root-only: image layers are shared by every tenant.
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.cache)?;
        }
        let r: Reference = reference
            .parse()
            .map_err(|e| Error::invalid(format!("image {reference}: {e}")))?;
        // A digest reference already in the cache needs no network.
        if let Some(d) = r.digest()
            && let Some(m) = self.load_manifest(d).await?
        {
            return Ok(self.resolved(m, reference));
        }
        let (manifest, digest, config) = self
            .client
            .pull_manifest_and_config(&r, &RegistryAuth::Anonymous)
            .await
            .map_err(|e| Error::FailedPrecondition(format!("pulling {reference}: {e}")))?;
        if let Some(d) = r.digest()
            && d != digest
        {
            return Err(Error::Internal(format!(
                "registry returned {digest} for {reference}"
            )));
        }
        if let Some(m) = self.load_manifest(&digest).await? {
            return Ok(self.resolved(m, reference));
        }
        let lock = self.lock(&digest);
        let _g = lock.lock().await;
        let mut layers = Vec::with_capacity(manifest.layers.len());
        for l in &manifest.layers {
            layers.push(self.ensure_layer(&r, l).await?);
        }
        let rec = ManifestRecord {
            digest: digest.clone(),
            reference: reference.to_string(),
            layers,
            config: parse_image_config(&config)?,
        };
        let dir = self.manifests_dir();
        tokio::fs::create_dir_all(&dir).await?;
        let hex = hex_of(&digest)?;
        let tmp = dir.join(format!(".tmp-{hex}.json"));
        tokio::fs::write(
            &tmp,
            serde_json::to_vec_pretty(&rec).context("encoding manifest")?,
        )
        .await?;
        tokio::fs::rename(&tmp, dir.join(format!("{hex}.json"))).await?;
        info!(image = reference, %digest, "image cached");
        Ok(self.resolved(rec, reference))
    }

    async fn gc(&self, in_use: &HashSet<String>) -> Result<GcReport> {
        let (manifests, layers) = (self.manifests_dir(), self.layers_dir());
        let in_use = in_use.clone();
        blocking(move || {
            let mut rep = GcReport::default();
            let mut keep_layers = HashSet::new();
            if let Ok(entries) = std::fs::read_dir(&manifests) {
                for e in entries {
                    let p = e?.path();
                    let name = p
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned();
                    if name.starts_with(".tmp-") {
                        std::fs::remove_file(&p)?;
                        continue;
                    }
                    let rec: ManifestRecord =
                        match std::fs::read(&p).map(|b| serde_json::from_slice(&b)) {
                            Ok(Ok(r)) => r,
                            _ => {
                                std::fs::remove_file(&p)?;
                                continue;
                            }
                        };
                    if in_use.contains(&rec.digest) {
                        keep_layers.extend(rec.layers);
                    } else {
                        std::fs::remove_file(&p)?;
                        rep.images.push(rec.digest);
                    }
                }
            }
            if let Ok(entries) = std::fs::read_dir(&layers) {
                for e in entries {
                    let p = e?.path();
                    let name = p
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned();
                    if keep_layers.contains(&name) {
                        continue;
                    }
                    if p.is_dir() {
                        std::fs::remove_dir_all(&p)?
                    } else {
                        std::fs::remove_file(&p)?
                    }
                    if !name.starts_with(".tmp-") {
                        rep.layers.push(format!("sha256:{name}"));
                    }
                }
            }
            Ok(rep)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_config() {
        let c = parse_image_config(
            r#"{"architecture":"amd64","config":{"Env":["PATH=/bin"],"Cmd":["sh"],"WorkingDir":"","User":"1000:1000"}}"#,
        )
        .unwrap();
        assert_eq!(c.cmd, vec!["sh"]);
        assert_eq!(c.working_dir, None);
        assert_eq!(c.user.as_deref(), Some("1000:1000"));
        assert_eq!(parse_image_config("{}").unwrap(), ImageConfig::default());
    }

    #[tokio::test]
    async fn gc_keeps_referenced_layers() {
        let d = tempfile::tempdir().unwrap();
        let s = OciImageStore::new(d.path(), vec![]);
        let (a, b, shared) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        std::fs::create_dir_all(s.manifests_dir()).unwrap();
        for l in [&a, &b, &shared] {
            std::fs::create_dir_all(s.layers_dir().join(l)).unwrap();
        }
        std::fs::create_dir_all(s.layers_dir().join(".tmp-dead")).unwrap();
        let rec = |digest: &str, layers: Vec<String>| ManifestRecord {
            digest: digest.into(),
            reference: "r".into(),
            layers,
            config: ImageConfig::default(),
        };
        let (d1, d2) = (
            format!("sha256:{}", "1".repeat(64)),
            format!("sha256:{}", "2".repeat(64)),
        );
        for r in [
            rec(&d1, vec![shared.clone(), a.clone()]),
            rec(&d2, vec![shared.clone(), b.clone()]),
        ] {
            let p = s
                .manifests_dir()
                .join(format!("{}.json", hex_of(&r.digest).unwrap()));
            std::fs::write(p, serde_json::to_vec(&r).unwrap()).unwrap();
        }
        let rep = s.gc(&HashSet::from([d1.clone()])).await.unwrap();
        assert_eq!(rep.images, vec![d2]);
        assert_eq!(rep.layers, vec![format!("sha256:{b}")]);
        assert!(s.layers_dir().join(&a).exists() && s.layers_dir().join(&shared).exists());
        assert!(!s.layers_dir().join(".tmp-dead").exists());
        assert_eq!(
            s.resolve(&format!("ghcr.io/x/y@{d1}"))
                .await
                .unwrap()
                .layers
                .len(),
            2
        );
    }

    /// Pulls from Docker Hub: `cargo test -p tenantd-image -- --ignored`
    #[tokio::test]
    #[ignore]
    async fn pulls_a_real_image() {
        let d = tempfile::tempdir().unwrap();
        let s = OciImageStore::new(d.path(), vec![]);
        let img = s.resolve("docker.io/library/busybox:latest").await.unwrap();
        assert!(img.digest.starts_with("sha256:"));
        assert!(img.layers[0].join("bin/busybox").exists());
        let again = s
            .resolve(&format!("docker.io/library/busybox@{}", img.digest))
            .await
            .unwrap();
        assert_eq!(again.layers, img.layers);
    }
}
