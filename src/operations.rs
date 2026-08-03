use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{AcmeConfig, CertificateMode, CloudflareEndpoints, Config};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileConfig {
    pub state_dir: PathBuf,
    pub admin_listen: SocketAddr,
    pub http_listen: SocketAddr,
    pub https_listen: SocketAddr,
    pub public_ips: Vec<IpAddr>,
    pub admin_public_url: url::Url,
    #[serde(default = "default_drain_seconds")]
    pub drain_seconds: u64,
    #[serde(default = "default_acme_directory_url")]
    pub acme_directory_url: String,
    #[serde(default)]
    pub acme_root_certificate: Option<PathBuf>,
}

impl FileConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read configuration {}", path.display()))?;
        toml::from_str(&contents).with_context(|| format!("parse configuration {}", path.display()))
    }

    pub fn runtime(self) -> Config {
        Config {
            state_dir: self.state_dir,
            admin_listen: self.admin_listen,
            secure_admin_cookies: true,
            admin_public_url: Some(self.admin_public_url),
            cloudflare_endpoints: CloudflareEndpoints::default(),
            http_listen: self.http_listen,
            https_listen: self.https_listen,
            public_ips: self.public_ips,
            drain_duration: std::time::Duration::from_secs(self.drain_seconds),
            certificate_mode: CertificateMode::Acme(AcmeConfig {
                directory_url: self.acme_directory_url,
                root_certificate: self.acme_root_certificate,
            }),
            admin_tls: true,
            clock: crate::Clock::system(),
            renewal_check_interval: std::time::Duration::from_secs(15 * 60),
        }
    }
}

pub struct InstallOptions<'a> {
    pub root: &'a Path,
    pub binary: &'a Path,
    pub public_ips: &'a [IpAddr],
}

pub fn install_systemd(options: InstallOptions<'_>) -> Result<()> {
    if options.public_ips.is_empty() {
        bail!("at least one --public-ip is required");
    }
    if !options.binary.is_file() {
        bail!("binary does not exist: {}", options.binary.display());
    }
    let binary_path = rooted(options.root, "usr/local/bin/hostknot");
    let config_path = rooted(options.root, "etc/hostknot/config.toml");
    let state_dir = rooted(options.root, "var/lib/hostknot");
    let unit_path = rooted(options.root, "etc/systemd/system/hostknot.service");
    for directory in [
        binary_path.parent(),
        config_path.parent(),
        unit_path.parent(),
    ]
    .into_iter()
    .flatten()
    {
        fs::create_dir_all(directory)?;
    }

    let same_binary = binary_path.exists()
        && fs::canonicalize(options.binary).ok() == fs::canonicalize(&binary_path).ok();
    if !same_binary {
        fs::copy(options.binary, &binary_path).with_context(|| {
            format!(
                "install {} as {}",
                options.binary.display(),
                binary_path.display()
            )
        })?;
    }
    set_mode(&binary_path, 0o755)?;
    // The state directory and master key are deliberately NOT created here:
    // the unit runs with DynamicUser + StateDirectory, so systemd owns the
    // directory and the service generates the key under its own UID. A
    // root-owned pre-created key would make the service crash-loop on EACCES.

    if !config_path.exists() {
        let primary_ip = options.public_ips[0];
        let admin_host = match primary_ip {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        };
        let config = FileConfig {
            state_dir: state_dir.clone(),
            admin_listen: "0.0.0.0:9443".parse().unwrap(),
            http_listen: "0.0.0.0:80".parse().unwrap(),
            https_listen: "0.0.0.0:443".parse().unwrap(),
            public_ips: options.public_ips.to_vec(),
            admin_public_url: url::Url::parse(&format!("https://{admin_host}:9443/"))?,
            drain_seconds: 300,
            acme_directory_url: default_acme_directory_url(),
            acme_root_certificate: None,
        };
        fs::write(&config_path, toml::to_string_pretty(&config)?)?;
        set_mode(&config_path, 0o644)?;
    }
    fs::write(&unit_path, SYSTEMD_UNIT)?;
    set_mode(&unit_path, 0o644)?;
    Ok(())
}

pub struct DoctorReport {
    pub checks: Vec<String>,
    pub ready: bool,
}

/// Collects every finding instead of aborting at the first problem, so one run
/// gives the operator the complete picture.
pub async fn doctor(config_path: &Path, offline: bool) -> Result<DoctorReport> {
    let config = FileConfig::load(config_path)?;
    let mut checks = Vec::new();
    let mut failures = 0_usize;
    let fail = |checks: &mut Vec<String>, failures: &mut usize, message: String| {
        checks.push(format!("[fail] {message}"));
        *failures += 1;
    };

    if config.public_ips.is_empty() {
        fail(
            &mut checks,
            &mut failures,
            "configuration has no public IP addresses".to_owned(),
        );
    }
    let local_addresses: Vec<IpAddr> = get_if_addrs::get_if_addrs()
        .map(|interfaces| {
            interfaces
                .into_iter()
                .map(|interface| interface.ip())
                .collect()
        })
        .unwrap_or_default();
    for address in &config.public_ips {
        let routable = match address {
            IpAddr::V4(ip) => {
                !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified())
            }
            IpAddr::V6(ip) => !(ip.is_loopback() || ip.is_unspecified()),
        };
        if !routable {
            checks.push(format!(
                "[warn] public IP {address} is not publicly routable; ACME issuance and DNS records will not work"
            ));
        } else if !local_addresses.is_empty() && !local_addresses.contains(address) {
            checks.push(format!(
                "[warn] public IP {address} is not assigned to a local interface (expected only behind NAT)"
            ));
        } else {
            checks.push(format!("[ok] public IP: {address}"));
        }
    }

    match fs::metadata(&config.state_dir) {
        Ok(metadata) if metadata.is_dir() => {
            checks.push(format!(
                "[ok] state directory: {}",
                config.state_dir.display()
            ));
            let master_key = config.state_dir.join("master.key");
            match fs::metadata(&master_key) {
                Ok(key_metadata) => {
                    let mut key_ok = true;
                    if key_metadata.len() != 32 {
                        fail(
                            &mut checks,
                            &mut failures,
                            "master key must contain exactly 32 bytes".to_owned(),
                        );
                        key_ok = false;
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if key_metadata.permissions().mode() & 0o077 != 0 {
                            fail(
                                &mut checks,
                                &mut failures,
                                "master key permissions must be 0600".to_owned(),
                            );
                            key_ok = false;
                        }
                    }
                    if key_ok {
                        checks.push("[ok] encrypted master key".to_owned());
                    }
                }
                Err(_) => {
                    checks.push("[info] master key will be generated on first start".to_owned())
                }
            }
            let database = config.state_dir.join("hostknot.sqlite3");
            if database.exists() {
                match rusqlite::Connection::open(&database).and_then(|connection| {
                    connection
                        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                }) {
                    Ok(integrity) if integrity == "ok" => {
                        checks.push("[ok] state database integrity".to_owned());
                    }
                    Ok(integrity) => fail(
                        &mut checks,
                        &mut failures,
                        format!("state database integrity check failed: {integrity}"),
                    ),
                    Err(error) => fail(
                        &mut checks,
                        &mut failures,
                        format!("state database cannot be opened: {error}"),
                    ),
                }
            }
        }
        Ok(_) => fail(
            &mut checks,
            &mut failures,
            format!(
                "state path is not a directory: {}",
                config.state_dir.display()
            ),
        ),
        Err(_) => checks.push(format!(
            "[info] state directory will be created on first start: {}",
            config.state_dir.display()
        )),
    }

    for (name, address) in [
        ("admin", config.admin_listen),
        ("HTTP", config.http_listen),
        ("HTTPS", config.https_listen),
    ] {
        match std::net::TcpListener::bind(address) {
            Ok(listener) => {
                drop(listener);
                checks.push(format!("[ok] {name} listener available at {address}"));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                checks.push(format!(
                    "[warn] {name} listener is already occupied at {address}"
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => fail(
                &mut checks,
                &mut failures,
                format!(
                    "cannot bind {name} listener at {address}: permission denied \
                     (run as root or grant CAP_NET_BIND_SERVICE)"
                ),
            ),
            Err(error) => fail(
                &mut checks,
                &mut failures,
                format!("cannot bind {name} listener at {address}: {error}"),
            ),
        }
    }

    if !offline {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        match client
            .get("https://api.cloudflare.com/client/v4/")
            .send()
            .await
        {
            Ok(response) => {
                checks.push(format!("[ok] Cloudflare reachable ({})", response.status()));
            }
            Err(error) => fail(
                &mut checks,
                &mut failures,
                format!("outbound Cloudflare connectivity failed: {error}"),
            ),
        }
        match client.get(&config.acme_directory_url).send().await {
            Ok(response) if response.status().is_success() => {
                checks.push("[ok] ACME directory reachable".to_owned());
            }
            Ok(response) => fail(
                &mut checks,
                &mut failures,
                format!("ACME directory returned {}", response.status()),
            ),
            Err(error) => fail(
                &mut checks,
                &mut failures,
                format!("outbound ACME connectivity failed: {error}"),
            ),
        }
    }

    let ready = failures == 0;
    checks.push(if ready {
        "ready".to_owned()
    } else {
        format!("not ready: {failures} problem(s) found")
    });
    Ok(DoctorReport { checks, ready })
}

fn rooted(root: &Path, relative: &str) -> PathBuf {
    root.join(relative)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

const fn default_drain_seconds() -> u64 {
    300
}

fn default_acme_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_owned()
}

const SYSTEMD_UNIT: &str = r#"[Unit]
Description=Hostknot domain binding proxy
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hostknot serve --config /etc/hostknot/config.toml
Restart=on-failure
RestartSec=5s
DynamicUser=yes
User=hostknot
StateDirectory=hostknot
ConfigurationDirectory=hostknot
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
StateDirectoryMode=0700

[Install]
WantedBy=multi-user.target
"#;
