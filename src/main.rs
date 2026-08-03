use std::{net::IpAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use hostknot::{FileConfig, Hostknot};

#[derive(Debug, Parser)]
#[command(name = "hostknot", about, disable_version_flag = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the administration and reverse-proxy listeners.
    Serve(ConfigArgs),
    /// Check whether this host is ready to run Hostknot.
    Doctor(DoctorArgs),
    /// Manage the system service.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Recover local administrator access.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Print version information.
    Version,
}

#[derive(Debug, Args)]
struct ConfigArgs {
    #[arg(long, default_value = "/etc/hostknot/config.toml")]
    config: PathBuf,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[arg(long, default_value = "/etc/hostknot/config.toml")]
    config: PathBuf,
    /// Skip outbound connectivity checks.
    #[arg(long)]
    offline: bool,
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    /// Install or update the hardened systemd service.
    Install(InstallArgs),
}

#[derive(Debug, Args)]
struct InstallArgs {
    #[arg(long, default_value = "/")]
    root: PathBuf,
    #[arg(long)]
    binary: Option<PathBuf>,
    #[arg(long = "public-ip", required = true)]
    public_ips: Vec<IpAddr>,
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    /// Invalidate sessions and issue a one-time setup token.
    Reset(ResetArgs),
}

#[derive(Debug, Args)]
struct ResetArgs {
    #[arg(long, default_value = "/var/lib/hostknot")]
    state_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hostknot=info".into()),
        )
        .json()
        .init();
    match Cli::parse().command {
        Command::Version => println!("hostknot {}", env!("CARGO_PKG_VERSION")),
        Command::Serve(args) => {
            let config = FileConfig::load(&args.config)?.runtime();
            let public_url = config.admin_public_url.clone();
            let running = Hostknot::start(config).await?;
            if let Some(token) = running.bootstrap_token() {
                let setup_url = public_url
                    .context("admin public URL is required")?
                    .join(&format!("setup?token={token}"))?;
                eprintln!("Open this one-time setup URL: {setup_url}");
            }
            wait_for_shutdown_signal().await?;
            running.shutdown().await;
        }
        Command::Doctor(args) => {
            let report = hostknot::operations::doctor(&args.config, args.offline).await?;
            for check in &report.checks {
                println!("{check}");
            }
            if !report.ready {
                std::process::exit(1);
            }
        }
        Command::Service {
            command: ServiceCommand::Install(args),
        } => {
            let binary = args
                .binary
                .unwrap_or(std::env::current_exe().context("locate current executable")?);
            hostknot::operations::install_systemd(hostknot::operations::InstallOptions {
                root: &args.root,
                binary: &binary,
                public_ips: &args.public_ips,
            })?;
            println!("Hostknot systemd service installed");
            println!("Next steps:");
            println!("  systemctl daemon-reload");
            println!("  systemctl enable --now hostknot");
            println!("  journalctl -u hostknot | grep 'setup URL'   # one-time admin setup link");
        }
        Command::Admin {
            command: AdminCommand::Reset(args),
        } => {
            let token = Hostknot::reset_admin(&args.state_dir)?;
            println!("One-time administrator setup token: {token}");
        }
    }
    Ok(())
}

/// systemd stops services with SIGTERM, so graceful shutdown must handle it
/// in addition to Ctrl-C.
async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}
