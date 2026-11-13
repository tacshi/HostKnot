use std::{
    io::{BufRead, BufReader, IsTerminal, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    process::{Command as Process, Stdio},
};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use hostknot::{AdminAccess, FileConfig, HostKnot};

#[derive(Debug, Parser)]
#[command(
    name = "hostknot",
    about,
    disable_version_flag = true,
    after_help = "Run `hostknot` with no command for status and common tasks."
)]
struct Cli {
    /// Configuration read by the overview shown when no command is given.
    #[arg(long, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the administration and reverse-proxy listeners.
    Serve(ConfigArgs),
    /// Check whether this host is ready to run HostKnot.
    Doctor(DoctorArgs),
    /// Manage the system service.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Find the admin panel URL or recover administrator access.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Show the service log in readable form (reads the systemd journal).
    Logs(LogsArgs),
    /// Print version information.
    Version,
}

#[derive(Debug, Args)]
struct ConfigArgs {
    #[arg(long, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[arg(long, default_value = DEFAULT_CONFIG)]
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
    /// Print the admin panel URL. Before first setup, this issues a fresh
    /// one-time setup link (any earlier link stops working).
    Url(ConfigArgs),
    /// Invalidate sessions and the password, then print a one-time setup link.
    Reset(ResetArgs),
}

#[derive(Debug, Args)]
struct LogsArgs {
    /// Keep printing new entries as they arrive.
    #[arg(short, long)]
    follow: bool,
    /// How many recent entries to show.
    #[arg(short = 'n', long, default_value_t = 100)]
    lines: u32,
    /// Only entries newer than this, e.g. "1 hour ago" or "2026-11-01".
    #[arg(long)]
    since: Option<String>,
}

#[derive(Debug, Args)]
struct ResetArgs {
    #[arg(long, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
    /// Override the state directory from the configuration file.
    #[arg(long)]
    state_dir: Option<PathBuf>,
}

const DEFAULT_CONFIG: &str = "/etc/hostknot/config.toml";
const DEFAULT_STATE_DIR: &str = "/var/lib/hostknot";
const SERVICE: &str = "hostknot";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hostknot=info".into()),
        )
        .json()
        .init();
    let cli = Cli::parse();
    let Some(command) = cli.command else {
        print_overview(&cli.config);
        return Ok(());
    };
    match command {
        Command::Logs(args) => show_logs(&args)?,
        Command::Version => println!("hostknot {}", env!("CARGO_PKG_VERSION")),
        Command::Serve(args) => {
            let config = FileConfig::load(&args.config)?.runtime();
            let public_url = config.admin_public_url.clone();
            let running = HostKnot::start(config).await?;
            if let Some(token) = running.bootstrap_token() {
                let setup_url = hostknot::setup_url(
                    &public_url.context("admin public URL is required")?,
                    &token,
                )?;
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
            let config_path = args.root.join("etc/hostknot/config.toml");
            let upgrade = config_path.exists();
            hostknot::operations::install_systemd(hostknot::operations::InstallOptions {
                root: &args.root,
                binary: &binary,
                public_ips: &args.public_ips,
            })?;
            print_install_guide(&config_path, upgrade);
        }
        Command::Admin {
            command: AdminCommand::Url(args),
        } => {
            let config = FileConfig::load(&args.config)?;
            let admin_url = &config.admin_public_url;
            match HostKnot::admin_access(&config.state_dir)? {
                AdminAccess::Setup { token } => {
                    print_setup_link(&hostknot::setup_url(admin_url, &token)?);
                    println!("Any setup link printed earlier no longer works.");
                }
                AdminAccess::SignIn => {
                    println!("Admin panel: {admin_url}");
                    println!();
                    println!("Sign in with the administrator password.");
                    println!("Forgot it? `hostknot admin reset` issues a new setup link;");
                    println!("bindings, credentials, and certificates are kept.");
                }
            }
        }
        Command::Admin {
            command: AdminCommand::Reset(args),
        } => {
            // A missing config only costs the full link: recovery must still
            // work with the state directory alone.
            let config = FileConfig::load(&args.config);
            let state_dir = args
                .state_dir
                .or_else(|| config.as_ref().ok().map(|config| config.state_dir.clone()))
                .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
            let token = HostKnot::reset_admin(&state_dir)?;
            println!("Administrator reset; all sessions were signed out.");
            match config {
                Ok(config) => {
                    print_setup_link(&hostknot::setup_url(&config.admin_public_url, &token)?)
                }
                Err(error) => {
                    eprintln!("warning: {error:#}");
                    println!("One-time setup token: {token}");
                    println!("Open https://<admin-host>:9443/setup?token=<token> to finish.");
                }
            }
        }
    }
    Ok(())
}

/// What a returning operator needs: is it running, where is the panel, and
/// which commands get them back in.
fn print_overview(config_path: &Path) {
    println!(
        "HostKnot {} — domains to local services, with DNS and HTTPS handled.",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    let config = FileConfig::load(config_path);
    if let Some(state) = service_state() {
        row("Service", &state);
    }
    match &config {
        Ok(config) => {
            row("Admin panel", config.admin_public_url.as_str());
            row("Config", &config_path.display().to_string());
        }
        Err(_) if !config_path.exists() => {
            row(
                "Config",
                &format!("{} (not installed yet)", config_path.display()),
            );
        }
        Err(error) => row("Config", &format!("{error:#}")),
    }
    println!();
    if config.is_err() && !config_path.exists() {
        section("Install");
        step(
            "Install the binary, config, and systemd service",
            Some("sudo hostknot service install --public-ip <YOUR_VPS_IP>"),
        );
        println!();
    }
    print_common_tasks();
    println!();
    println!("Every command and option: hostknot help");
}

fn print_install_guide(config_path: &Path, upgrade: bool) {
    let admin_url = FileConfig::load(config_path)
        .map(|config| config.admin_public_url.to_string())
        .unwrap_or_else(|_| "https://<YOUR_VPS_IP>:9443/".to_owned());
    if upgrade {
        println!("HostKnot upgraded. Your config, bindings, and credentials are unchanged.");
        println!();
        section("Next step");
        step(
            "Restart onto the new binary and confirm the version",
            Some("sudo systemctl restart hostknot && hostknot version"),
        );
    } else {
        println!("HostKnot installed.");
        println!();
        section("Next steps");
        step(
            "1. Start the service",
            Some("sudo systemctl daemon-reload && sudo systemctl enable --now hostknot"),
        );
        step(
            "2. Print a one-time setup link",
            Some("sudo hostknot admin url"),
        );
        step(
            "3. Open the link, create the administrator, then connect Cloudflare",
            None,
        );
        println!("     The admin panel lives at {admin_url}");
    }
    println!();
    print_common_tasks();
    println!();
    println!("Forget these later? Run `hostknot` to see them again.");
}

fn print_common_tasks() {
    section("Get into the admin panel");
    task(
        "sudo hostknot admin url",
        "Panel URL; before first setup, a fresh one-time setup link",
    );
    task(
        "sudo hostknot admin reset",
        "Forgot the password? Reset it and get a setup link",
    );
    println!();
    section("Check on the service");
    task("sudo hostknot logs -f", "Follow the service log");
    task(
        "sudo hostknot doctor",
        "Check ports, keys, database, and connectivity",
    );
    task("systemctl status hostknot", "Is the service running?");
    task(
        "sudo systemctl restart hostknot",
        "Restart after a config change",
    );
}

fn section(title: &str) {
    if std::io::stdout().is_terminal() {
        println!("\x1b[1m{title}\x1b[0m");
    } else {
        println!("{title}");
    }
}

fn row(label: &str, value: &str) {
    println!("  {label:<13}{value}");
}

fn task(command: &str, description: &str) {
    println!("  {command:<34}  {description}");
}

/// A numbered or one-off instruction, with its command indented beneath.
fn step(description: &str, command: Option<&str>) {
    println!("  {description}");
    if let Some(command) = command {
        println!("     {command}");
    }
}

/// `systemctl is-active` prints a single word (active, inactive, failed, …);
/// hosts without systemd simply omit the row.
fn service_state() -> Option<String> {
    let output = Process::new("systemctl")
        .args(["is-active", SERVICE])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let state = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!state.is_empty()).then_some(state)
}

fn show_logs(args: &LogsArgs) -> Result<()> {
    let mut journalctl = Process::new("journalctl");
    journalctl
        .args(["--unit", SERVICE, "--output", "cat", "--no-pager"])
        .args(["--lines", &args.lines.to_string()]);
    if let Some(since) = &args.since {
        journalctl.args(["--since", since]);
    }
    if args.follow {
        journalctl.arg("--follow");
    }
    let mut child = journalctl
        .stdout(Stdio::piped())
        .spawn()
        .context("could not run journalctl: `hostknot logs` reads the systemd journal on the HostKnot server")?;
    let color = std::io::stdout().is_terminal();
    let mut stdout = std::io::stdout().lock();
    for line in BufReader::new(child.stdout.take().expect("piped stdout")).lines() {
        let line = line?;
        // A closed pipe (`hostknot logs | head`) is a normal way to stop.
        if writeln!(stdout, "{}", hostknot::logs::format_line(&line, color)).is_err() {
            let _ = child.kill();
            break;
        }
    }
    let status = child.wait()?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

fn print_setup_link(url: &url::Url) {
    println!("Open this one-time setup link (expires in 1 hour):");
    println!();
    println!("  {url}");
    println!();
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
