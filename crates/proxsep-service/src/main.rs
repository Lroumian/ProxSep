#[cfg(windows)]
mod scm;

use clap::{Args, Parser, Subcommand};
#[cfg(windows)]
use proxsep_service::validate_service_name;
use proxsep_service::{DEFAULT_SERVICE_NAME, EngineConfig};
use std::{net::SocketAddr, path::PathBuf};

#[derive(Parser)]
#[command(
    version,
    about = "Rust proxy runtime: console daemon and Windows service management"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct EngineArgs {
    #[arg(long)]
    profile: PathBuf,
    #[arg(long, default_value = "127.0.0.1:1080")]
    listen: SocketAddr,
    #[arg(long, default_value = "service-client.exe")]
    application: String,
}

impl EngineArgs {
    fn config(&self) -> Result<EngineConfig, String> {
        let config = EngineConfig {
            profile_path: std::fs::canonicalize(&self.profile)
                .map_err(|e| format!("cannot resolve profile path: {e}"))?,
            listen: self.listen,
            application: self.application.clone(),
        };
        config.validate()?;
        Ok(config)
    }
}

#[derive(Subcommand)]
enum Command {
    /// Run in the console until Ctrl+C, then stop and drain tunnels.
    Run {
        #[command(flatten)]
        engine: EngineArgs,
    },
    /// Entry point used by the Windows Service Control Manager.
    Service {
        #[arg(long, default_value = DEFAULT_SERVICE_NAME)]
        name: String,
        #[command(flatten)]
        engine: EngineArgs,
    },
    /// Register a service. Does not start it. Requires SCM installation privileges.
    Install {
        #[arg(long, default_value = DEFAULT_SERVICE_NAME)]
        name: String,
        #[command(flatten)]
        engine: EngineArgs,
        #[arg(long, default_value = "NT AUTHORITY\\LocalService")]
        account: String,
        #[arg(long)]
        auto_start: bool,
    },
    /// Remove a stopped service. Does not stop a running service automatically.
    Uninstall {
        #[arg(long, default_value = DEFAULT_SERVICE_NAME)]
        name: String,
    },
    /// Query the service's SCM state.
    Status {
        #[arg(long, default_value = DEFAULT_SERVICE_NAME)]
        name: String,
    },
    /// Start an installed service.
    Start {
        #[arg(long, default_value = DEFAULT_SERVICE_NAME)]
        name: String,
    },
    /// Request a graceful service stop.
    Stop {
        #[arg(long, default_value = DEFAULT_SERVICE_NAME)]
        name: String,
    },
}

fn main() {
    if let Err(error) = execute(Cli::parse().command) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn execute(command: Command) -> Result<(), String> {
    match command {
        Command::Run { engine } => {
            let config = engine.config()?;
            tokio::runtime::Runtime::new()
                .map_err(|e| e.to_string())?
                .block_on(async {
                    let listener = proxsep_service::start_engine(&config).await?;
                    println!(
                        "Listening on {}; press Ctrl+C to stop",
                        listener.local_addr()
                    );
                    let result = tokio::signal::ctrl_c().await.map_err(|e| e.to_string());
                    listener.stop().await;
                    result
                })
        }
        #[cfg(windows)]
        Command::Service { name, engine } => {
            validate_service_name(&name)?;
            // Defer profile access until after SCM registration so startup errors
            // reach the service's Stopped status with a nonzero exit code.
            scm::dispatch(
                name,
                EngineConfig {
                    profile_path: engine.profile,
                    listen: engine.listen,
                    application: engine.application,
                },
            )
        }
        #[cfg(windows)]
        Command::Install {
            name,
            engine,
            account,
            auto_start,
        } => {
            validate_service_name(&name)?;
            scm::install(&name, &engine.config()?, &account, auto_start)
        }
        #[cfg(windows)]
        Command::Uninstall { name } => {
            validate_service_name(&name)?;
            scm::uninstall(&name)
        }
        #[cfg(windows)]
        Command::Status { name } => {
            validate_service_name(&name)?;
            scm::status(&name)
        }
        #[cfg(windows)]
        Command::Start { name } => {
            validate_service_name(&name)?;
            scm::start(&name)
        }
        #[cfg(windows)]
        Command::Stop { name } => {
            validate_service_name(&name)?;
            scm::stop(&name)
        }
        #[cfg(not(windows))]
        _ => Err(
            "Windows SCM management is only available on Windows; use 'run' on this platform"
                .into(),
        ),
    }
}
