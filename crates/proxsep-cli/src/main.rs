use std::{
    io::{BufRead, Write},
    path::PathBuf,
    sync::Arc,
};

use clap::{Parser, Subcommand, ValueEnum};
use proxsep_core::{profile::Profile, rules::Connection};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
};

#[derive(Parser)]
#[command(
    name = "proxsep",
    version,
    about = "Behavior-compatible Rust network routing core"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Discover or invoke the shared UI/CLI/JSON/MCP command catalog.
    #[command(name = "command")]
    Shared {
        #[command(subcommand)]
        action: SharedCommand,
    },
    /// Use our already-loaded independent driver. Never installs/loads a driver or changes DNS settings.
    Transparent {
        profile: PathBuf,
        #[arg(long, default_value = "127.0.0.1:0")]
        ipv4_listen: String,
        #[arg(long, default_value = "[::1]:0")]
        ipv6_listen: String,
    },
    /// Route dynamic destinations through a PPX profile. Does not change system proxy settings.
    Serve {
        profile: PathBuf,
        #[arg(long, default_value = "127.0.0.1:1081")]
        listen: String,
        #[arg(long, default_value = "")]
        app: String,
        #[arg(long)]
        dns_listen: Option<String>,
        #[arg(long, default_value = "127.0.0.1:53")]
        dns_upstream: std::net::SocketAddr,
    },
    CheckProxy {
        profile: PathBuf,
        #[arg(long)]
        id: u32,
        #[arg(long)]
        chain: bool,
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
    },
    ExportProfile {
        profile: PathBuf,
        output: PathBuf,
    },
    DriverStatus {
        #[arg(long)]
        device: String,
    },
    CheckProfile {
        profile: PathBuf,
    },
    Route {
        profile: PathBuf,
        #[arg(long)]
        app: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        port: u16,
        #[arg(long)]
        pid: Option<u32>,
        /// Resolved destination addresses available to IP/CIDR rules.
        #[arg(long = "resolved-ip")]
        resolved_ips: Vec<std::net::IpAddr>,
        /// Network interface name or identifier used by interface-aware rules.
        #[arg(long)]
        interface: Option<String>,
        /// Active address for --interface; repeat for multiple addresses.
        #[arg(long = "interface-ip", requires = "interface")]
        interface_ips: Vec<std::net::IpAddr>,
        /// Print every evaluated rule and condition.
        #[arg(long)]
        trace: bool,
    },
    Tunnel {
        #[arg(long, default_value = "127.0.0.1:1081")]
        listen: String,
        #[arg(long)]
        proxy: String,
        #[arg(long, value_enum)]
        protocol: ProxyProtocol,
        #[arg(long)]
        target_host: String,
        #[arg(long)]
        target_port: u16,
        #[arg(long)]
        username: Option<String>,
        #[arg(long, requires = "username")]
        password: Option<String>,
    },
}

#[derive(Subcommand)]
enum SharedCommand {
    /// List machine-readable command descriptors.
    List,
    /// Describe one command, including its input/output JSON Schema.
    Describe { id: String },
    /// Execute one JSON request envelope.
    Invoke {
        request: String,
        #[arg(long)]
        profile: Option<PathBuf>,
    },
    /// Execute newline-delimited JSON requests with one persistent context.
    Stream {
        #[arg(long)]
        profile: Option<PathBuf>,
    },
}

#[cfg(test)]
mod branding_tests {
    use super::{Cli, Command};
    use clap::{CommandFactory, Parser};

    #[test]
    fn command_name_is_proxsep() {
        assert_eq!(Cli::command().get_name(), "proxsep");
    }

    #[test]
    fn route_accepts_an_explicit_decision_trace_flag() {
        let cli = Cli::try_parse_from([
            "proxsep",
            "route",
            "profile.ppx",
            "--app",
            "app.exe",
            "--host",
            "example.com",
            "--port",
            "443",
            "--pid",
            "8432",
            "--resolved-ip",
            "34.120.1.8",
            "--interface",
            "Ethernet",
            "--interface-ip",
            "192.0.2.10",
            "--trace",
        ])
        .unwrap();
        let Command::Route {
            trace,
            pid,
            resolved_ips,
            interface,
            interface_ips,
            ..
        } = cli.command
        else {
            panic!("expected route command");
        };
        assert!(trace);
        assert_eq!(pid, Some(8432));
        assert_eq!(
            resolved_ips,
            vec!["34.120.1.8".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(interface.as_deref(), Some("Ethernet"));
        assert_eq!(
            interface_ips,
            vec!["192.0.2.10".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn shared_command_adapter_exposes_list_describe_invoke_and_stream() {
        for arguments in [
            vec!["proxsep", "command", "list"],
            vec!["proxsep", "command", "describe", "route.trace"],
            vec![
                "proxsep",
                "command",
                "invoke",
                r#"{"command":"system.command.count","arguments":{}}"#,
            ],
            vec!["proxsep", "command", "stream"],
        ] {
            assert!(Cli::try_parse_from(arguments).is_ok());
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum ProxyProtocol {
    Socks5,
    Http,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Shared { action } => run_shared_command(action)?,
        Command::Transparent {
            profile,
            ipv4_listen,
            ipv6_listen,
        } => {
            let runtime = proxsep_runtime::Runtime::new(load_profile(&profile)?);
            let v4: std::net::SocketAddr = ipv4_listen.parse()?;
            let v6: std::net::SocketAddr = ipv6_listen.parse()?;
            if v4.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                || v6.ip() != std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            {
                return Err("transparent driver ABI requires exactly 127.0.0.1 and ::1".into());
            }
            let ipv4 = runtime.start_transparent(&ipv4_listen).await?;
            let ipv6 = runtime.start_transparent(&ipv6_listen).await?;
            let driver = proxsep_driver::device::DriverDevice::open_path(
                proxsep_driver::INDEPENDENT_DEVICE_PATH,
            )?;
            driver.configure_independent(&proxsep_driver::IndependentConfig::new(
                std::process::id(),
                ipv4.local_addr().port(),
                ipv6.local_addr().port(),
            )?)?;
            driver.start()?;
            println!(
                "independent transparent TCP listeners: {} / {}; DNS capture not enabled",
                ipv4.local_addr(),
                ipv6.local_addr()
            );
            let signal = tokio::signal::ctrl_c().await;
            // Stop interception before tearing down listeners. Device close also
            // releases its owner and stops interception in our driver.
            let stopped = driver.stop();
            ipv4.stop().await;
            ipv6.stop().await;
            signal?;
            stopped?;
        }
        Command::Serve {
            profile,
            listen,
            app,
            dns_listen,
            dns_upstream,
        } => {
            let runtime = proxsep_runtime::Runtime::new(load_profile(&profile)?);
            let listener = runtime.start_socks5(&listen, app).await?;
            let dns = if let Some(address) = dns_listen {
                Some(runtime.start_dns(&address, dns_upstream).await?)
            } else {
                None
            };
            println!("SOCKS5 listening on {}", listener.local_addr());
            if let Some(dns) = &dns {
                println!("DNS listening on {}", dns.local_addr());
            }
            tokio::signal::ctrl_c().await?;
            listener.stop().await;
            if let Some(dns) = dns {
                dns.stop().await;
            }
            for event in runtime.events() {
                println!(
                    "{} {}:{} {} sent={} received={} {}",
                    event.application,
                    event.target,
                    event.port,
                    event.state,
                    event.sent,
                    event.received,
                    event.error.unwrap_or_default()
                );
            }
        }
        Command::CheckProxy {
            profile,
            id,
            chain,
            host,
            port,
        } => {
            let mut profile = load_profile(&profile)?;
            profile.rules = vec![proxsep_core::profile::Rule {
                name: "Default".into(),
                action: if chain {
                    proxsep_core::profile::Action::Chain(id.to_string())
                } else {
                    proxsep_core::profile::Action::Proxy(id.to_string())
                },
                ..Default::default()
            }];
            profile.validate()?;
            let runtime = proxsep_runtime::Runtime::new(profile);
            let now = std::time::Instant::now();
            let stream = runtime
                .connect(&Connection::new("ProxyChecker", host, port))
                .await?;
            println!(
                "proxy tunnel connected in {} ms; local={}",
                now.elapsed().as_millis(),
                stream.local_addr()?
            );
        }
        Command::ExportProfile { profile, output } => {
            let xml = load_profile(&profile)?.to_xml()?;
            // Never overwrite a destination implicitly.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output)?;
            file.write_all(xml.as_bytes())?;
            file.sync_all()?;
        }
        Command::DriverStatus { device } => {
            let driver = proxsep_driver::device::DriverDevice::open_path(&device)?;
            println!(
                "version={} counters={:?}",
                driver.version()?,
                driver.counters()?
            );
        }
        Command::CheckProfile { profile } => {
            let xml = std::fs::read_to_string(profile)?;
            let registry = proxsep_command::CommandRegistry::standard();
            let summary = registry.execute(
                &proxsep_command::CommandContext::default(),
                "profile.summary",
                serde_json::json!({ "xml": xml }),
            )?;
            println!(
                "valid Proxifier profile v{}: {} proxies, {} chains, {} rules",
                summary["version"], summary["proxies"], summary["chains"], summary["rules"]
            );
        }
        Command::Route {
            profile,
            app,
            host,
            port,
            pid,
            resolved_ips,
            interface,
            interface_ips,
            trace,
        } => {
            let xml = std::fs::read_to_string(profile)?;
            let mut interfaces = serde_json::Map::new();
            if let Some(interface) = interface {
                interfaces.insert(interface, serde_json::json!(interface_ips));
            }
            let registry = proxsep_command::CommandRegistry::standard();
            let command = if trace { "route.trace" } else { "route.decide" };
            let result = registry.execute(
                &proxsep_command::CommandContext::default(),
                command,
                serde_json::json!({
                    "xml": xml,
                    "application": app,
                    "target": host,
                    "port": port,
                    "pid": pid,
                    "resolved_ips": resolved_ips,
                    "interfaces": interfaces
                }),
            )?;
            if trace {
                print!("{}", result["text"].as_str().unwrap_or_default());
            } else {
                println!(
                    "{}: {}",
                    result["rule"].as_str().unwrap_or("<unknown>"),
                    result["action"].as_str().unwrap_or("<unknown>")
                );
            }
        }
        Command::Tunnel {
            listen,
            proxy,
            protocol,
            target_host,
            target_port,
            username,
            password,
        } => {
            let listener = TcpListener::bind(&listen).await?;
            let config = Arc::new((
                proxy,
                protocol,
                target_host,
                target_port,
                username.zip(password),
            ));
            println!("listening on {listen}");
            loop {
                let (mut client, _) = listener.accept().await?;
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
                        let mut upstream = TcpStream::connect(&config.0).await?;
                        let credentials = config
                            .4
                            .as_ref()
                            .map(|value| (value.0.as_str(), value.1.as_str()));
                        match config.1 {
                            ProxyProtocol::Socks5 => {
                                proxsep_protocol::socks5::negotiate(
                                    &mut upstream,
                                    &config.2,
                                    config.3,
                                    credentials,
                                )
                                .await?
                            }
                            ProxyProtocol::Http => {
                                proxsep_protocol::http_connect::negotiate(
                                    &mut upstream,
                                    &config.2,
                                    config.3,
                                    credentials,
                                )
                                .await?
                            }
                        }
                        copy_bidirectional(&mut client, &mut upstream).await?;
                        Ok(())
                    }
                    .await;
                    if let Err(error) = result {
                        eprintln!("tunnel error: {error}");
                    }
                });
            }
        }
    }
    Ok(())
}

fn run_shared_command(action: SharedCommand) -> Result<(), Box<dyn std::error::Error>> {
    use proxsep_command::CommandRegistry;

    let registry = CommandRegistry::standard();
    match action {
        SharedCommand::List => {
            write_json(&registry.descriptors())?;
        }
        SharedCommand::Describe { id } => {
            let Some(descriptor) = registry.descriptor(&id) else {
                return Err(format!("unknown command: {id}").into());
            };
            write_json(descriptor)?;
        }
        SharedCommand::Invoke { request, profile } => {
            let context = command_context(profile)?;
            write_json(&registry.execute_json(&context, &request))?;
        }
        SharedCommand::Stream { profile } => {
            let context = command_context(profile)?;
            let stdin = std::io::stdin();
            let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
            for line in stdin.lock().lines() {
                let response = registry.execute_json(&context, &line?);
                serde_json::to_writer(&mut stdout, &response)?;
                stdout.write_all(b"\n")?;
                stdout.flush()?;
            }
        }
    }
    Ok(())
}

fn command_context(
    profile: Option<PathBuf>,
) -> Result<proxsep_command::CommandContext, Box<dyn std::error::Error>> {
    Ok(proxsep_command::CommandContext {
        runtime: profile
            .as_ref()
            .map(load_profile)
            .transpose()?
            .map(proxsep_runtime::Runtime::new),
    })
}

fn write_json(value: &impl serde::Serialize) -> Result<(), Box<dyn std::error::Error>> {
    let stdout = std::io::stdout();
    let mut stdout = std::io::BufWriter::new(stdout.lock());
    serde_json::to_writer_pretty(&mut stdout, value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn load_profile(path: &PathBuf) -> Result<Profile, Box<dyn std::error::Error>> {
    Ok(Profile::from_xml_for_current_user(
        &std::fs::read_to_string(path)?,
    )?)
}
