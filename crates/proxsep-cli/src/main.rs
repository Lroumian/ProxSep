use std::{path::PathBuf, sync::Arc};

use clap::{Parser, Subcommand, ValueEnum};
use proxsep_core::{
    profile::Profile,
    rules::{Connection, RuleEngine},
};
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
}

#[derive(Clone, Copy, ValueEnum)]
enum ProxyProtocol {
    Socks5,
    Http,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
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
            use std::io::Write;
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
            let profile = load_profile(&profile)?;
            println!(
                "valid Proxifier profile v{}: {} proxies, {} chains, {} rules",
                profile.version,
                profile.proxies.len(),
                profile.chains.len(),
                profile.rules.len()
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
            let profile = load_profile(&profile)?;
            let mut connection = Connection::new(app, host, port);
            connection.pid = pid;
            connection.resolved_ips = resolved_ips;
            if let Some(interface) = interface {
                connection.interfaces.insert(interface, interface_ips);
            }
            let engine = RuleEngine::new(&profile.rules);
            if trace {
                print!("{}", engine.trace(&connection).render_text(&connection));
            } else {
                let decision = engine.decide(&connection);
                println!("{}: {:?}", decision.rule_name, decision.action);
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

fn load_profile(path: &PathBuf) -> Result<Profile, Box<dyn std::error::Error>> {
    Ok(Profile::from_xml_for_current_user(
        &std::fs::read_to_string(path)?,
    )?)
}
