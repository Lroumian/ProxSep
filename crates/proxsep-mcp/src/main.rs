use std::{
    io::{BufRead, Write},
    path::PathBuf,
};

use clap::Parser;
use proxsep_command::{CommandContext, CommandRegistry};
use proxsep_core::profile::Profile;
use proxsep_mcp::McpServer;

#[derive(Parser)]
#[command(name = "proxsep-mcp", version, about = "ProxSep MCP command adapter")]
struct Cli {
    /// Optional PPX profile used to create a persistent runtime context.
    #[arg(long)]
    profile: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let runtime = if let Some(path) = cli.profile {
        let xml = std::fs::read_to_string(path)?;
        Some(proxsep_runtime::Runtime::new(
            Profile::from_xml_for_current_user(&xml)?,
        ))
    } else {
        None
    };
    let server = McpServer::new(CommandRegistry::standard(), CommandContext { runtime });
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut stdout = std::io::BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        if let Some(response) = server.handle_json(&line?) {
            serde_json::to_writer(&mut stdout, &response)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
    Ok(())
}
