mod opencode;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "axiom",
    version,
    about = "Install and configure the Axiom proxy"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Configure a supported local coding agent.
    Configure {
        #[command(subcommand)]
        agent: Agent,
    },
}

#[derive(Debug, Subcommand)]
enum Agent {
    /// Add or update Axiom's managed OpenCode provider.
    Opencode(OpenCodeArgs),
}

#[derive(Debug, Args)]
struct OpenCodeArgs {
    /// Override the OpenCode config file. Primarily useful for testing.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Local Axiom proxy API root.
    #[arg(long, default_value = "http://127.0.0.1:8484/v1")]
    base_url: String,

    /// Print the updated config without writing it.
    #[arg(long)]
    dry_run: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Configure {
            agent: Agent::Opencode(args),
        } => {
            let outcome = opencode::configure(opencode::ConfigureOptions {
                config_path: args.config,
                base_url: args.base_url,
                dry_run: args.dry_run,
            })?;
            if args.dry_run {
                print!("{}", outcome.rendered);
            } else if outcome.changed {
                println!("Configured OpenCode at {}", outcome.path.display());
                if let Some(backup) = outcome.backup_path {
                    println!("Backup: {}", backup.display());
                }
            } else {
                println!(
                    "OpenCode is already configured at {}",
                    outcome.path.display()
                );
            }
        }
    }
    Ok(())
}
