use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};

use crate::opencode;

#[derive(Debug, Parser)]
#[command(
    name = "axiomio",
    version,
    about = "AxiomIO desktop application and TEE-attested E2EE proxy"
)]
struct Cli {
    /// Run the local proxy without opening the desktop application.
    #[arg(long)]
    headless: bool,

    #[command(subcommand)]
    command: Option<Command>,
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
    /// Add or update AxiomIO's managed OpenCode provider.
    Opencode(OpenCodeArgs),
}

#[derive(Debug, Args)]
struct OpenCodeArgs {
    /// Override the OpenCode config file. Primarily useful for testing.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Local AxiomIO proxy API root.
    #[arg(long, default_value = "http://127.0.0.1:8484/v1")]
    base_url: String,

    /// Print the updated config without writing it.
    #[arg(long)]
    dry_run: bool,
}

pub fn run<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = Cli::parse_from(args);
    match (cli.headless, cli.command) {
        (true, None) => {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(crate::run_headless())?;
        }
        (
            false,
            Some(Command::Configure {
                agent: Agent::Opencode(args),
            }),
        ) => configure_opencode(args)?,
        (true, Some(_)) => bail!("--headless cannot be combined with a subcommand"),
        (false, None) => bail!("run without arguments to open the desktop application"),
    }
    Ok(())
}

fn configure_opencode(args: OpenCodeArgs) -> Result<()> {
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
    Ok(())
}
