use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use std::process::Command;
use which::which;

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Automation orchestrator for monad-firewall", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile the eBPF bytecode and the user-space agent
    Build,
    /// Run the core firewall daemon with escalated privileges
    Run {
        #[arg(short, long, default_value = "eth0")]
        interface: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Build => {
            build_ebpf()?;
            build_userspace()?;
        }
        Commands::Run { interface } => {
            build_ebpf()?;
            build_userspace()?;
            run_daemon(&interface)?;
        }
    }

    Ok(())
}

fn build_ebpf() -> Result<()> {
    println!("⚙️ Compiling monad-firewall-ebpf targeting bpfeb-unknown-none...");

    let bpf_linker_found = which("bpf-linker").is_ok()
        || std::env::var("HOME")
            .map(|h| {
                std::path::Path::new(&h)
                    .join(".cargo/bin/bpf-linker")
                    .exists()
            })
            .unwrap_or(false);

    if !bpf_linker_found {
        return Err(anyhow!(
            "Missing 'bpf-linker'. Please install it using: cargo install bpf-linker"
        ));
    }

    let status = Command::new("cargo")
        .args([
            "+nightly",
            "build",
            "--package",
            "monad-firewall-ebpf",
            "--target",
            "bpfel-unknown-none",
            "--release",
            "-Z",
            "build-std=core",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("Failed to execute cargo build for eBPF bytecode")?;

    if !status.success() {
        return Err(anyhow!("eBPF bytecode compilation failed"));
    }

    Ok(())
}

fn build_userspace() -> Result<()> {
    println!("⚙️ Compiling user-space targets...");

    let status = Command::new("cargo")
        .args(["build", "--package", "monad-firewall-core"])
        .status()
        .context("Failed to execute cargo build for user-space core")?;

    if !status.success() {
        return Err(anyhow!("User-space compilation failed"));
    }

    Ok(())
}

fn run_daemon(interface: &str) -> Result<()> {
    println!(
        "🚀 Executing monad-firewall-core on interface: {}...",
        interface
    );

    // Check if sudo is present to handle capability escalation
    let has_sudo = which("sudo").is_ok();

    let mut cmd = if has_sudo {
        let mut c = Command::new("sudo");
        c.arg("target/debug/monad-firewall-core");
        c
    } else {
        Command::new("target/debug/monad-firewall-core")
    };

    let status = cmd
        .args(["--interface", interface])
        .status()
        .context("Failed to execute monad-firewall-core runtime engine")?;

    if !status.success() {
        return Err(anyhow!("Firewall daemon exited with an error status"));
    }

    Ok(())
}
