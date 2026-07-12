use std::fs;

use anyhow::Context as _;
use aya::programs::{Xdp, XdpMode};
use clap::Parser;
#[rustfmt::skip]
use log::warn;
use monad_firewall_common::AllowList;
use tokio::signal;

mod setup;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "ens18")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let opt = Opt::parse();
    setup::bump_memlock_rlimit();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/monad-firewall"
    )))?;

    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface } = opt;
    let program: &mut Xdp = ebpf.program_mut("monad_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpMode::default())
        .context("failed to attach the XDP program with default mode - try changing XdpMode::default() to XdpMode::Skb")?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn get_firewall_rules() {
    let config: Config = toml::from_str(&fs::read_to_string("rule.toml")?)?;
    let rules = ebpf.map_mut("RULES").unwrap();
    for rule in config.allow {
        let key = AllowList {
            ip: rule.ip,
            port: rule.port,
            _pad: 0,
        };

        rules.insert(0, &key, &1u8, 0)?;
    }
    rules
}
