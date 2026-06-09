use wasmtime::{Engine, Module, Store, Memory, TypedFunc, Caller};
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use tokio::sync::mpsc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub timestamp_ns: u64,
    pub comm: Vec<u8>,
    pub filename: Vec<u8>,
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

#[allow(dead_code)]
pub struct HostState {
    pub banned_binaries: Vec<String>,
    pub process_history: Arc<Mutex<Vec<ExecEvent>>>,
    pub alerts_tx: mpsc::Sender<Alert>,
}

pub struct WasmRuntime {
    _engine: Engine,
    _module: Module,
    store: Store<HostState>,
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
