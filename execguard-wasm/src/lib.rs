#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::format;
use serde::{Serialize, Deserialize};

#[allow(dead_code)]
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

#[no_mangle]
pub extern "C" fn process_event(input_ptr: i32, input_len: i32) -> i32 {
    let input_slice = unsafe {
        core::slice::from_raw_parts(input_ptr as *const u8, input_len as usize)
    };
    
    let mut event: ExecEvent = match serde_json::from_slice(input_slice) {
        Ok(e) => e,
        Err(_) => return -1,
    };
    
    let filename = vec_to_string(&event.filename);
    let comm = vec_to_string(&event.comm);
    
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

fn vec_to_string(bytes: &[u8]) -> String {
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

// CORRECAO: Allocator sem mutable static reference
use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;

struct SimpleAllocator;

unsafe impl GlobalAlloc for SimpleAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        static mut HEAP: UnsafeCell<[u8; 65536]> = UnsafeCell::new([0; 65536]);
        static mut HEAP_POS: usize = 0;
        
        let pos = HEAP_POS;
        HEAP_POS += layout.size();
        (*HEAP.get()).as_mut_ptr().add(pos)
    }
    
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOCATOR: SimpleAllocator = SimpleAllocator;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
