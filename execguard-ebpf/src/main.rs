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
}

#[map(name = "EXEC_EVENTS")]
static mut EXEC_EVENTS: RingBuf<ExecEvent> = RingBuf::with_max_entries(8192, 0);

#[tracepoint]
pub fn execguard(ctx: TracePointContext) -> u32 {
    // sys_enter_execve: args na struct trace_entry
    // arg0 = filename (const char __user *)
    // arg1 = argv (const char __user *const __user *)
    // arg2 = envp (const char __user *const __user *)
    
    let mut event = ExecEvent {
        pid: ctx.pid(),
        uid: ctx.uid(),
        gid: 0,
        timestamp_ns: unsafe { aya_ebpf::helpers::gen::bpf_ktime_get_ns() },
        comm: [0; 16],
        filename: [0; 256],
        argc: 0,
    };
    
    // Copia comm do processo atual (16 bytes)
    let comm = unsafe { core::slice::from_raw_parts(ctx.comm().as_ptr() as *const u8, 16) };
    event.comm[..16].copy_from_slice(comm);
    
    // Lê filename do userspace (arg0 do execve)
    // Offset 16 no tracepoint context = primeiro arg
    let filename_ptr: u64 = unsafe { ctx.read_at::<u64>(16) };
    
    if filename_ptr != 0 {
        let _ = unsafe {
            bpf_probe_read_user_str_bytes(
                filename_ptr as *const u8,
                &mut event.filename,
            )
        };
    }
    
    // Tenta contar argc (arg1 = argv)
    let argv_ptr: u64 = unsafe { ctx.read_at::<u64>(24) };
    if argv_ptr != 0 {
        // Conta argumentos iterando argv[]
        // Simplificado: não contamos no MVP
        event.argc = 0;
    }
    
    // Envia para ringbuf
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
