#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug)]
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

impl ExecEvent {
    pub const SIZE: usize = core::mem::size_of::<Self>();
}
