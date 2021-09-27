#![no_std]
use plain::Plain;

pub const UNSPECIFIED: u32 = u32::MAX;

#[repr(C)]
#[derive(Default)]
pub struct event {
    pub pid: u32,
    pub kernel_stackid: u32,
    pub user_stackid: u32,
}

unsafe impl Plain for event {}
