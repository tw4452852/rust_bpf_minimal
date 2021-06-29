#![no_std]
#![no_main]

use aya_bpf::macros::*;
use aya_bpf::programs::ProbeContext;

#[panic_handler]
fn do_panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[kprobe(name="kprobe")]
fn kprobe(_ctx: ProbeContext) {
}

