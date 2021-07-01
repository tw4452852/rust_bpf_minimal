#![no_std]
#![no_main]

use aya_bpf::{
    cty::*,
    helpers::bpf_get_smp_processor_id,
    macros::*,
    maps::{Array, HashMap, PerfMap},
    programs::ProbeContext,
    BpfContext,
};

#[panic_handler]
fn do_panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[map]
static mut HIT_PIDS: PerfMap<u32> = PerfMap::new(0);

#[map]
static mut COMMS: HashMap<u32, [c_char; 16]> = HashMap::with_max_entries(64, 0);

#[map]
static mut CORE: Array<u32> = Array::with_max_entries(1, 0);

#[kprobe]
fn kprobe(ctx: ProbeContext) {
    let pid = ctx.pid();
    let comm = ctx.command().unwrap_or([0; 16]);
    let filter_core = unsafe { *CORE.get(0).unwrap_or(&1113) };
    let current_core = unsafe { bpf_get_smp_processor_id() };

    if filter_core != 1113 && filter_core != current_core {
        return;
    }

    unsafe {
        COMMS.insert(&pid, &comm, 0);
        HIT_PIDS.output(&ctx, &pid, 0);
    }
}
