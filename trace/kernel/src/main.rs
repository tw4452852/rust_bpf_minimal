#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{BPF_F_FAST_STACK_CMP, BPF_F_USER_STACK},
    cty::*,
    helpers::bpf_get_smp_processor_id,
    macros::*,
    maps::{Array, HashMap, PerfMap, StackTrace},
    programs::{ProbeContext, TracePointContext},
    BpfContext,
};
use share::*;

#[panic_handler]
fn do_panic(_info: &core::panic::PanicInfo) -> ! {
    unreachable!()
}

#[map]
static mut EVENTS: PerfMap<event> = PerfMap::new(0);

#[map]
static mut COMMS: HashMap<u32, [c_char; 16]> = HashMap::with_max_entries(64, 0);

#[map]
static mut CORE: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static mut STACK: Array<bool> = Array::with_max_entries(1, 0);

#[map]
static mut STACKS: StackTrace = StackTrace::with_max_entries(64, 0);

#[kprobe]
fn kprobe(ctx: ProbeContext) {
    let pid = ctx.pid();
    let comm = ctx.command().unwrap_or([0; 16]);
    let filter_core = unsafe { *CORE.get(0).unwrap_or(&UNSPECIFIED) };
    let current_core = unsafe { bpf_get_smp_processor_id() };
    let capture_stack = unsafe { *STACK.get(0).unwrap_or(&false) };

    if filter_core != UNSPECIFIED && filter_core != current_core {
        return;
    }

    let (kernel_stackid, user_stackid) = if capture_stack {
        (
            unsafe {
                STACKS
                    .get_stackid(&ctx, BPF_F_FAST_STACK_CMP as u64)
                    .unwrap_or(-1) as u32
            },
            u32::MAX,
        )
        //unsafe {
        //    STACKS
        //        .get_stackid(&ctx, (BPF_F_FAST_STACK_CMP|BPF_F_USER_STACK) as u64)
        //        .unwrap_or(-1) as u32
        //})
    } else {
        (u32::MAX, u32::MAX)
    };

    unsafe {
        COMMS.insert(&pid, &comm, 0);
        EVENTS.output(
            &ctx,
            &event {
                pid,
                kernel_stackid,
                user_stackid,
            },
            0,
        );
    }
}

#[tracepoint]
fn tracepoint(ctx: TracePointContext) {
    let pid = ctx.pid();
    let comm = ctx.command().unwrap_or_default();
    let filter_core = unsafe { *CORE.get(0).unwrap_or(&UNSPECIFIED) };
    let current_core = unsafe { bpf_get_smp_processor_id() };
    let capture_stack = unsafe { *STACK.get(0).unwrap_or(&false) };

    if filter_core != UNSPECIFIED && filter_core != current_core {
        return;
    }

    let (kernel_stackid, user_stackid) = if capture_stack {
        (
            unsafe {
                STACKS
                    .get_stackid(&ctx, BPF_F_FAST_STACK_CMP as u64)
                    .unwrap_or(-1) as u32
            },
            unsafe {
                STACKS
                    .get_stackid(&ctx, (BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK) as u64)
                    .unwrap_or(-1) as u32
            },
        )
    } else {
        (u32::MAX, u32::MAX)
    };

    unsafe {
        COMMS.insert(&pid, &comm, 0);
        EVENTS.output(
            &ctx,
            &event {
                pid,
                kernel_stackid,
                user_stackid,
            },
            0,
        );
    }
}
