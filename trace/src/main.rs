use aya::{
    maps::{
        hash_map::HashMap,
        perf::{AsyncPerfEventArray, PerfBufferError},
        Array, StackTraceMap,
    },
    programs::KProbe,
    util::{kernel_symbols, online_cpus},
    Bpf, Btf, Pod,
};
use bytes::BytesMut;
use plain::Plain;
use std::{
    convert::{TryFrom, TryInto},
    fmt,
    sync::Arc,
    thread, time,
};
use structopt::StructOpt;
use tokio::task;

#[derive(Debug, StructOpt)]
/// A tool to trace function call
struct Opt {
    #[structopt(short)]
    /// specify the kernel function to trace
    kprobe: Option<String>,

    #[structopt(short)]
    /// only trace on the specified core
    core: Option<u32>,

    #[structopt(short)]
    /// enable callchian dump
    stack: bool,
}

#[derive(Copy, Clone, Debug)]
struct Comm([u8; 16]);

unsafe impl Pod for Comm {}

impl fmt::Display for Comm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = String::from_utf8_lossy(&self.0[..]);
        let s = s.trim_matches(char::from(0));
        write!(f, "{}", s)
    }
}

#[repr(C)]
#[derive(Default)]
struct event {
    pid: u32,
    kernel_stackid: u32,
}
unsafe impl Plain for event {}

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let opt = Opt::from_args();

    let code = include_bytes!("../../target/bpfel-unknown-none/debug/trace-bpf").to_vec();
    let mut bpf = Bpf::load(&code, Btf::from_sys_fs().ok())?;

    // dump
    for (name, map) in bpf.maps() {
        println!(
            "found map `{}` of type `{:?}`",
            name,
            map?.map_type().unwrap()
        );
    }

    for program in bpf.programs() {
        println!(
            "found program `{}` of type `{:?}`",
            program.name(),
            program.prog_type()
        );
    }

    // register callbacks
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    let comms = Arc::new(HashMap::try_from(bpf.map("COMMS")?)?);
    let stacks = Arc::new(StackTraceMap::try_from(bpf.map("STACKS")?)?);
    let ksyms = Arc::new(kernel_symbols()?);

    for cpu_id in online_cpus()? {
        // open a separate perf buffer for each cpu
        let mut buf = perf_array.open(cpu_id, None)?;
        let db = Arc::clone(&comms);
        let stacks = Arc::clone(&stacks);
        let capture_stack = opt.stack;
        let ksyms = Arc::clone(&ksyms);

        // process each perf buffer in a separate task
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(64))
                .collect::<Vec<_>>();

            loop {
                // wait for events
                let events = buf.read_events(&mut buffers).await?;

                // events.read contains the number of events that have been read,
                // and is always <= buffers.len()
                for i in 0..events.read {
                    let buf = &buffers[i];
                    let &event {
                        pid,
                        kernel_stackid,
                    } = event::from_bytes(buf).unwrap();
                    let comm: Comm = unsafe { db.get(&pid, 0).unwrap() };

                    println!("cpu{}: pid({})({}) hit!", cpu_id, pid, comm);
                    if capture_stack && kernel_stackid != 0 {
                        let mut stack_trace = stacks.get(&kernel_stackid, 0).unwrap();

                        for frame in stack_trace.resolve(&ksyms).frames() {
                            println!(
                                "{:#x} {}",
                                frame.ip,
                                frame
                                    .symbol_name
                                    .as_ref()
                                    .unwrap_or(&"[unknown symbol name]".to_owned())
                            );
                        }
                    }
                }
            }

            Ok::<_, PerfBufferError>(())
        });
    }

    // filter core
    let mut core_array = Array::try_from(bpf.map_mut("CORE")?)?;
    let core = opt.core.unwrap_or(1113);
    core_array.set(0, core, 0)?;

    // stacktrace
    let mut stack_array = Array::try_from(bpf.map_mut("STACK")?)?;
    stack_array.set(0, opt.stack as u8, 0)?;

    // attach kprobe
    if let Some(kprobe) = opt.kprobe {
        let prog: &mut KProbe = bpf.program_mut("kprobe")?.try_into()?;
        prog.load()?;
        prog.attach(&kprobe, 0, None)?;
    }

    thread::sleep(time::Duration::from_secs(2));

    Ok(())
}
