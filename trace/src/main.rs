use aya::{
    maps::{
        hash_map::HashMap,
        perf::{AsyncPerfEventArray, PerfBufferError},
        Array,
    },
    programs::KProbe,
    util::online_cpus,
    Bpf, Btf, Pod,
};
use bytes::BytesMut;
use std::{
    convert::{TryFrom, TryInto},
    fmt,
    sync::Arc,
    thread, time,
};
use structopt::StructOpt;
use tokio::task;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(short)]
    kprobe: Option<String>,

    #[structopt(short)]
    core: Option<u32>,
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
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("HIT_PIDS")?)?;
    let comms = Arc::new(HashMap::try_from(bpf.map("COMMS")?)?);

    for cpu_id in online_cpus()? {
        // open a separate perf buffer for each cpu
        let mut buf = perf_array.open(cpu_id, None)?;
        let db = Arc::clone(&comms);

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
                    let pid = u32::from_le_bytes(buf[..4].try_into().unwrap());
                    let comm: Comm = unsafe { db.get(&pid, 0).unwrap() };
                    println!("cpu{}: pid({})({}) hit!", cpu_id, pid, comm);
                }
            }

            Ok::<_, PerfBufferError>(())
        });
    }

    // filter core
    let mut core_array = Array::try_from(bpf.map_mut("CORE")?)?;
    let core = opt.core.unwrap_or(1113);
    core_array.set(0, core, 0)?;

    // attach kprobe
    if let Some(kprobe) = opt.kprobe {
        let prog: &mut KProbe = bpf.program_mut("kprobe")?.try_into()?;
        prog.load()?;
        prog.attach(&kprobe, 0, None)?;
    }

    thread::sleep(time::Duration::from_secs(2));

    Ok(())
}
