use aya::Bpf;

fn main() -> anyhow::Result<()> {
    let mut bpf = Bpf::load_file("../target/bpfel-unknown-none/debug/kernel").or_else(|e| {
        println!("errno: {}", std::io::Error::last_os_error());
        Err(e)
    })?;

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


    Ok(())
}
