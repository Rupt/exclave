// rs.rs — the Rust regressions of PROPOSAL.md 17.4: File::metadata (statx with AT_EMPTY_PATH),
// Command::spawn (clone3 refused, then clone), the F-N12 spawn loop, std::fs on can and host paths, canonicalize.
// Built by the host's rustc against the host's glibc, run inside a can in loader mode.
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::process::Command;

fn main() {
    let mut fails = 0;
    let marker = "/usr/share/exclave-test-marker";
    let m = fs::metadata(marker).expect("metadata by path");
    let f = fs::File::open(marker).expect("open");
    let m2 = f.metadata().expect("metadata by descriptor");
    if m.ino() != m2.ino() || !m.is_file() || m.len() != 7 { fails += 1; println!("FAIL File::metadata differs from metadata by path"); }
    let truep = std::env::var("EXCLAVE_TEST_TRUE").unwrap_or("/usr/bin/true".to_string());
    match Command::new(&truep).status() { Ok(s) if s.success() => {}, other => { fails += 1; println!("FAIL Command::status: {:?}", other); } }
    // F-N12 (review round 1): metadata of an identity file, then a loop of spawns by path and one by PATH; the
    // anomaly seen on the spike was a 127 from the loop
    fs::metadata("/etc/passwd").expect("metadata of an identity file");
    for i in 0..20 {
        match Command::new(&truep).status() { Ok(s) if s.success() => {}, other => { fails += 1; println!("FAIL F-N12 spawn {}: {:?}", i, other); break; } }
    }
    match Command::new("true").status() { Ok(s) if s.success() => {}, other => { fails += 1; println!("FAIL F-N12 spawn by PATH: {:?}", other); } }
    match Command::new("sh").arg("-c").arg("echo spawned $0").output() {
        Ok(o) if o.stdout == b"spawned sh\n" => {}
        other => { fails += 1; println!("FAIL Command::output: {:?}", other.map(|o| String::from_utf8_lossy(&o.stdout).into_owned())); }
    }
    let n = fs::read_dir("/usr/lib/gcc").expect("read_dir").count();
    if n == 0 { fails += 1; println!("FAIL read_dir /usr/lib/gcc empty"); }
    match fs::write("/usr/share/exclave-new", "y") {
        Err(e) if e.raw_os_error() == Some(30) => {}
        other => { fails += 1; println!("FAIL write to the can: {:?}", other); }
    }
    match fs::File::open("/usr/share/nonexistent") {
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        other => { fails += 1; println!("FAIL open of a missing can file: {:?}", other.map(|_| ())); }
    }
    let cwd = std::env::current_dir().expect("cwd");
    let host = cwd.join("rs-host-file");
    fs::write(&host, "host").expect("write to the host");
    if fs::read_to_string(&host).unwrap() != "host" { fails += 1; println!("FAIL host read back"); }
    fs::remove_file(&host).expect("remove host file");
    let sh = std::env::var("EXCLAVE_TEST_SH").unwrap_or("/usr/bin/sh".to_string());
    let sh_exe = std::env::var("EXCLAVE_TEST_SH_EXE").unwrap_or("/usr/bin/dash".to_string());
    match fs::canonicalize(&sh) {
        Ok(p) if p == std::path::Path::new(&sh_exe) => {}
        other => { fails += 1; println!("FAIL canonicalize {}: {:?}", sh, other); }
    }
    match fs::canonicalize("/proc/self/exe") {
        Ok(p) if p.file_name().map(|n| n == "rs").unwrap_or(false) => {}
        other => { fails += 1; println!("FAIL canonicalize /proc/self/exe: {:?}", other); }
    }
    let threads: Vec<_> = (0..8).map(|i| std::thread::spawn(move || { let mut s = 0u64; for k in 0..1000u64 { s += k * i; if k % 100 == 0 { fs::metadata("/usr/share").unwrap(); } } s })).collect();
    for (i, t) in threads.into_iter().enumerate() { if t.join().unwrap() != 499500 * i as u64 { fails += 1; println!("FAIL thread {}", i); } }
    println!("rust: {} failures", fails);
    std::process::exit(if fails > 0 { 1 } else { 0 });
}
