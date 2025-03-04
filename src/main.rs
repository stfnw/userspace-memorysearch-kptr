// This is a small experiment in probably the dumbest way to search for
// potential kASLR leaks: periodically search all user-space memory for
// 8-byte values that look like potential kernel pointers.
// I expect it to yield lots of false positives and no actual results.
// For educational purposes only.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, Read, Seek, SeekFrom};
use std::path::Path;

const PATTERN_LENGTH: usize = 8; // sizeof(void*)

fn main() {
    let predicate = create_predicate();
    search_memory(PATTERN_LENGTH, predicate);
}

fn create_predicate() -> impl Fn(u64) -> bool {
    // Get start and end of kernel / vmlinux .text section from /proc/kallsysms.
    // These are exposed through the symbols _text and _etext respectively.
    // Access to /proc/kallsyms requires root permissions.
    // sudo grep -w -e _text -e _etext /proc/kallsyms

    let mut vals = Vec::new();
    for line in io::BufReader::new(File::open("/proc/kallsyms").unwrap()).lines() {
        let line = line.unwrap();
        if line.contains("T _text") || line.contains("T _etext") {
            let val = line.split_whitespace().next().unwrap();
            let val = u64::from_str_radix(val, 16).unwrap();
            vals.push(val);
        }
    }

    if vals.len() != 2 || vals[0] == 0 || vals[1] == 0 {
        panic!("Error TODO");
    }

    let start: u64 = vals[0];
    let end: u64 = vals[1];

    move |addr: u64| {
        addr % PATTERN_LENGTH as u64  == 0 // 8-byte-aligned
        && start <= addr && addr <= end // inside vmlinux .text section
    }
}

fn search_memory<T: Fn(u64) -> bool>(chunksize: usize, predicate: T) {
    for entry in fs::read_dir(Path::new("/proc")).unwrap() {
        let path = entry.unwrap().path();

        // Check if the entry is a directory and if its name is a number (PID)
        if path.is_dir() {
            if let Some(pid_) = path.file_name().and_then(|s| s.to_str()) {
                if let Ok(pid) = pid_.parse::<u32>() {
                    if let Err(e) = search_memory_pid(pid, chunksize, &predicate) {
                        match e.kind() {
                            io::ErrorKind::PermissionDenied => println!("PID {}: {:?}", pid, e),
                            _ => panic!("{:?}", e),
                        }
                    }
                }
            }
        }
    }
}


#[derive(Debug)]
struct Match {
    pid: u32,
    uaddr: u64, // Address in userspace.
    kaddr: u64, // Potential kernel address leak.
    regiondesc: String,
}

impl fmt::Display for Match {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Found pattern 0x{:016x} in process PID {:5} at 0x{:016X} ({})",
            self.kaddr, self.pid, self.uaddr, self.regiondesc
        )
    }
}

fn search_memory_pid<T: Fn(u64) -> bool>(
    pid: u32,
    chunksize: usize,
    predicate: T,
) -> io::Result<Vec<Match>> {
    let mut matches = Vec::new();

    let regions = read_memory_maps(pid)?;
    let mut mem_file = File::open(format!("/proc/{pid}/mem"))?;

    for region in regions {
        // Exclude non-readable memory regions.
        if !region.permissions.contains('r') {
            continue;
        }

        // Exclude programs / executable memory regions. This assumes that those do not contain any
        // interesting addresses; we assume interesting addressess are mostly contained in dynamic
        // memory (stack or heap). This assumption may be wrong though.
        if region.permissions.contains('x') && !region.permissions.contains('w') {
            continue;
        }

        // https://lwn.net/Articles/615809/ Implementing virtual system calls.
        // These memory regions somehow cause an error on reading, even thow by page table
        // permissions they are supposed to be readable. => Just exclude them, they probably don't
        // contain anything of interest.
        if let Some(p) = &region.pathname {
            if p.contains("[vdso]") || p.contains("[vvar]") || p.contains("[vvar_vclock]") {
                continue;
            }
        }

        let size = region.end - region.start;
        let mut buffer = vec![0u8; size as usize];

        mem_file.seek(SeekFrom::Start(region.start))?;
        match mem_file.read_exact(&mut buffer) {
            Ok(_) => {
                // Note: we iterate in *non-overlapping* windows/chunks,
                // because pointers are usually 8-byte-aligned.
                for (pos, chunk) in buffer.chunks_exact(chunksize).enumerate() {
                    let val = u64::from_le_bytes(chunk.try_into().unwrap());
                    if predicate(val) {
                        let m = Match {
                            pid,
                            uaddr: region.start + pos as u64,
                            kaddr: val,
                            regiondesc: format!(
                                "{}{}",
                                region.permissions,
                                if let Some(ref p) = region.pathname {
                                    format!(" in region {}", p)
                                } else {
                                    String::new()
                                }
                            ),
                        };
                        println!("{}", m);
                        matches.push(m);
                    }
                }
            }
            Err(e) => {
                eprintln!("Could not read memory region {:?}: {}", region, e);
            }
        }
    }

    Ok(matches)
}

#[derive(Debug)]
struct MemoryRegion {
    start: u64,
    end: u64,
    permissions: String,
    pathname: Option<String>,
}

fn read_memory_maps(pid: u32) -> io::Result<Vec<MemoryRegion>> {
    let path = format!("/proc/{pid}/maps");
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut regions = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();

        let address_range: Vec<&str> = parts[0].split('-').collect();
        let start = u64::from_str_radix(address_range[0], 16).unwrap();
        let end = u64::from_str_radix(address_range[1], 16).unwrap();
        let permissions = parts[1].to_string();
        let pathname = if parts.len() > 5 {
            Some(parts[5..].join(" "))
        } else {
            None
        };

        regions.push(MemoryRegion {
            start,
            end,
            permissions,
            pathname,
        });
    }

    Ok(regions)
}
