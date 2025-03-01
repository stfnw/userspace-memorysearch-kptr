// This is a small experiment in probably the dumbest way to search for
// potential kASLR leaks: periodically search all user-space memory for
// 8-byte values that look like potential kernel pointers.
// I expect it to yield lots of false positives and no actual results.
// For educational purposes only.

use std::fs::File;
use std::io::{self, BufRead, Read, Seek, SeekFrom};
use std::str;

const PATTERN_LENGTH: usize = 8; // sizeof(void*)

fn main() -> io::Result<()> {
    // sudo grep -w -e _text -e _etext /proc/kallsyms
    let start: u64 = 0xffffffffb3000000;
    let end: u64 = 0xffffffffb4000000;

    search_memory(PATTERN_LENGTH, |x| start <= x && x <= end)?;
    Ok(())
}

#[derive(Debug)]
struct MemoryRegion {
    start: usize,
    end: usize,
    permissions: String,
    pathname: Option<String>,
}

fn search_memory<T: Fn(u64) -> bool>(chunksize: usize, predicate: T) -> io::Result<()> {
    let regions = read_memory_maps()?;
    let mut mem_file = File::open("/proc/self/mem")?;

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
        let mut buffer = vec![0u8; size];

        mem_file.seek(SeekFrom::Start(region.start as u64))?;
        match mem_file.read_exact(&mut buffer) {
            Ok(_) => {
                // Note: we iterate in *non-overlapping* windows/chunks,
                // because pointers are usually 8-byte-aligned.
                for (pos, chunk) in buffer.chunks_exact(chunksize).enumerate() {
                    let val = u64::from_le_bytes(chunk.try_into().unwrap());
                    if predicate(val) {
                        println!(
                            "0x{:016X} (offset 0x{:08X}): Found pattern 0x{:016x} ({}{})",
                            region.start + pos,
                            pos,
                            val,
                            region.permissions,
                            if let Some(ref p) = region.pathname {
                                format!(", in region {}", p)
                            } else {
                                String::new()
                            }
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("Could not read memory region {:?}: {}", region, e);
            }
        }
    }

    Ok(())
}

fn read_memory_maps() -> io::Result<Vec<MemoryRegion>> {
    let path = "/proc/self/maps";
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    let mut regions = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();

        let address_range: Vec<&str> = parts[0].split('-').collect();
        let start = usize::from_str_radix(address_range[0], 16).unwrap();
        let end = usize::from_str_radix(address_range[1], 16).unwrap();
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
