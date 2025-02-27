// This is a small experiment in probably the dumbest way to search for
// potential kASLR leaks: periodically search all user-space memory for
// 8-byte values that look like potential kernel pointers.
// I expect it to yield lots of false positives and no actual results.
// For educational purposes only.

use std::fs::File;
use std::io::{self, BufRead, Read, Seek, SeekFrom};
use std::str;

fn main() -> io::Result<()> {
    let pattern = b"pattern_to_search"; // TODO
    search_memory(pattern)?;
    Ok(())
}

#[derive(Debug)]
struct MemoryRegion {
    start: usize,
    end: usize,
    permissions: String,
    pathname: Option<String>,
}

fn search_memory(pattern: &[u8]) -> io::Result<()> {
    let regions = read_memory_maps()?;
    let mut mem_file = File::open("/proc/self/mem")?;

    for region in regions {
        if !region.permissions.contains('r') {
            continue;
        }

        // https://lwn.net/Articles/615809/ Implementing virtual system calls
        if let Some(p) = &region.pathname {
            if p.contains("[vdso]") || p.contains("[vvar]") {
                continue;
            }
        }

        let size = region.end - region.start;
        let mut buffer = vec![0u8; size];

        mem_file.seek(SeekFrom::Start(region.start as u64))?;
        match mem_file.read_exact(&mut buffer) {
            Ok(_) => {
                if let Some(pos) = buffer
                    .windows(pattern.len())
                    .position(|window| window == pattern)
                {
                    println!(
                        "Found pattern at address: 0x{:x}{}",
                        region.start + pos,
                        if let Some(p) = region.pathname {
                            format!("(in region {})", p)
                        } else {
                            String::new()
                        }
                    );
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
