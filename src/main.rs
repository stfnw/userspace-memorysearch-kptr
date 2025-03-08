// This is a small experiment in probably the dumbest way to search for
// potential kASLR leaks: periodically search all user-space memory for
// 8-byte values that look like potential kernel pointers.
// I expect it to yield lots of false positives and no actual results.
// For educational purposes only.

use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufRead, Read, Seek, SeekFrom};
use std::path::Path;

const PATTERN_LENGTH: usize = 8; // sizeof(void*)

fn main() {
    if cfg!(not(target_os = "linux")) {
        panic!("This program can only run on Linux!");
    }

    let args = parse_args().unwrap();
    let predicate = create_predicate().unwrap();
    search_memory(PATTERN_LENGTH, predicate, args.continuous).unwrap();
}

#[derive(Debug)]
#[allow(dead_code)]
enum SearchError {
    CliArgParseError(String),
    ProcTraversePidsIo(io::Error),
    ProcParseInt {
        file: String,
        val: String,
        err: std::num::ParseIntError,
    },
    ProcParseLine {
        file: String,
        line: String,
    },
    SearchMemIo {
        pid: u32,
        err: io::Error,
    },
    PermissionDeniedKallsyms,
    SearchMemPermissionDeniedPid {
        pid: u32,
        err: io::Error,
    },
}

impl fmt::Display for SearchError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for SearchError {}

type Result<T> = std::result::Result<T, SearchError>;

impl From<(u32, io::Error)> for SearchError {
    fn from(err: (u32, io::Error)) -> SearchError {
        match err.1.kind() {
            io::ErrorKind::PermissionDenied => SearchError::SearchMemPermissionDeniedPid {
                pid: err.0,
                err: err.1,
            },
            _ => SearchError::SearchMemIo {
                pid: err.0,
                err: err.1,
            },
        }
    }
}

#[derive(Debug)]
struct Args {
    continuous: bool,
}

fn parse_args() -> Result<Args> {
    let args: Vec<String> = std::env::args().collect();

    // Default values
    let mut continuous = false;

    for arg in args[1..].iter() {
        match arg.as_ref() {
            "--continuous" => continuous = true,
            _ => {
                return Err(SearchError::CliArgParseError(format!(
                    "Unexpected argument {}",
                    arg
                )))
            }
        }
    }

    Ok(Args { continuous })
}

fn create_predicate() -> Result<impl Fn(u64) -> bool> {
    // Get start and end of kernel / vmlinux .text section from /proc/kallsysms.
    // These are exposed through the symbols _text and _etext respectively.
    // Access to /proc/kallsyms requires root permissions.
    // sudo grep -w -e _text -e _etext /proc/kallsyms

    let mut vals = Vec::new();
    for line in
        io::BufReader::new(File::open("/proc/kallsyms").map_err(SearchError::ProcTraversePidsIo)?)
            .lines()
    {
        let line = line.map_err(SearchError::ProcTraversePidsIo)?;
        if line.contains("T _text") || line.contains("T _etext") {
            let val = line
                .split_whitespace()
                .next()
                .ok_or(SearchError::ProcParseLine {
                    file: "/proc/kallsyms".to_string(),
                    line: line.clone(),
                })?;
            let val = u64::from_str_radix(val, 16).map_err(|e| SearchError::ProcParseInt {
                file: "/proc/kallsyms".to_string(),
                val: val.to_string(),
                err: e,
            })?;
            vals.push(val);
        }
    }

    if vals.len() != 2 || vals[0] == 0 || vals[1] == 0 {
        return Err(SearchError::PermissionDeniedKallsyms);
    }

    let start: u64 = vals[0];
    let end: u64 = vals[1];

    println!(
        "Kernel .text section starts at 0x{:016x} and ends at 0x{:016x}",
        start, end
    );

    Ok(move |addr: u64| {
        addr % PATTERN_LENGTH as u64  == 0 // 8-byte-aligned
        && start <= addr && addr <= end // inside vmlinux .text section
    })
}

#[derive(Debug, Eq, Hash, PartialEq, Clone)]
struct Match {
    pid: u32,
    pname: String,
    uaddr: u64, // Address in userspace.
    kaddr: u64, // Potential kernel address leak.
    regiondesc: String,
}

impl fmt::Display for Match {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Found pattern 0x{:016x} in process {:16} with pid {:7} at 0x{:016X} ({})",
            self.kaddr, self.pname, self.pid, self.uaddr, self.regiondesc
        )
    }
}

fn search_memory<T: Fn(u64) -> bool>(
    chunksize: usize,
    predicate: T,
    continuous: bool,
) -> Result<()> {
    let ownpid = std::process::id();

    let mut matches: HashSet<Match> = HashSet::new();

    loop {
        for entry in fs::read_dir(Path::new("/proc")).map_err(SearchError::ProcTraversePidsIo)? {
            let path = entry.map_err(SearchError::ProcTraversePidsIo)?.path();

            if path.is_dir() {
                if let Some(pid_) = path.file_name().and_then(|s| s.to_str()) {
                    if let Ok(pid) = pid_.parse::<u32>() {
                        // Don't search own process memory.
                        if pid == ownpid {
                            continue;
                        }

                        match search_memory_pid(pid, chunksize, &predicate) {
                            Ok(ms) => {
                                for m in ms {
                                    if continuous {
                                        if matches.contains(&m) {
                                            continue;
                                        } else {
                                            matches.insert(m.clone());
                                        }
                                    }
                                    println!("{}", m);
                                }
                                Ok(())
                            }
                            Err(SearchError::SearchMemPermissionDeniedPid { pid, err }) => {
                                println!("PID {}: {:?}", pid, err);
                                Ok(())
                            }
                            Err(e) => Err(e),
                        }?
                    }
                }
            }
        }

        if !continuous {
            break;
        }
    }

    Ok(())
}

fn search_memory_pid<T: Fn(u64) -> bool>(
    pid: u32,
    chunksize: usize,
    predicate: T,
) -> Result<Vec<Match>> {
    let mut matches = Vec::new();

    let pname = fs::read_to_string(format!("/proc/{pid}/comm")).map_err(|e| (pid, e))?;

    let regions = read_memory_maps(pid)?;
    let mem_file_path = format!("/proc/{pid}/mem");
    let mut mem_file = File::open(mem_file_path).map_err(|e| (pid, e))?;

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

        // Filter special cases on pathname
        if let Some(p) = &region.pathname {
            // https://lwn.net/Articles/615809/ Implementing virtual system calls.
            // These memory regions somehow cause an error on reading, even thow by page table
            // permissions they are supposed to be readable. => Just exclude them, they probably don't
            // contain anything of interest.
            if p == "[vdso]" || p == "[vvar]" || p == "[vvar_vclock]" {
                continue;
            }

            if p.starts_with("/dev/dri/") && region.permissions == "rw-s" {
                continue;
            }
        }

        let size = region.end - region.start;
        let mut buffer = vec![0u8; size as usize];

        mem_file
            .seek(SeekFrom::Start(region.start))
            .map_err(|e| (pid, e))?;
        match mem_file.read_exact(&mut buffer) {
            Ok(_) => {
                // Note: we iterate in *non-overlapping* windows/chunks,
                // because pointers are usually 8-byte-aligned.
                for (pos, chunk) in buffer.chunks_exact(chunksize).enumerate() {
                    let val = u64::from_le_bytes(chunk.try_into().unwrap());
                    if predicate(val) {
                        let m = Match {
                            pid,
                            pname: pname.trim().to_string(),
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

fn read_memory_maps(pid: u32) -> Result<Vec<MemoryRegion>> {
    let path = format!("/proc/{pid}/maps");
    let file = File::open(path.clone()).map_err(|e| (pid, e))?;
    let reader = io::BufReader::new(file);

    let mut regions = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|e| (pid, e))?;
        let parts: Vec<&str> = line.split_whitespace().collect();

        let address_range: Vec<&str> = parts[0].split('-').collect();
        let start =
            u64::from_str_radix(address_range[0], 16).map_err(|err| SearchError::ProcParseInt {
                file: path.clone(),
                val: address_range[0].to_string(),
                err,
            })?;
        let end =
            u64::from_str_radix(address_range[1], 16).map_err(|err| SearchError::ProcParseInt {
                file: path.clone(),
                val: address_range[0].to_string(),
                err,
            })?;
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
