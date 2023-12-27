use std::io;
use std::io::{BufWriter, Write};

fn format_int(mut num: u32, buf: &mut [u8; 10]) -> &[u8] {
    let mut start = 0;

    for (i, c) in buf.iter_mut().enumerate().rev() {
        let (d, r) = (num / 10, num % 10);
        *c = r as u8 + b'0';
        num = d;
        if num == 0 {
            start = i;
            break;
        }
    }
    &buf[start..10]
}

fn write_int(num: u32, writer: &mut BufWriter<io::StdoutLock>) {
    let mut buf = [0u8; 10];
    let slice = format_int(num, &mut buf);
    writer.write_all(slice).unwrap();
}

// TODO - REPLACE ALL BufWriter WITH CUSTOM ALIGNED HUGE PAGE BUFFER

fn main() -> io::Result<()> {
    let buf = unsafe { mmap_stdin() };
    let stdout = io::stdout();
    let mut writer = BufWriter::with_capacity(128*1024, stdout.lock());

    for buffer in buf.chunks_exact(4).map(|x| x.try_into().unwrap()) {
        let num = u32::from_le_bytes(buffer);
        let fizz = num % 3 == 0;
        let buzz = num % 5 == 0;

        if fizz {
            writer.write_all(b"Fizz").unwrap();
        }
        if buzz {
            writer.write_all(b"Buzz").unwrap();
        }
        if !fizz & !buzz {
            write_int(num, &mut writer);
            //write!(writer, "{}", num).unwrap();
        }

        writer.write_all(b"\n").unwrap();
    }

    Ok(())
}

#[test]
fn test_format_int() {
    let mut buf = [0u8; 10];
    assert_eq!(format_int(0, &mut buf), b"0");
    assert_eq!(format_int(1, &mut buf), b"1");
    assert_eq!(format_int(10, &mut buf), b"10");
    assert_eq!(format_int(100, &mut buf), b"100");
    assert_eq!(format_int(1000, &mut buf), b"1000");
    assert_eq!(format_int(10000, &mut buf), b"10000");
    assert_eq!(format_int(100000, &mut buf), b"100000");
    assert_eq!(format_int(1000000, &mut buf), b"1000000");
    assert_eq!(format_int(10000000, &mut buf), b"10000000");
    assert_eq!(format_int(100000000, &mut buf), b"100000000");
    assert_eq!(format_int(1000000000, &mut buf), b"1000000000");
}

// SUPPORT CRAP

#[link(name = "c")]
extern {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut u8;
    fn madvise(addr: *mut u8, length: usize, advice: i32) -> i32;
    fn lseek(fd: i32, offset: i64, whence: i32) -> i64;
    fn open(path: *const u8, oflag: i32) -> i32;
}

#[allow(dead_code)]
unsafe fn mmap_stdin<'a>() -> &'a [u8] {
    mmap_fd(0)
}

#[allow(dead_code)]
unsafe fn mmap_path<'a>(path: &str) -> &'a [u8] {
    let mut path2 = vec![];
    path2.extend_from_slice(path.as_bytes());
    path2.push(0);
    let fd = open(path2.as_ptr(), 0);
    if fd == -1 {
        panic!("open failed, errno {}", std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    mmap_fd(fd)
}

#[cfg(target_os = "linux")]
const MAP_POPULATE: i32 = 0x8000;

#[cfg(target_os = "macos")]
const MAP_POPULATE: i32 = 0x0000;

unsafe fn mmap_fd<'a>(fd: i32) -> &'a [u8] {
    let seek_end = 2;
    let size = lseek(fd, 0, seek_end);
    //eprintln!("size: {}\n", size);
    if size == -1 {
        panic!("lseek failed, errno {}", std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    let prot_read = 0x01;
    let map_private = 0x02;
    let map_populate = MAP_POPULATE;
    let ptr = mmap(0 as _, size as usize, prot_read, map_private | map_populate, fd, 0);
    if ptr as isize == -1 {
        panic!("mmap failed, errno {}", std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    let madv_sequential = 0x02;
    let r = madvise(ptr, size as usize, madv_sequential);
    if r == -1 {
        panic!("madvise failed, errno {}", std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    let madv_willneed = 0x03;
    let r = madvise(ptr, size as usize, madv_willneed);
    if r == -1 {
        panic!("madvise failed, errno {}", std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    std::slice::from_raw_parts(ptr, size as usize)
}