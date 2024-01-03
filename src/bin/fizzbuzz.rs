use std::io;
//use std::io::{BufWriter, Write};
use std::io::{Write};
use std::convert::TryInto;
use std::ffi::{c_char, CStr};
//use lexical_core::*;

struct HugePageBufferedWriter<W: Write> {
    buffer: *mut u8,
    capacity: usize,
    position: usize,
    inner: W
}

impl <W: Write> HugePageBufferedWriter<W>  {
    fn new(writer: W) -> io::Result<HugePageBufferedWriter<W>> {
        let size = 2 * 1024 * 1024;
        let buffer = unsafe { mmap_huge_page(size) };

        Ok(HugePageBufferedWriter {
            buffer,
            capacity: size,
            position: 0,
            inner: writer,
        })
    }

    fn write_inner(&mut self) -> io::Result<()> {
        unsafe {
            self.inner.write_all(std::slice::from_raw_parts(self.buffer, self.position))?;
        }
        self.position = 0;

        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.position > 0 {
            self.write_inner()?;
            self.inner.flush()?;
        }

        Ok(())
    }

    #[inline]
    fn write_hot(&mut self, buf: &[u8]) -> io::Result<usize> {
        let to_write = buf.len();
        debug_assert!(to_write <= self.capacity - self.position);
        unsafe {
            std::ptr::copy_nonoverlapping(buf.as_ptr(), self.buffer.add(self.position), to_write);
        }
        self.position += to_write;
        Ok(to_write)
    }

    #[cold]
    #[inline(never)]
    fn write_cold(&mut self, buf: &[u8]) -> io::Result<usize> {
        let space_left = self.capacity - self.position;
        let to_write = buf.len();

        if to_write > space_left {
            self.write_inner()?;
            debug_assert!(to_write <= space_left);
        }
        self.write_hot(buf)
    }
}

impl <W: Write> Write for HugePageBufferedWriter<W> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let space_left = self.capacity - self.position;
        let to_write = buf.len();

        if to_write <= space_left {
            self.write_hot(buf)
        } else {
            self.write_cold(buf)
        }
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let space_left = self.capacity - self.position;
        let to_write = buf.len();

        let written = if to_write <= space_left {
            self.write_hot(buf)
        } else {
            self.write_cold(buf)
        }?;
        debug_assert!(written == to_write);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush()
    }
}

impl <W: Write> Drop for HugePageBufferedWriter<W> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

struct HugePageMMAPWriter {
    buffer: *mut u8,
    capacity: usize,
    position: usize,
    fd: i32,
}

impl HugePageMMAPWriter  {
    fn new() -> io::Result<HugePageMMAPWriter> {
        let buffer = unsafe { mmap_stdout() };

        Ok(HugePageMMAPWriter {
            buffer: buffer.as_mut_ptr(),
            capacity: buffer.len(),
            position: 0,
            fd: 1,
        })
    }

    #[inline(always)]
    fn write_hot(&mut self, buf: &[u8]) {
        let to_write = buf.len();
        debug_assert!(to_write <= self.capacity - self.position);
        unsafe {
            std::ptr::copy_nonoverlapping(buf.as_ptr(), self.buffer.add(self.position), to_write);
        }
        self.position += to_write;
    }

    #[inline]
    fn rest(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(self.buffer.add(self.position), self.capacity - self.position)
        }
    }

    #[inline]
    fn advance(&mut self, written: usize) {
        self.position += written;
    }
}

impl Write for HugePageMMAPWriter {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_hot(buf);
        Ok(buf.len())
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.write_hot(buf);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl Drop for HugePageMMAPWriter {
    fn drop(&mut self) {
        unsafe { ftruncate(self.fd, self.position as i64); }
    }
}

// all this stuff cribbed from lexical-core
macro_rules! index_unchecked {
    ($x:ident[$i:expr]) => {
        *$x.get_unchecked($i)
    };
}

macro_rules! index_unchecked_mut {
    ($x:ident[$i:expr]) => {
        *$x.get_unchecked_mut($i)
    };

    ($x:ident[$i:expr] = $y:ident[$j:expr]) => {
        *$x.get_unchecked_mut($i) = *$y.get_unchecked($j)
    };
}

#[inline]
pub fn fast_log2(x: u32) -> usize {
    (u32::BITS - 1 - (x | 1u32).leading_zeros()) as usize
}

#[inline]
pub fn fast_digit_count(x: u32) -> usize {
    const TABLE: [u64; 32] = [
        4294967296,
        8589934582,
        8589934582,
        8589934582,
        12884901788,
        12884901788,
        12884901788,
        17179868184,
        17179868184,
        17179868184,
        21474826480,
        21474826480,
        21474826480,
        21474826480,
        25769703776,
        25769703776,
        25769703776,
        30063771072,
        30063771072,
        30063771072,
        34349738368,
        34349738368,
        34349738368,
        34349738368,
        38554705664,
        38554705664,
        38554705664,
        41949672960,
        41949672960,
        41949672960,
        42949672960,
        42949672960,
    ];
    // SAFETY: always safe, since fast_log2 will always return a value
    // <= 32. This is because the range of values from `ctlz(x | 1)` is
    // `[0, 31]`, so `32 - 1 - ctlz(x | 1)` must be in the range `[0, 31]`.
    let shift = unsafe { index_unchecked!(TABLE[fast_log2(x)]) };
    let count = (x as u64 + shift) >> 32;
    count as usize
}

pub const DIGIT_TO_BASE10_SQUARED: [u8; 200] = [
    b'0', b'0', b'0', b'1', b'0', b'2', b'0', b'3', b'0', b'4', b'0', b'5', b'0', b'6', b'0', b'7',
    b'0', b'8', b'0', b'9', b'1', b'0', b'1', b'1', b'1', b'2', b'1', b'3', b'1', b'4', b'1', b'5',
    b'1', b'6', b'1', b'7', b'1', b'8', b'1', b'9', b'2', b'0', b'2', b'1', b'2', b'2', b'2', b'3',
    b'2', b'4', b'2', b'5', b'2', b'6', b'2', b'7', b'2', b'8', b'2', b'9', b'3', b'0', b'3', b'1',
    b'3', b'2', b'3', b'3', b'3', b'4', b'3', b'5', b'3', b'6', b'3', b'7', b'3', b'8', b'3', b'9',
    b'4', b'0', b'4', b'1', b'4', b'2', b'4', b'3', b'4', b'4', b'4', b'5', b'4', b'6', b'4', b'7',
    b'4', b'8', b'4', b'9', b'5', b'0', b'5', b'1', b'5', b'2', b'5', b'3', b'5', b'4', b'5', b'5',
    b'5', b'6', b'5', b'7', b'5', b'8', b'5', b'9', b'6', b'0', b'6', b'1', b'6', b'2', b'6', b'3',
    b'6', b'4', b'6', b'5', b'6', b'6', b'6', b'7', b'6', b'8', b'6', b'9', b'7', b'0', b'7', b'1',
    b'7', b'2', b'7', b'3', b'7', b'4', b'7', b'5', b'7', b'6', b'7', b'7', b'7', b'8', b'7', b'9',
    b'8', b'0', b'8', b'1', b'8', b'2', b'8', b'3', b'8', b'4', b'8', b'5', b'8', b'6', b'8', b'7',
    b'8', b'8', b'8', b'9', b'9', b'0', b'9', b'1', b'9', b'2', b'9', b'3', b'9', b'4', b'9', b'5',
    b'9', b'6', b'9', b'7', b'9', b'8', b'9', b'9',
];

pub unsafe fn digit_to_char(digit: u32) -> u8 {
    const TABLE: [u8; 36] = [
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E',
        b'F', b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P', b'Q', b'R', b'S', b'T',
        b'U', b'V', b'W', b'X', b'Y', b'Z',
    ];
    unsafe { *TABLE.get_unchecked(digit as usize) }
}

macro_rules! write_digits {
    ($bytes:ident, $index:ident, $table:ident, $r:ident) => {{
        debug_assert!($index >= 2);
        debug_assert!($bytes.len() >= 2);
        debug_assert!($r + 1 < $table.len());
        $index -= 1;
        unsafe { index_unchecked_mut!($bytes[$index] = $table[$r + 1]) };
        $index -= 1;
        unsafe { index_unchecked_mut!($bytes[$index] = $table[$r]) };
    }};
}

macro_rules! write_digit {
    ($bytes:ident, $index:ident, $r:ident) => {{
        debug_assert!($index >= 1);
        debug_assert!($bytes.len() >= 1);
        debug_assert!($r < 36);
        $index -= 1;
        unsafe { index_unchecked_mut!($bytes[$index]) = digit_to_char($r) };
    }};
}

unsafe fn write_digits(
    mut value: u32,
    radix: u32,
    table: &[u8],
    buffer: &mut [u8],
    mut index: usize,
) -> usize {
    // Pre-compute our powers of radix.
    let radix2 = radix * radix;
    let radix4 = radix2 * radix2;

    // SAFETY: All of these are safe for the buffer writes as long as
    // the buffer is large enough to hold `T::MAX` digits in radix `N`.

    // Decode 4 digits at a time.
    while value >= radix4 {
        let r = value % radix4;
        value /= radix4;
        let r1 = (2u32 * (r / radix2)) as usize;
        let r2 = (2u32 * (r % radix2)) as usize;

        // SAFETY: This is always safe, since the table is 2*radix^2, and
        // r1 and r2 must be in the range [0, 2*radix^2-1), since the maximum
        // value of r is `radix4-1`, which must have a div and r
        // in the range [0, radix^2-1).
        write_digits!(buffer, index, table, r2);
        write_digits!(buffer, index, table, r1);
    }

    // Decode 2 digits at a time.
    while value >= radix2 {
        let r = (2u32 * (value % radix2)) as usize;
        value /= radix2;

        // SAFETY: this is always safe, since the table is 2*radix^2, and
        // r must be in the range [0, 2*radix^2-1).
        write_digits!(buffer, index, table, r);
    }

    // Decode last 2 digits.
    if value < radix {
        // SAFETY: this is always safe, since value < radix, so it must be < 36.
        let r = value;
        write_digit!(buffer, index, r);
    } else {
        let r = (2u32 * value) as usize;
        // SAFETY: this is always safe, since the table is 2*radix^2, and
        // the value must <= radix^2, so rem must be in the range
        // [0, 2*radix^2-1).
        write_digits!(buffer, index, table, r);
    }

    index
}

#[inline]
fn write_int(num: u32, buf: &mut [u8]) -> usize {
    let count = fast_digit_count(num);
    let into = &mut buf[..count];
    unsafe { write_digits(num, 10, &DIGIT_TO_BASE10_SQUARED, into, into.len()) };
    count
}

fn main() -> io::Result<()> {
    let stdin_buf = unsafe { mmap_stdin() };
    //let stdout = io::stdout();
    //let mut writer = BufWriter::with_capacity(128*1024, stdout.lock());
    //let mut writer = HugePageBufferedWriter::new(stdout.lock()).unwrap();
    let mut writer = HugePageMMAPWriter::new().unwrap();
    //let mut buf = [0u8; 10];

    for num in stdin_buf.chunks_exact(4).map(|x| u32::from_le_bytes(x.try_into().unwrap())) {
//    for num in stdin_buf.chunks_exact(4).map(|x| u32::from_le_bytes(unsafe { *(x.as_ptr() as *const [u8; 4]) })) {
        let (fizz, buzz) = (num % 3 == 0, num % 5 == 0);
        if fizz {
            let _ = writer.write_all(b"Fizz");
        }
        if buzz {
            let _ = writer.write_all(b"Buzz");
        }
        if !(fizz | buzz) {
            let written = write_int(num, writer.rest());
            //let written = lexical_core::write(3, writer.rest()).len();
            writer.advance(written);

        }
        let _ = writer.write_all(b"\n");
    }

    Ok(())
}

#[inline]
fn format_int(num: u32, buf: &mut [u8]) -> &[u8] {
    let count = write_int(num, buf);
    &buf[..count]
}

#[test]
fn test_format_int() {


    let mut buf = [0u8; 16];
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
    fn ftruncate(fd: i32, offset: i64) -> i32;
    fn open(path: *const c_char, oflag: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn dup2(fd_src: i32, fd_dest: i32) -> i32;
    fn getpid() -> i32;
}

#[allow(dead_code)]
unsafe fn mmap_stdin<'a>() -> &'a [u8] {
    mmap_fd(0)
}

#[allow(dead_code)]
unsafe fn mmap_stdout<'a>() -> &'a mut [u8] {
    reopen_stdout_rw();
    mmap_fd_expand(1, 1 << 30)
}
#[allow(dead_code)]
unsafe fn mmap_path<'a>(path: &str) -> &'a [u8] {
    let mut path2 = vec![];
    path2.extend_from_slice(path.as_bytes());
    path2.push(0);
    let fd = open(path2.as_ptr() as *const c_char, 0);
    if fd == -1 {
        panic!("open failed, errno {}", std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    mmap_fd(fd)
}

#[cfg(target_os = "linux")]
const MAP_POPULATE: i32 = 0x8000;
#[cfg(target_os = "linux")]
const MAP_ANONYMOUS: i32 = 0x20;
#[cfg(target_os = "linux")]
const MAP_HUGETLB: i32 = 0x040000;
#[cfg(target_os = "linux")]
const VM_FLAGS_SUPERPAGE_SIZE_2MB: i32 = -1;

#[cfg(target_os = "macos")]
const MAP_POPULATE: i32 = 0x0000;
#[cfg(target_os = "macos")]
const MAP_ANONYMOUS: i32 = 0x1000;
#[cfg(target_os = "macos")]
const MAP_HUGETLB: i32 = 0x0000;
#[cfg(target_os = "macos")]
// doesn't seem to work with mmap, maybe try mach_vm_alloc next time
//const VM_FLAGS_SUPERPAGE_SIZE_2MB: i32 = 2 << 16;
const VM_FLAGS_SUPERPAGE_SIZE_2MB: i32 = -1;

#[cfg(target_os = "macos")]
fn get_stdout_path(path_buf: &mut [u8; 4096]) {
    unsafe {
        let f_getpath = 50;
        let stdout = 1;
        let result = fcntl(stdout, f_getpath, path_buf.as_mut_ptr());
        if result == -1 {
            panic!("fcntl failed, errno {}", std::io::Error::last_os_error().raw_os_error().unwrap());
        }
        let path = CStr::from_ptr(path_buf.as_ptr() as *const c_char);
        //eprintln!("here {}", path.to_str().unwrap());
    }
}
#[cfg(target_os = "linux")]
fn get_stdout_path(path_buf: &mut [u8; 4096]) {
    unsafe {
        let pid = getpid();
        let stdout = 1;
        let proc_path = format!("/proc/{}/fd/{}", pid, stdout);
        let bytes = proc_path.as_bytes();
        assert!(bytes.len() < path_buf.len());
        path_buf[..bytes.len()].copy_from_slice(bytes);
        path_buf[bytes.len()] = 0;

        let path = CStr::from_ptr(path_buf.as_ptr() as *const c_char);
        //eprintln!("here {}", path.to_str().unwrap());
    }
}

#[cfg(feature = "reopen_stdout")]
fn reopen_stdout_rw() {
    let mut path_buf = [0u8; 4096];
    unsafe {
        let stdout = 1;
        get_stdout_path(&mut path_buf);

        let o_rdwr = 2;
        let fd = open(path_buf.as_ptr() as *const c_char, o_rdwr);
        if fd == -1 {
            panic!("open failed, errno {}", std::io::Error::last_os_error().raw_os_error().unwrap());
        }
        let fd_new = dup2(fd, stdout);
        if fd_new == -1 {
            panic!("open failed, errno {}", std::io::Error::last_os_error().raw_os_error().unwrap());
        }
        assert!(fd_new == stdout);
    }
}

#[cfg(not(feature = "reopen_stdout"))]
fn reopen_stdout_rw() {
    // not necessary on the highload system?
}

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

unsafe fn mmap_fd_expand<'a>(fd: i32, size: usize) -> &'a mut [u8] {
    let result = ftruncate(fd, size as i64);
    if result == -1 {
        panic!("ftruncate failed, errno {}", std::io::Error::last_os_error().raw_os_error().unwrap());
    }
    let prot_read = 0x01;
    let prot_write = 0x02;
    let map_shared = 0x01;
    let ptr = mmap(0 as _, size as usize, prot_read | prot_write, map_shared, fd, 0);
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
    std::slice::from_raw_parts_mut(ptr, size as usize)
}

unsafe fn mmap_huge_page(size: usize) -> *mut u8 {
    let prot_read = 0x01;
    let prot_write = 0x02;
    let map_private = 0x02;
    let map_anonymous = MAP_ANONYMOUS;
    let map_populate = MAP_POPULATE;
    let map_hugetlb = MAP_HUGETLB;
    let vm_flags_superpage_size_2mb = VM_FLAGS_SUPERPAGE_SIZE_2MB;
    let ptr = mmap(0 as _, size, prot_read | prot_write, map_private | map_anonymous | map_hugetlb | map_populate, vm_flags_superpage_size_2mb, 0);
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
    ptr
}
