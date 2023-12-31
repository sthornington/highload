use std::io;
//use std::io::{BufWriter, Write};
use std::io::{Write};
use std::convert::TryInto;
use std::ffi::{c_char, CStr};

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
    cursor: *mut u8,
    fd: i32,
}

impl HugePageMMAPWriter  {
    fn new() -> io::Result<HugePageMMAPWriter> {
        let buffer = unsafe { mmap_stdout() };

        Ok(HugePageMMAPWriter {
            buffer: buffer.as_mut_ptr(),
            capacity: buffer.len(),
            cursor: buffer.as_mut_ptr(),
            fd: 1,
        })
    }

    #[inline]
    fn write_hot(&mut self, buf: &[u8]) {
        let to_write = buf.len();
        unsafe {
            debug_assert!(to_write <= (self.capacity - self.cursor.offset_from(self.buffer) as usize));
            std::ptr::copy_nonoverlapping(buf.as_ptr(), self.cursor, to_write);
            self.cursor = self.cursor.add(to_write);
        }
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
        unsafe { ftruncate(self.fd, self.cursor.offset_from(self.buffer) as i64); }
    }
}

#[inline]
fn format_int(mut num: u32, buf: &mut [u8; 16]) -> usize {
    let mut start = 0;

    for (i, c) in buf.iter_mut().enumerate().rev() {
        let (d, r) = (num / 10, num % 10);
        *c = r as u8 + b'0';
        num = d;
        if d == 0 {
            start = i;
            break;
        }
    }
    start
}

#[inline]
fn write_int(num: u32, buf: &mut [u8; 16], writer: &mut impl Write) {
    let start = format_int(num, buf);
    writer.write_all(&buf[start..]).unwrap();
}

#[repr(align(128))]
struct AlignedCharArray {
    array: [u8; 16],
}

fn main() -> io::Result<()> {
    let stdin_buf = unsafe { mmap_stdin() };
    //let stdout = io::stdout();
    //let mut writer = BufWriter::with_capacity(128*1024, stdout.lock());
    //let mut writer = HugePageBufferedWriter::new(stdout.lock()).unwrap();
    let mut writer = HugePageMMAPWriter::new().unwrap();
    let mut buf = AlignedCharArray { array: [0u8; 16] };
    //let mut buf = [0u8; 10];

//    for num in stdin_buf.chunks_exact(4).map(|x| u32::from_le_bytes(x.try_into().unwrap())) {
    for num in stdin_buf.chunks_exact(4).map(|x| u32::from_le_bytes(unsafe { *(x.as_ptr() as *const [u8; 4]) })) {
        let fizz = num % 3 == 0;
        let buzz = num % 5 == 0;

        if fizz {
            writer.write_all(b"Fizz").unwrap();
        }
        if buzz {
            writer.write_all(b"Buzz").unwrap();
        }
        if !fizz & !buzz {
            write_int(num, &mut buf.array, &mut writer);
            //write!(writer, "{}", num).unwrap();
        }

        writer.write_all(b"\n").unwrap();
    }

    Ok(())
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
    mmap_fd_expand(1, 1 << 29)
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