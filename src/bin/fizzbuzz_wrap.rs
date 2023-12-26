use std::ffi::{CString};
use std::fs::File;
use rand::{random};
use std::{env, io};
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Instant;

fn main() -> io::Result<()> {
    let name = CString::new("fizzbuzz_input").expect("CString::new failed");
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    let mut outfile = unsafe { File::from_raw_fd(fd) };

    let mut child_path = env::current_exe()?;
    child_path.pop();
    child_path.push("fizzbuzz");

    eprintln!("gen integers..");
    for _i in 0..30_000_000 {
        let random_number = random::<u32>();
        let le_bytes = random_number.to_le_bytes();
        outfile.write_all(&le_bytes)?;
    }
    eprintln!("done. forking.");
    let now = Instant::now();
    // Fork a child process
    match unsafe { libc::fork() } {
        -1 => eprintln!("fork failed"),
        0 => {
            eprintln!("child, execing {}...", child_path.display());

            unsafe {
                libc::dup2(fd, libc::STDIN_FILENO);
                libc::close(fd);
            }
            let mut cmd = Command::new(child_path);
            cmd.exec();

            eprintln!("execlp failed");
            std::process::exit(1);
        },
        pid => {
            eprintln!("parent, waiting...");

            let mut status: i32 = 0;
            unsafe {
                libc::waitpid(pid, &mut status, 0);
            }
            let elapsed = now.elapsed();
            eprintln!("Elapsed: {:.2?}", elapsed);
            unsafe { libc::close(fd) };
        }
    }
    Ok(())
}

// SUPPORT CRAP
