mod errors;

use libc::user_regs_struct;
use log::*;
use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use nix::sys::uio::{IoVec, RemoteIoVec, process_vm_readv};

use crate::errors::*;

pub fn trace_read(pid: Pid) -> Result<()> {
    ptrace::attach(pid)?;
    waitpid(pid, None)?;
    debug!("pid attached !");

    loop {
        // Enter syscall
        ptrace::syscall(pid, None)?;
        waitpid(pid, None)?;
        let regs = ptrace::getregs(pid)?;
        let return_val = regs.rax;

        //if syscall_num == libc::SYS_exit_group.try_into().unwrap() {
        //    eprintln!("{:?} exiting", pid);
        //    return Ok(());
        //}

        // Run syscall and stop on exit
        match ptrace::syscall(pid, None) {
            Err(e) => {
                error!("Err: {:?}", e);
                return Ok(());
            },
            _ => (),
        };

        waitpid(pid, None)?;
        let regs = ptrace::getregs(pid)?;
        debug!("{}({}, {}, {}, {}, {}, {})={}",
                    regs.orig_rax, regs.rdi, regs.rsi,
                    regs.rdx, regs.r10, regs.r8, regs.r9,
                    return_val);
    }
}

/*
 * * Registers on entry:
 * rax  system call number
 * rcx  return address
 * r11  saved rflags (note: r11 is callee-clobbered register in C ABI)
 * rdi  arg0
 * rsi  arg1
 * rdx  arg2
 * r10  arg3 (needs to be moved to rcx to conform to C ABI)
 * r8   arg4
 * r9   arg5
 * (note: r12-r15, rbp, rbx are callee-preserved in C ABI)
 */

/// Hook for nanosleep(2).
///
/// Prototype: int nanosleep(const struct timespec *req, struct timespec *rem);
fn nanosleep_hook(pid: Pid, regs: &mut user_regs_struct) -> Result<()> {
    let mut buf = [0u8; std::mem::size_of::<libc::timespec>()];
    let remote_iov = RemoteIoVec {
                        base: regs.rdi as usize,
                        len: std::mem::size_of::<libc::timespec>()
                    };
    debug!("nanosleep arg 1: 0x{:x}", regs.rdi);
    let ret = process_vm_readv(pid,
                               &[IoVec::from_mut_slice(&mut buf)],
                               &[remote_iov])?;
    debug!("readv ret: {}", ret);
    let s = buf.as_ptr() as *mut libc::timespec;

    unsafe {
        debug!("nanosleep called for {} seconds and {} nanoseconds", (*s).tv_sec, (*s).tv_nsec);
    }

    Ok(())
}

/// Hook for socket(2).
///
/// int socket(int domain, int type, int protocol);
fn socket_hook(pid: Pid, regs: &mut user_regs_struct) -> Result<()> {
    debug!("socket arg 1: 0x{:x}", regs.rdi);
    debug!("socket arg 2: 0x{:x}", regs.rsi);
    debug!("socket arg 3: 0x{:x}", regs.rdx);

    Ok(())
}

/// Hook for read(2).
///
/// ssize_t read(int fd, void *buf, size_t count);
fn read_hook(pid: Pid, regs: &mut user_regs_struct) -> Result<()> {
    debug!("read arg 1: 0x{:x}", regs.rdi);
    debug!("read arg 2: 0x{:x}", regs.rsi);
    debug!("read arg 3: 0x{:x}", regs.rdx);

    Ok(())
}

/// Hook for openat(2).
///
/// int openat(int dirfd, const char *pathname, int flags);
fn openat_hook(pid: Pid, regs: &mut user_regs_struct) -> Result<()> {
    debug!("openat arg 1: 0x{:x}", regs.rdi);
    debug!("openat arg 2: 0x{:x}", regs.rsi);
    debug!("openat arg 3: 0x{:x}", regs.rdx);

    Ok(())
}

/// Hook for write(2).
///
/// ssize_t write(int fd, const void *buf, size_t count);
fn write_hook(pid: Pid, regs: &mut user_regs_struct) -> Result<()> {
    debug!("write arg 1: 0x{:x}", regs.rdi);
    debug!("write arg 2: 0x{:x}", regs.rsi);
    debug!("write arg 3: 0x{:x}", regs.rdx);

    Ok(())
}

fn sysint(pid: Pid) -> Result<()> {
    waitpid(pid, None)?;
    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_EXITKILL)?;

    loop {
        ptrace::syscall(pid, None)?;
        waitpid(pid, None)?;
        let mut regs = ptrace::getregs(pid)?;

        debug!("Syscall: {}", regs.orig_rax);
        if regs.orig_rax == 35 {
            nanosleep_hook(pid, &mut regs)?;
        } else if regs.orig_rax == 41 {
            socket_hook(pid, &mut regs)?;
        } else if regs.orig_rax == 257 {
            openat_hook(pid, &mut regs)?;
        } else if regs.orig_rax == 1 {
            write_hook(pid, &mut regs)?;
        } else if regs.orig_rax == 60 {
            // Exit
            return Ok(());
        }

        ptrace::syscall(pid, None)?;
        waitpid(pid, None)?;

        let regs = ptrace::getregs(pid)?;
        debug!("Syscall ret: {}", regs.rax);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::execv;
    use nix::unistd::{fork, ForkResult};
    use std::ffi::CString;

    #[test]
    fn test_sysint_cat() {
        env_logger::init();

        match fork() {
            Ok(ForkResult::Parent { child, .. }) => {
                let res = sysint(child);
                //eprintln!("{:?}", res);
                //kill(child, Some(Signal::SIGKILL)).unwrap();
            }
            Ok(ForkResult::Child) => {
                nix::sys::ptrace::traceme().expect("traceme");
                //kill(nix::unistd::getpid(), Some(Signal::SIGSTOP)).unwrap();
                execv(
                    &CString::new("./cat").unwrap(),
                    &[
                        &CString::new("./nc").unwrap(),
                        &CString::new("README.md").unwrap(),
                    ],
                )
                .unwrap();
            }
            Err(_) => panic!("Fork failed"),
        }
    }

    #[test]
    fn test_sysint_socket() {
        env_logger::init();

        match fork() {
            Ok(ForkResult::Parent { child, .. }) => {
                let res = sysint(child);
                //eprintln!("{:?}", res);
                kill(child, Some(Signal::SIGKILL)).unwrap();
            }
            Ok(ForkResult::Child) => {
                nix::sys::ptrace::traceme().expect("traceme");
                //kill(nix::unistd::getpid(), Some(Signal::SIGSTOP)).unwrap();
                execv(
                    &CString::new("./nc").unwrap(),
                    &[
                        &CString::new("./nc").unwrap(),
                        &CString::new("127.0.0.1").unwrap(),
                        &CString::new("8080").unwrap(),
                    ],
                )
                .unwrap();
            }
            Err(_) => panic!("Fork failed"),
        }
    }

    #[test]
    fn test_sysint() {
        env_logger::init();

        match fork() {
            Ok(ForkResult::Parent { child, .. }) => {
                let res = sysint(child);
                //eprintln!("{:?}", res);
                kill(child, Some(Signal::SIGKILL)).unwrap();
            }
            Ok(ForkResult::Child) => {
                nix::sys::ptrace::traceme().expect("traceme");
                //kill(nix::unistd::getpid(), Some(Signal::SIGSTOP)).unwrap();
                execv(
                    &CString::new("./tests/test_prog").unwrap(),
                    &[
                        &CString::new("./tests/test_prog").unwrap(),
                    ],
                )
                .unwrap();
            }
            Err(_) => panic!("Fork failed"),
        }
    }

    #[test]
    fn test_trace_sleep() {
        env_logger::init();

        match fork() {
            Ok(ForkResult::Parent { child, .. }) => {
                let res = trace_read(child);
                //eprintln!("{:?}", res);
                kill(child, Some(Signal::SIGKILL)).unwrap();
            }
            Ok(ForkResult::Child) => {
                execv(
                    &CString::new("./tests/test_prog").unwrap(),
                    &[
                        &CString::new("./tests/test_prog").unwrap(),
                    ],
                )
                .unwrap();
            }
            Err(_) => panic!("Fork failed"),
        }
    }
}
