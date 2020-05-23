mod errors;

use libc::user_regs_struct;
use log::*;
use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;

use crate::errors::*;

/// Replacement for nanosleep(2).
/// Prototype: int nanosleep(const struct timespec *req, struct timespec *rem);
fn nanosleep_hook(regs: user_regs_struct) -> Result<user_regs_struct> {
    Ok(regs)
}

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

fn sysint(pid: Pid) -> Result<()> {
    waitpid(pid, None)?;
    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_EXITKILL)?;

    loop {
        ptrace::syscall(pid, None)?;
        waitpid(pid, None)?;
        let regs = ptrace::getregs(pid)?;

        debug!("Syscall: {}", regs.orig_rax);

        ptrace::syscall(pid, None)?;
        waitpid(pid, None)?;

        let regs = ptrace::getregs(pid)?;
        debug!("Syscall ret: {}", regs.rax);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::execv;
    use nix::unistd::{fork, ForkResult};
    use std::ffi::CString;

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
