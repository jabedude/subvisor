mod errors;

use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;

use crate::errors::*;

pub fn trace_read(pid: Pid) -> Result<()> {
    ptrace::attach(pid)?;
    waitpid(pid, None)?;
    eprintln!("pid attached !");

    loop {
        // Enter syscall
        ptrace::syscall(pid, None)?;
        waitpid(pid, None)?;
        let regs = ptrace::getregs(pid)?;
        eprintln!(" = {}", regs.rax);

        //if syscall_num == libc::SYS_exit_group.try_into().unwrap() {
        //    eprintln!("{:?} exiting", pid);
        //    return Ok(());
        //}

        // Run syscall and stop on exit
        match ptrace::syscall(pid, None) {
            Err(e) => {
                eprintln!("Err: {:?}", e);
                return Ok(());
            },
            _ => (),
        };
        waitpid(pid, None)?;
        let regs = ptrace::getregs(pid)?;
        eprint!("{}({}, {}, {}, {}, {}, {})", 
                    regs.orig_rax, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9);
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
    fn test_trace_sleep() {

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
