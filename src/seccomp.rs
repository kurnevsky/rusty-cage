use libc::*;
use seccomp_vm::*;
use syscall::*;

const PR_SET_SECCOMP: c_int = 22;
const PR_SET_NO_NEW_PRIVS: c_int = 38;

const SECCOMP_MODE_FILTER: c_ulong = 2;

#[derive(Clone, Copy, Debug)]
pub enum SeccompFilterType {
  Whitelist,
  Blacklist
}

fn set_no_new_privs() -> Result<(), String> {
  let result = unsafe {
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
  };
  if result == 0 {
    Ok(())
  } else {
    Err(format!("Failed to set NO_NEW_PRIVS flag with status: {}", result))
  }
}

fn build_program(filter_type: SeccompFilterType, syscalls_list: &[String]) -> Result<Vec<sock_filter>, String> {
  let (inner_ret, outer_ret) = match filter_type {
    SeccompFilterType::Whitelist => (SECCOMP_RET_ALLOW, SECCOMP_RET_KILL),
    SeccompFilterType::Blacklist => (SECCOMP_RET_KILL, SECCOMP_RET_ALLOW)
  };
  let mut result = Vec::with_capacity(syscalls_list.len() * 2 + 2);
  // load the syscall number
  result.push(sock_filter { code: BPF_LD + BPF_W + BPF_ABS, jt: 0, jf: 0, k: 0 });
  for syscall in syscalls_list {
    let number = try!(SYSCALLS.get(syscall.as_str()).cloned().ok_or_else(|| format!("Unknown syscall name: {}", syscall)));
    result.push(sock_filter { code: BPF_JMP + BPF_JEQ + BPF_K, jt: 0, jf: 1, k: number });
    result.push(sock_filter { code: BPF_RET + BPF_K, jt: 0, jf: 0, k: inner_ret });
  }
  result.push(sock_filter { code: BPF_RET + BPF_K, jt: 0, jf: 0, k: outer_ret });
  Ok(result)
}

fn set_seccomp_filter(filter_type: SeccompFilterType, syscalls_list: &[String]) -> Result<(), String> {
  let cmds = try!(build_program(filter_type, syscalls_list));
  let prog = sock_fprog {
    len: cmds.len() as c_ushort,
    filter: cmds.as_ptr(),
  };
  let result = unsafe {
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog as *const sock_fprog as c_ulong)
  };
  if result == 0 {
    Ok(())
  } else {
    Err(format!("Failed to set seccomp filter with status: {}", result))
  }
}

pub fn acticate(filter_type: SeccompFilterType, syscalls_list: &[String]) -> Result<(), String> {
  try!(set_no_new_privs());
  set_seccomp_filter(filter_type, syscalls_list)
}
