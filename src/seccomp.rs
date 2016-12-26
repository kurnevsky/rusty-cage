use libc::*;
use seccomp_vm::*;

const PR_SET_SECCOMP: c_int = 22;
const PR_SET_NO_NEW_PRIVS: c_int = 38;

const SECCOMP_MODE_FILTER: c_ulong = 2;

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

fn build_program() -> Vec<sock_filter> {
  vec!(
    sock_filter {
      code: 0,
      jt: 0,
      jf: 0,
      k: 1,
    }
  )
}

fn set_seccomp_filter() -> Result<(), String> {
  let cmds = build_program();
  let prog = sock_fprog {
    len: cmds.len() as c_ushort,
    filter: cmds.as_ptr(),
  };
  let result = unsafe {
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog as *const sock_fprog as c_ulong, !0, 0)
  };
  if result == 0 {
    Ok(())
  } else {
    Err(format!("Failed to set seccomp filter with status: {}", result))
  }
}

pub fn acticate() -> Result<(), String> {
  try!(set_no_new_privs());
  set_seccomp_filter()
}
