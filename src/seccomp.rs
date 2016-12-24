use libc::*;
use seccomp_vm::*;

const PR_SET_SECCOMP: c_int = 22;
const PR_SET_NO_NEW_PRIVS: c_int = 38;

const SECCOMP_MODE_FILTER: c_ulong = 2;

pub fn acticate() -> Result<(), String> {
  let set_no_new_privs_result = unsafe {
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
  };
  if set_no_new_privs_result != 0 {
    return Err(format!("Failed to set NO_NEW_PRIVS flag with status: {}", set_no_new_privs_result));
  }
  let vec = vec!(
    sock_filter {
      code: 0,
      jt: 0,
      jf: 0,
      k: 1,
    }
  );
  let prog = sock_fprog {
    len: vec.len() as c_ushort,
    filter: vec.as_ptr(),
  };
  let set_seccomp_result = unsafe {
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog as *const sock_fprog as c_ulong, !0, 0)
  };
  if set_seccomp_result != 0 {
    return Err(format!("Failed to set seccomp filter with status: {}", set_seccomp_result));
  }
  Ok(())
}
