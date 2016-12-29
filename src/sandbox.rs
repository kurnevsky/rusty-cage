use std::process::Command;
use std::os::unix::process::CommandExt;
use seccomp;

pub struct SeccompParams {
  pub filter_type: seccomp::SeccompFilterType,
  pub syscalls_list: Vec<String>
}

pub struct Sandbox {
  pub seccomp_params: Option<SeccompParams>
}

impl Sandbox {
  pub fn new(seccomp_params: Option<SeccompParams>) -> Sandbox {
    Sandbox {
      seccomp_params: seccomp_params
    }
  }

  pub fn run(&mut self, command: &mut Command) -> Result<(), String> {
    if let Some(ref mut seccomp_params) = self.seccomp_params {
      seccomp_params.syscalls_list.dedup();
      try!(seccomp::activate(seccomp_params.filter_type, &seccomp_params.syscalls_list));
    }
    command.exec(); //TODO: use result
    Ok(())
  }
}
