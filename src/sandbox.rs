use std::process::Command;
use std::os::unix::process::CommandExt;
use seccomp;

pub struct SeccompParams {
  pub filter_type: seccomp::SeccompFilterType,
  pub syscalls_list: Vec<String>
}

pub struct SandboxParams {
  pub seccomp_params: Option<SeccompParams>
}

pub fn run(params: &SandboxParams, command: &mut Command) -> Result<(), String> {
  if let Some(ref seccomp_params) = params.seccomp_params {
    try!(seccomp::activate(seccomp_params.filter_type, &seccomp_params.syscalls_list));
  }
  command.exec(); //TODO: use result
  Ok(())
}
