#![feature(plugin)]
#![plugin(phf_macros)]

extern crate libc;
extern crate clap;
#[macro_use]
extern crate cfg_if;
extern crate phf;

mod syscall;
mod seccomp_vm;
mod seccomp;
mod sandbox;

use std::panic;
use std::process::Command;
use clap::{Arg, App, ArgMatches};

fn build_command<'a, T: Iterator<Item = &'a str>>(program: &mut T) -> Command {
  let mut command = Command::new(program.next().expect("program: at least one element is expected"));
  while let Some(arg) = program.next() {
    command.arg(arg);
  }
  command
}

fn parse_seccomp_params(matches: &ArgMatches) -> Option<sandbox::SeccompParams> {
  if let Some(seccomp_whitelist) = matches.values_of("seccomp-whitelist") {
    Some(sandbox::SeccompParams {
      filter_type: seccomp::SeccompFilterType::Whitelist,
      syscalls_list: seccomp_whitelist.map(|p| p.to_owned()).collect()
    })
  } else if let Some(seccomp_blacklist) = matches.values_of("seccomp-blacklist") {
    Some(sandbox::SeccompParams {
      filter_type: seccomp::SeccompFilterType::Blacklist,
      syscalls_list: seccomp_blacklist.map(|p| p.to_owned()).collect()
    })
  } else {
    None
  }
}

fn print_seccomp_panic_msg(seccomp_panic: &seccomp::SeccompPanic) {
  match *seccomp_panic {
    seccomp::SeccompPanic::SetNoNewPrivsFailed(code) => println!("Failed to set NO_NEW_PRIVS flag with status: {}", code),
    seccomp::SeccompPanic::SetDumpableFlagFailed(code) => println!("Failed to set DUMPABLE flag with status: {}", code),
    seccomp::SeccompPanic::SetSeccompFilterFailed(code) => println!("Failed to set seccomp filter with status: {}", code),
    seccomp::SeccompPanic::UnknownSyscallName(ref syscall) => println!("Unknown syscall name: {}", syscall)
  }
}

fn set_panic_hook() {
  let default_hook = panic::take_hook();
  panic::set_hook(Box::new(move |panic_info| {
    let payload = panic_info.payload();
    if let Some(seccomp_panic) = payload.downcast_ref::<seccomp::SeccompPanic>() {
      print_seccomp_panic_msg(seccomp_panic);
    } else {
      default_hook(panic_info);
    }
  }));
}

fn main() {
  let matches = App::new("rusty-cage")
    .version("0.1.0")
    .author("Evgeny Kurnevsky <kurnevsky@gmail.com>")
    .about("Command line tool")
    .arg(Arg::with_name("seccomp-whitelist")
         .long("seccomp-whitelist")
         .conflicts_with("blacklist")
         .value_delimiter(",")
         .multiple(true))
    .arg(Arg::with_name("seccomp-blacklist")
         .long("seccomp-blacklist")
         .conflicts_with("seccomp-whitelist")
         .value_delimiter(",")
         .multiple(true))
    .arg(Arg::with_name("program")
         .required(true)
         .multiple(true))
    .get_matches();
  let seccomp_params = parse_seccomp_params(&matches);
  let mut command = build_command(&mut matches.values_of("program").expect("program expected"));
  set_panic_hook();
  sandbox::Sandbox::new(seccomp_params).run(&mut command);
}
