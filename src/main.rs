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

use std::process::Command;
use clap::{Arg, App, ArgMatches};

fn build_command<'a, T: Iterator<Item = &'a str>>(program: &mut T) -> Command {
  let mut command = Command::new(program.next().expect("")); //TODO msg
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
  let mut command = build_command(&mut matches.values_of("program").expect("")); //TODO msg
  sandbox::Sandbox::new(seccomp_params).run(&mut command);
}
