extern crate libc;
extern crate clap;

mod seccomp;

use clap::{Arg, App, SubCommand};

use libc::*;

fn main() {
  let matches = App::new("rusty-cage")
    .version("0.1.0")
    .author("Evgeny Kurnevsky <kurnevsky@gmail.com>")
    .about("Command line tool")
    .subcommand(SubCommand::with_name("seccomp")
                .arg(Arg::with_name("whitelist")
                     .short("w")
                     .long("whitelist")
                     .takes_value(true)
                     .multiple(true))
                .arg(Arg::with_name("blacklist")
                     .short("b")
                     .long("blacklist")
                     .takes_value(true)
                     .multiple(true)))
    .get_matches();
  println!("{:?}", seccomp::acticate())
}
