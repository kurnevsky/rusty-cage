#![allow(dead_code)]

use libc::*;

pub const SECCOMP_RET_KILL: u32 = 0x00000000; // kill the task immediately
pub const SECCOMP_RET_TRAP: u32 = 0x00030000; // disallow and force a SIGSYS
pub const SECCOMP_RET_ERRNO: u32 = 0x00050000; // returns an errno
pub const SECCOMP_RET_TRACE: u32 = 0x7ff00000; // pass to a tracer or disallow
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff0000; // allow

// Instruction classes
pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ST: u16 = 0x02;
pub const BPF_STX: u16 = 0x03;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_MISC: u16 = 0x07;

// ld/ldx fields
pub const BPF_W: u16 = 0x00;
pub const BPF_H: u16 = 0x08;
pub const BPF_B: u16 = 0x10;
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;
pub const BPF_MSH: u16 = 0xa0;

// alu fields
pub const BPF_ADD: u16 = 0x00;
pub const BPF_SUB: u16 = 0x10;
pub const BPF_MUL: u16 = 0x20;
pub const BPF_DIV: u16 = 0x30;
pub const BPF_OR: u16 = 0x40;
pub const BPF_AND: u16 = 0x50;
pub const BPF_LSH: u16 = 0x60;
pub const BPF_RSH: u16 = 0x70;
pub const BPF_NEG: u16 = 0x80;
pub const BPF_MOD: u16 = 0x90;
pub const BPF_XOR: u16 = 0xa0;

// jmp fields
pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;
pub const BPF_K: u16 = 0x00;
pub const BPF_X: u16 = 0x08;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct sock_filter {
  pub code: u16,
  pub jt: u8,
  pub jf: u8,
  pub k: u32,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct sock_fprog {
  pub len: c_ushort,
  pub filter: *const sock_filter,
}
