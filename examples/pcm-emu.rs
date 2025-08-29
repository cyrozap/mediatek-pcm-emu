/*
 *  pcm-emu.rs - A basic emulator for the MediaTek PCM.
 *  Copyright (C) 2022-2023  Forest Crossman <cyrozap@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use std::fs;
use std::io::{Write, stdout};
use std::time::Instant;

use clap::Parser;

use mtk_pcm_emu::{Core, ExitReason, IM_SIZE, Register};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The byte address to start at in the binary (32-bit aligned).
    #[arg(short, long, default_value_t = String::from("0"))]
    start: String,

    /// The binary to read.
    binary: String,
}

fn handle_mem_read(_core: &mut Core, addr: u32) -> Result<u32, ExitReason> {
    let value = 0;
    eprintln!("0x{:08x} => 0x{:08x}", addr, value);
    Ok(value)
}

fn handle_mem_write(_core: &mut Core, addr: u32, value: u32) -> Option<ExitReason> {
    match addr {
        0x11002000 => {
            stdout().write_all(&[(value & 0xff) as u8]).unwrap();
            stdout().flush().unwrap();
            None
        }
        _ => {
            eprintln!("0x{:08x} <= 0x{:08x}", addr, value);
            None
        }
    }
}

fn main() {
    let args = Args::parse();

    let start = match u16::from_str_radix(args.start.trim_start_matches("0x"), 16) {
        Ok(v) => v / 4,
        Err(error) => {
            eprintln!(
                "Failed to parse start address {:?}: {:?}",
                &args.start, error
            );
            return;
        }
    };

    let binary = match fs::read(&args.binary) {
        Ok(f) => f,
        Err(error) => {
            eprintln!("Error opening file {:?}: {:?}", &args.binary, error);
            return;
        }
    };

    let mut im: [u32; IM_SIZE] = [0; IM_SIZE];
    for (i, chunk) in binary.chunks_exact(4).enumerate() {
        im[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    let mut pcm_core = Core::new(
        im,
        None,
        None,
        Some(handle_mem_read),
        Some(handle_mem_write),
    );

    pcm_core.goto(start);

    let start = Instant::now();
    let reason = pcm_core.run();
    let elapsed = start.elapsed();

    match reason {
        ExitReason::Invalid(ip, instr) => {
            eprintln!(
                "Invalid instruction at 0x{:04x}: 0x{:08x}",
                ip * 4,
                instr.word
            );
        }
        ExitReason::IOErr(ip, t) => {
            eprintln!("Exit at 0x{:04x} due to I/O error: {:?}", ip * 4, t);
        }
        ExitReason::Halt(ip) => {
            eprintln!("Halted at 0x{:04x}", ip * 4);
        }
    };

    let instructions_retired = pcm_core.get_instructions_retired();
    let ips = (instructions_retired as u128) * 1_000_000_000 / elapsed.as_nanos();
    eprintln!(
        "Executed {:?} instructions in {}.{:06} seconds ({} instructions per second)",
        instructions_retired,
        elapsed.as_secs(),
        elapsed.subsec_micros(),
        ips,
    );

    for i in (0..16).step_by(4) {
        let mut register_strings: [String; 4] =
            [String::new(), String::new(), String::new(), String::new()];
        for (j, s) in register_strings.iter_mut().enumerate() {
            let reg_idx = (i + j) as u8;
            let reg = Register::from_index(reg_idx).unwrap();
            *s = format!("R{}: 0x{:08x}", reg_idx, pcm_core.reg_read(reg));
        }
        eprintln!("{}", register_strings.join(", "));
    }
}
