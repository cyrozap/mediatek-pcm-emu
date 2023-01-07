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
use std::io::{stdout, Write};

use clap::Parser;

use mtk_pcm_emu;
use mtk_pcm_emu::{Core, ExitReason};

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
            stdout().write(&[(value & 0xff) as u8]).unwrap();
            stdout().flush().unwrap();
            None
        }
        _ => {
            eprintln!("0x{:08x} <= 0x{:08x}", addr, value);
            None
        }
    }
}

fn get_u32_from_im(im: [u8; 1 << 15], addr: u16) -> u32 {
    ((im[(addr as usize) + 3] as u32) << 24)
        | ((im[(addr as usize) + 2] as u32) << 16)
        | ((im[(addr as usize) + 1] as u32) << 8)
        | (im[(addr as usize) + 0] as u32)
}

fn main() {
    let args = Args::parse();

    let start = match u16::from_str_radix((&args.start).trim_start_matches("0x"), 16) {
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

    let mut im: [u8; 1 << 15] = [0; 1 << 15];
    for (i, b) in binary.iter().enumerate() {
        if i >= im.len() {
            break;
        }
        im[i] = *b;
    }

    let mut pcm_core = mtk_pcm_emu::Core::new(
        start,
        im,
        None,
        None,
        Some(handle_mem_read),
        Some(handle_mem_write),
    );
    loop {
        match pcm_core.run() {
            ExitReason::Invalid(instr) => {
                eprintln!(
                    "Invalid instruction at 0x{:04x}: 0x{:08x} ({:?})",
                    pcm_core.ip * 4,
                    get_u32_from_im(pcm_core.im, pcm_core.ip * 4),
                    instr
                );
                break;
            }
            ExitReason::IOErr(t) => {
                eprintln!(
                    "Exit at 0x{:04x} due to I/O error: {:?}",
                    pcm_core.ip * 4,
                    t
                );
                break;
            }
            ExitReason::Halt => {
                eprintln!("Halted before 0x{:04x}", pcm_core.ip * 4);
                break;
            }
        };
    }
    eprintln!("Executed {:?} instructions", pcm_core.instructions_retired);
}
