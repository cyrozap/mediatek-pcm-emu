/*
 *  pcm-emu.rs - A basic emulator for the MediaTek PCM.
 *  Copyright (C) 2022  Forest Crossman <cyrozap@gmail.com>
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
use mtk_pcm_emu::{ExitReason, IoType};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The byte address to start at in the binary (32-bit aligned).
    #[arg(short, long, default_value_t = String::from("0"))]
    start: String,

    /// The binary to read.
    binary: String,
}

fn handle_io(t: IoType) -> Result<u32, &'static str> {
    match t {
        IoType::MemRead(addr) => match addr {
            // _ => Err("Reading not supported")}; // TODO
            addr => {
                let value = 0;
                eprintln!("0x{:08x} => 0x{:08x}", addr, value);
                Ok(value)
            }
        },
        IoType::MemWrite(addr, value) => match addr {
            0x11002000 => {
                stdout().write(&[(value & 0xff) as u8]).unwrap();
                stdout().flush().unwrap();
                Ok(value)
            }
            // _ => Err("Unsupported write address"),
            _ => {
                eprintln!("0x{:08x} <= 0x{:08x}", addr, value);
                Ok(value)
            }
        },
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

    let mut pcm_core = mtk_pcm_emu::Core::new(start, im);
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
            ExitReason::IO(t) => match handle_io(t) {
                Ok(v) => pcm_core.memory_value = Some(v),
                Err(_) => {
                    eprintln!("Exit at 0x{:04x} due to I/O: {:?}", pcm_core.ip * 4, t);
                    break;
                }
            },
            ExitReason::Halt => {
                eprintln!("Halted before 0x{:04x}", pcm_core.ip * 4);
                break;
            }
        };
    }
    eprintln!("Executed {:?} instructions", pcm_core.instructions_retired);
}
