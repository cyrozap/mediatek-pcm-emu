/*
 *  src/lib.rs - Emulator core for MediaTek PCM.
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

#[derive(Debug, Copy, Clone)]
pub enum Register {
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    R31,
}

#[derive(Debug, Copy, Clone)]
pub enum IoType {
    MemRead(u32),
    MemWrite(u32, u32),
}

pub enum ExitReason {
    IO(IoType),
    Halt,
    Invalid(Instruction),
}

#[derive(Debug)]
pub struct Instruction {
    op3128: u8,
    op2727: bool,
    rd: u8,
    inv: bool,
    shl: bool,
    sh: u8,
    rxryrs: u16,
    rxry: u16,
    rx: u8,
    ry: u8,
    rs: u8,
}

impl Instruction {
    fn from_u32(v: u32) -> Self {
        Self {
            op3128: (v >> 28) as u8,
            op2727: ((v >> 27) & 1) != 0,
            rd: ((v >> 22) & 0x1F) as u8,
            inv: ((v >> 21) & 1) != 0,
            shl: ((v >> 20) & 1) != 0,
            sh: ((v >> 15) & 0x1F) as u8,
            rxryrs: (v & 0x7FFF) as u16,
            rxry: ((v >> 5) & 0x3FF) as u16,
            rx: ((v >> 10) & 0x1F) as u8,
            ry: ((v >> 5) & 0x1F) as u8,
            rs: (v & 0x1F) as u8,
        }
    }
}

fn get_index_for_reg(reg: Register) -> usize {
    match reg {
        Register::R0 => 0,
        Register::R1 => 1,
        Register::R2 => 2,
        Register::R3 => 3,
        Register::R4 => 4,
        Register::R5 => 5,
        Register::R6 => 6,
        Register::R7 => 7,
        Register::R8 => 8,
        Register::R9 => 9,
        Register::R10 => 10,
        Register::R11 => 11,
        Register::R12 => 12,
        Register::R13 => 13,
        Register::R14 => 14,
        Register::R15 => 15,
        Register::R31 => 31,
    }
}

fn get_register_for_index(index: u8) -> Result<Register, &'static str> {
    match index {
        0 => Ok(Register::R0),
        1 => Ok(Register::R1),
        2 => Ok(Register::R2),
        3 => Ok(Register::R3),
        4 => Ok(Register::R4),
        5 => Ok(Register::R5),
        6 => Ok(Register::R6),
        7 => Ok(Register::R7),
        8 => Ok(Register::R8),
        9 => Ok(Register::R9),
        10 => Ok(Register::R10),
        11 => Ok(Register::R11),
        12 => Ok(Register::R12),
        13 => Ok(Register::R13),
        14 => Ok(Register::R14),
        15 => Ok(Register::R15),
        31 => Ok(Register::R31),
        _ => Err("Invalid register index"),
    }
}

pub struct Core {
    pub ip: u16,
    link_register: u16,
    in_call: bool,
    regfile: [u32; 16],
    pub reg_read_filter: Option<fn(&mut Core, Register, u32) -> Option<u32>>,
    pub reg_write_filter: Option<fn(&mut Core, Register, u32) -> Option<u32>>,
    pub im: [u8; 1 << 15],
    pub memory_value: Option<u32>,
    delay_count: u8,
    next_ip: Option<u16>,
    next_in_call: bool,
    next_r11: u32,
    resume_at: u32,
    pub instructions_retired: u64,
}

impl Core {
    pub fn new(ip: u16, im: [u8; 1 << 15]) -> Self {
        Self {
            ip,
            link_register: 0,
            in_call: false,
            regfile: [0; 16],
            reg_read_filter: None,
            reg_write_filter: None,
            im,
            memory_value: None,
            delay_count: 0,
            next_ip: None,
            next_in_call: false,
            next_r11: 0,
            resume_at: 0,
            instructions_retired: 0,
        }
    }

    fn reg_read_raw(&self, reg: Register) -> u32 {
        self.regfile[get_index_for_reg(reg)]
    }

    fn reg_write_raw(&mut self, reg: Register, value: u32) {
        self.regfile[get_index_for_reg(reg)] = value;
    }

    fn handle_r11_read(&self) -> u32 {
        match self.in_call {
            true => self.regfile[self.reg_read_raw(Register::R11) as usize],
            false => self.reg_read_raw(Register::R11),
        }
    }

    fn handle_r11_write(&mut self, value: u32) {
        match self.in_call {
            true => self.regfile[self.reg_read_raw(Register::R11) as usize] = value,
            false => self.reg_write_raw(Register::R11, value),
        }
    }

    pub fn reg_read(&mut self, reg: Register) -> u32 {
        let regfile_value = match reg {
            Register::R11 => self.handle_r11_read(),
            Register::R31 => 0,
            _ => self.reg_read_raw(reg),
        };

        match self.reg_read_filter {
            Some(reg_read_filter) => match reg_read_filter(self, reg, regfile_value) {
                Some(filtered_value) => filtered_value,
                None => regfile_value,
            },
            None => regfile_value,
        }
    }

    pub fn reg_write(&mut self, reg: Register, value: u32) {
        let write_value = match self.reg_write_filter {
            Some(reg_write_filter) => match reg_write_filter(self, reg, value) {
                Some(filtered_value) => filtered_value,
                None => value,
            },
            None => value,
        };

        match reg {
            Register::R11 => self.handle_r11_write(write_value),
            Register::R31 => (),
            _ => self.reg_write_raw(reg, write_value),
        };
    }

    pub fn mem_read(&mut self, addr: u32) -> Result<u32, ExitReason> {
        match self.memory_value {
            Some(v) => {
                self.memory_value = None;
                Ok(v)
            }
            None => Err(ExitReason::IO(IoType::MemRead(addr))),
        }
    }

    pub fn mem_write(&mut self, addr: u32, value: u32) -> Option<ExitReason> {
        match self.memory_value {
            Some(_) => {
                self.memory_value = None;
                None
            }
            None => Some(ExitReason::IO(IoType::MemWrite(addr, value))),
        }
    }

    fn fetch_im_word(&mut self) -> u32 {
        let addr = (self.ip as usize) * 4;
        let word = u32::from_le_bytes(self.im[addr..addr + 4].try_into().unwrap());
        self.ip += 1;
        word
    }

    fn fetch_instruction(&mut self) -> Instruction {
        Instruction::from_u32(self.fetch_im_word())
    }

    fn exec_add_sub_common(&mut self, instr: Instruction, value: u32) -> Option<ExitReason> {
        let rs = match get_register_for_index(instr.rs) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rs_val = self.reg_read(rs);

        let rd = match get_register_for_index(instr.rd) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rd_val = match instr.inv {
            true => rs_val.wrapping_sub(value),
            false => rs_val.wrapping_add(value),
        };

        self.reg_write(rd, rd_val);

        None
    }

    fn exec_add_sub_reg_imm32(&mut self, instr: Instruction) -> Option<ExitReason> {
        let imm32 = self.fetch_im_word();
        let imm_val = match instr.shl {
            true => match self.mem_read(imm32) {
                Ok(v) => v,
                Err(e) => return Some(e),
            },
            false => imm32,
        };

        self.exec_add_sub_common(instr, imm_val)
    }

    fn exec_add_sub_regs(&mut self, instr: Instruction) -> Option<ExitReason> {
        let rx = match get_register_for_index(instr.rx) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rx_val = self.reg_read(rx);

        let shifted = match instr.shl {
            true => rx_val << instr.sh,
            false => rx_val >> instr.sh,
        };

        self.exec_add_sub_common(instr, shifted)
    }

    fn exec_add_sub(&mut self, instr: Instruction) -> Option<ExitReason> {
        match instr.op2727 {
            true => self.exec_add_sub_reg_imm32(instr),
            false => self.exec_add_sub_regs(instr),
        }
    }

    fn exec_compare_common(&mut self, instr: Instruction, value: u32) -> Option<ExitReason> {
        let signed_val = value as i32;

        let negated = match instr.inv {
            true => signed_val,
            false => -signed_val,
        };

        let rs = match get_register_for_index(instr.rs) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rs_val = self.reg_read(rs) as i32;

        let rd = match get_register_for_index(instr.rd) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let result = match instr.op3128 {
            0x2 => rs_val > negated,
            0x3 => rs_val >= negated,
            0x4 => rs_val < negated,
            0x5 => rs_val <= negated,
            0x6 => rs_val == negated,
            0x7 => rs_val != negated,
            _ => panic!("We should never get here."),
        };

        let rd_val = match result {
            true => 1,
            false => 0,
        };

        self.reg_write(rd, rd_val);

        None
    }

    fn exec_compare_reg_imm32(&mut self, instr: Instruction) -> Option<ExitReason> {
        let imm32 = self.fetch_im_word();
        let imm_val = match instr.shl {
            true => match self.mem_read(imm32) {
                Ok(v) => v,
                Err(e) => return Some(e),
            },
            false => imm32,
        };

        self.exec_compare_common(instr, imm_val)
    }

    fn exec_compare_regs(&mut self, instr: Instruction) -> Option<ExitReason> {
        let rx = match get_register_for_index(instr.rx) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rx_val = self.reg_read(rx);

        let shifted = match instr.shl {
            true => rx_val << instr.sh,
            false => rx_val >> instr.sh,
        };

        self.exec_compare_common(instr, shifted)
    }

    fn exec_compare(&mut self, instr: Instruction) -> Option<ExitReason> {
        match instr.op2727 {
            true => self.exec_compare_reg_imm32(instr),
            false => self.exec_compare_regs(instr),
        }
    }

    fn exec_and_or_common(&mut self, instr: Instruction, value: u32) -> Option<ExitReason> {
        let inverted = match instr.inv {
            true => !value,
            false => value,
        };

        let rs = match get_register_for_index(instr.rs) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rs_val = self.reg_read(rs);

        let rd = match get_register_for_index(instr.rd) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rd_val = match instr.op3128 {
            0x8 => rs_val & inverted,
            0xa => rs_val | inverted,
            _ => panic!("We should never get here."),
        };

        self.reg_write(rd, rd_val);

        None
    }

    fn exec_and_or_reg_imm32(&mut self, instr: Instruction) -> Option<ExitReason> {
        let imm32 = self.fetch_im_word();
        let imm_val = match instr.shl {
            true => match self.mem_read(imm32) {
                Ok(v) => v,
                Err(e) => return Some(e),
            },
            false => imm32,
        };

        self.exec_and_or_common(instr, imm_val)
    }

    fn exec_and_or_regs(&mut self, instr: Instruction) -> Option<ExitReason> {
        let rx = match get_register_for_index(instr.rx) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rx_val = self.reg_read(rx);

        let shifted = match instr.shl {
            true => rx_val << instr.sh,
            false => rx_val >> instr.sh,
        };

        self.exec_and_or_common(instr, shifted)
    }

    fn exec_and_or(&mut self, instr: Instruction) -> Option<ExitReason> {
        match instr.op2727 {
            true => self.exec_and_or_reg_imm32(instr),
            false => self.exec_and_or_regs(instr),
        }
    }

    fn exec_anor_common(
        &mut self,
        instr: Instruction,
        and_value: u32,
        or_value: u32,
    ) -> Option<ExitReason> {
        let inverted = match instr.inv {
            true => !and_value,
            false => and_value,
        };

        let rs = match get_register_for_index(instr.rs) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rs_val = self.reg_read(rs);

        let rd = match get_register_for_index(instr.rd) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rd_val = (rs_val & inverted) | or_value;

        self.reg_write(rd, rd_val);

        None
    }

    fn exec_anor_reg_imm32(&mut self, instr: Instruction) -> Option<ExitReason> {
        let and_imm32 = self.fetch_im_word();
        let or_imm32 = self.fetch_im_word();

        // FIXME: This will loop forever if shl is set.
        let and_val = match instr.shl {
            true => match self.mem_read(and_imm32) {
                Ok(v) => v,
                Err(e) => return Some(e),
            },
            false => and_imm32,
        };

        let or_val = match instr.shl {
            true => match self.mem_read(or_imm32) {
                Ok(v) => v,
                Err(e) => return Some(e),
            },
            false => or_imm32,
        };

        self.exec_anor_common(instr, and_val, or_val)
    }

    fn exec_anor_regs(&mut self, instr: Instruction) -> Option<ExitReason> {
        let rx = match get_register_for_index(instr.rx) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rx_val = self.reg_read(rx);

        let rx_val_shifted = match instr.shl {
            true => rx_val << instr.sh,
            false => rx_val >> instr.sh,
        };

        let ry = match get_register_for_index(instr.ry) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let ry_val = self.reg_read(ry);

        self.exec_anor_common(instr, rx_val_shifted, ry_val)
    }

    fn exec_anor(&mut self, instr: Instruction) -> Option<ExitReason> {
        match instr.op2727 {
            true => self.exec_anor_reg_imm32(instr),
            false => self.exec_anor_regs(instr),
        }
    }

    fn exec_jump_call_uncond(&mut self, instr: Instruction) -> Option<ExitReason> {
        if instr.op3128 == 0xc {
            if self.in_call {
                // TODO: Confirm how this works on real hardware.
                panic!("Tried executing a call within a call");
            }
            self.next_in_call = true;
            self.next_r11 = instr.rd as u32;
            self.link_register = self.ip + 1;
        }
        self.next_ip = Some(((instr.sh as u16) << 10) | instr.rxry);
        self.delay_count = 2;
        None
    }

    fn exec_jump_call_cond(&mut self, instr: Instruction) -> Option<ExitReason> {
        let rs = match get_register_for_index(instr.rs) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rs_val = self.reg_read(rs);

        let do_jump = match instr.inv {
            true => rs_val == 0,
            false => rs_val != 0,
        };

        match do_jump {
            true => self.exec_jump_call_uncond(instr),
            false => None,
        }
    }

    fn exec_jump_call(&mut self, instr: Instruction) -> Option<ExitReason> {
        match instr.op2727 {
            true => self.exec_jump_call_cond(instr),
            false => self.exec_jump_call_uncond(instr),
        }
    }

    fn exec_store_multi_imm32(&mut self, instr: Instruction) -> Option<ExitReason> {
        let word_count = instr.sh as u32;

        if word_count < 1 {
            return Some(ExitReason::Invalid(instr));
        }

        let addr = self.fetch_im_word();

        for i in 0..word_count {
            let value = self.fetch_im_word();
            if self.resume_at >= i {
                match self.mem_write(addr + 4 * i, value) {
                    Some(reason) => {
                        self.resume_at = i;
                        return Some(reason);
                    }
                    None => (),
                }
            }
        }

        self.resume_at = 0;

        None
    }

    fn exec_store_multi(&mut self, instr: Instruction) -> Option<ExitReason> {
        match instr.inv {
            true => self.exec_store_multi_imm32(instr),
            false => Some(ExitReason::Invalid(instr)), // TODO
        }
    }

    fn exec_store_imm16(&mut self, instr: Instruction) -> Option<ExitReason> {
        let high_bit: u32 = match instr.shl {
            true => 1 << 15,
            false => 0,
        };
        let value = high_bit | instr.rxryrs as u32;

        let rd = match get_register_for_index(instr.rd) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rd_val = self.reg_read(rd);

        self.mem_write(rd_val, value)
    }

    fn exec_store_regs(&mut self, instr: Instruction) -> Option<ExitReason> {
        let rs = match get_register_for_index(instr.rs) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rs_val = self.reg_read(rs);

        let rd = match get_register_for_index(instr.rd) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(instr)),
        };

        let rd_val = self.reg_read(rd);

        self.mem_write(rd_val, rs_val)
    }

    fn exec_store_single(&mut self, instr: Instruction) -> Option<ExitReason> {
        match instr.inv {
            true => self.exec_store_imm16(instr),
            false => self.exec_store_regs(instr),
        }
    }

    fn exec_store(&mut self, instr: Instruction) -> Option<ExitReason> {
        match instr.op2727 {
            true => self.exec_store_multi(instr),
            false => self.exec_store_single(instr),
        }
    }

    fn exec_return(&mut self) -> Option<ExitReason> {
        if self.in_call {
            self.next_in_call = false;
            self.next_ip = Some(self.link_register);
        } else {
            self.next_ip = None;
        }
        self.delay_count = 2;
        None
    }

    pub fn step(&mut self) -> Option<ExitReason> {
        // eprintln!(
        //     "Instruction 0x{:04x} (in call: {:?}, delay_count: {:?})",
        //     self.ip * 4,
        //     self.in_call,
        //     self.delay_count
        // );
        // for i in 0..self.regfile.len() {
        //     eprintln!("R{}: 0x{:08x}", i, self.regfile[i]);
        // }
        let saved_ip = self.ip;
        let instr = self.fetch_instruction();
        let res = match instr.op3128 {
            0x0 => self.exec_add_sub(instr),
            0x1 => self.exec_add_sub(instr),
            0x2..=0x7 => self.exec_compare(instr),
            0x8 => self.exec_and_or(instr),
            // TODO: 0x9: xor operations
            0xa => self.exec_and_or(instr),
            0xb => self.exec_anor(instr),
            0xc => self.exec_jump_call(instr),
            0xd => self.exec_jump_call(instr),
            0xe => self.exec_store(instr),
            0xf => self.exec_return(),
            _ => Some(ExitReason::Invalid(instr)),
        };
        match res {
            Some(reason) => {
                self.ip = saved_ip;
                return Some(reason);
            }
            None => (),
        };
        if self.delay_count > 0 {
            self.delay_count -= 1;
            if self.delay_count == 0 {
                match self.next_ip {
                    Some(next_ip) => {
                        self.ip = next_ip;
                        self.in_call = self.next_in_call;
                        if self.next_in_call {
                            self.reg_write_raw(Register::R11, self.next_r11);
                        }
                    }
                    None => return Some(ExitReason::Halt),
                }
            }
        }
        self.instructions_retired += 1;
        None
    }

    pub fn run(&mut self) -> ExitReason {
        loop {
            match self.step() {
                Some(reason) => return reason,
                None => (),
            }
        }
    }
}
