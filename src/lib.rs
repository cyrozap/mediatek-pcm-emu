/*
 *  src/lib.rs - Emulator core for MediaTek PCM.
 *  Copyright (C) 2022-2023, 2025  Forest Crossman <cyrozap@gmail.com>
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

use std::io::Read;

pub const IM_SIZE: usize = 1 << 10;

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

impl Register {
    pub fn from_index(index: u8) -> Result<Self, &'static str> {
        match index {
            0 => Ok(Self::R0),
            1 => Ok(Self::R1),
            2 => Ok(Self::R2),
            3 => Ok(Self::R3),
            4 => Ok(Self::R4),
            5 => Ok(Self::R5),
            6 => Ok(Self::R6),
            7 => Ok(Self::R7),
            8 => Ok(Self::R8),
            9 => Ok(Self::R9),
            10 => Ok(Self::R10),
            11 => Ok(Self::R11),
            12 => Ok(Self::R12),
            13 => Ok(Self::R13),
            14 => Ok(Self::R14),
            15 => Ok(Self::R15),
            31 => Ok(Self::R31),
            _ => Err("Invalid register index"),
        }
    }

    fn to_usize(self) -> usize {
        match self {
            Self::R0 => 0,
            Self::R1 => 1,
            Self::R2 => 2,
            Self::R3 => 3,
            Self::R4 => 4,
            Self::R5 => 5,
            Self::R6 => 6,
            Self::R7 => 7,
            Self::R8 => 8,
            Self::R9 => 9,
            Self::R10 => 10,
            Self::R11 => 11,
            Self::R12 => 12,
            Self::R13 => 13,
            Self::R14 => 14,
            Self::R15 => 15,
            Self::R31 => 31,
        }
    }
}

#[derive(Debug)]
pub enum IoType {
    MemRead(u32),
    MemWrite(u32, u32),
}

/// A trait for hooking into the emulator core's memory and register accesses.
///
/// This trait provides a way to implement custom behavior for memory and
/// register operations, allowing for the emulation of peripherals or other
/// system-specific hardware.
///
/// # Usage
///
/// To use hooks, create a struct, implement this trait, and derive [`Default`].
/// Then, pass an instance of your struct to [`Core::new`].
///
/// ```no_run
/// use mtk_pcm_emu::{Core, ExitReason, Hooks};
///
/// #[derive(Default)]
/// struct MyHooks;
///
/// impl Hooks for MyHooks {
///     fn mem_read(&mut self, _core: &mut Core<Self>, addr: u32) -> Result<u32, ExitReason> {
///         println!("Reading from 0x{:08x}", addr);
///         Ok(0) // Return some value
///     }
///
///     fn mem_write(&mut self, _core: &mut Core<Self>, addr: u32, value: u32) -> Option<ExitReason> {
///         println!("Writing 0x{:08x} to 0x{:08x}", value, addr);
///         None // No error
///     }
/// }
///
/// fn main() {
///     let hooks = MyHooks;
///     let mut pcm_core = Core::new(hooks);
///     // ...
/// }
/// ```
///
/// All methods have default implementations. The default register hooks do
/// nothing. The default memory hooks return an I/O error, simulating an open
/// bus.
///
/// The [`Core`] is generic over any type that implements [`Hooks`]. This allows
/// the compiler to specialize the [`Core`] for a specific set of hooks at
/// compile time, enabling optimizations like inlining the hook functions. The
/// [`Default`] trait is required to work around Rust's borrowing rules when
/// calling hook methods.
pub trait Hooks {
    /// A filter for register reads.
    ///
    /// This function is called whenever a register is read. It can return a
    /// new value to substitute for the read value, or `None` to use the
    /// original value.
    fn reg_read_filter(&mut self, _core: &mut Core<Self>, _reg: Register, _val: u32) -> Option<u32>
    where
        Self: Sized + Default,
    {
        None
    }

    /// A filter for register writes.
    ///
    /// This function is called whenever a register is written to. It can
    /// return a new value to substitute for the value being written, or `None`
    /// to use the original value.
    fn reg_write_filter(&mut self, _core: &mut Core<Self>, _reg: Register, _val: u32) -> Option<u32>
    where
        Self: Sized + Default,
    {
        None
    }

    /// A handler for memory reads.
    ///
    /// This function is called whenever the core attempts to read from memory.
    /// It should return the value at the given address, or an `ExitReason` if
    /// an error occurred.
    fn mem_read(&mut self, core: &mut Core<Self>, addr: u32) -> Result<u32, ExitReason>
    where
        Self: Sized + Default,
    {
        Err(ExitReason::IOErr(core.current_pc, IoType::MemRead(addr)))
    }

    /// A handler for memory writes.
    ///
    /// This function is called whenever the core attempts to write to memory.
    /// It can return an `ExitReason` if an error occurred.
    fn mem_write(&mut self, core: &mut Core<Self>, addr: u32, value: u32) -> Option<ExitReason>
    where
        Self: Sized + Default,
    {
        Some(ExitReason::IOErr(
            core.current_pc,
            IoType::MemWrite(addr, value),
        ))
    }
}

pub enum ExitReason {
    IOErr(u16, IoType),
    Halt(u16),
    Invalid(u16, Instruction),
}

#[derive(Debug, Clone)]
enum ExecState {
    Normal,
    DelaySlot(u16, CallState),
    Halt,
}

#[derive(Debug, Clone, Copy)]
enum CallState {
    NC,
    C1,
    C2,
}

impl CallState {
    fn prev(&self) -> Self {
        match self {
            Self::C2 => Self::C1,
            _ => Self::NC,
        }
    }

    fn next(&self) -> Self {
        match self {
            Self::NC => Self::C1,
            _ => Self::C2,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CallInfo {
    link_register: u16,
    r11: u32,
}

impl CallInfo {
    fn new() -> Self {
        Self {
            link_register: 0,
            r11: 0,
        }
    }
}

struct CallBuffer {
    queue: [CallInfo; 2],
    size: usize,
    ptr: usize,
}

impl CallBuffer {
    fn new() -> Self {
        Self {
            queue: [CallInfo::new(); 2],
            size: 0,
            ptr: 0,
        }
    }

    fn push(&mut self, info: CallInfo) {
        self.queue[self.ptr] = info;

        self.ptr = self.ptr.wrapping_add(1);
        if self.ptr >= self.queue.len() {
            self.ptr = 0;
        }

        if self.size < self.queue.len() {
            self.size += 1;
        }
    }

    fn pop(&mut self) -> CallInfo {
        self.size = self.size.saturating_sub(1);

        self.ptr = self.ptr.wrapping_sub(1);
        if self.ptr >= self.queue.len() {
            self.ptr = self.queue.len() - 1;
        }

        self.queue[self.ptr]
    }
}

enum Comparison {
    GT,
    GE,
    LT,
    LE,
    EQ,
    NE,
}

enum AndOr {
    And,
    Or,
}

enum JumpCall {
    Call,
    Jump,
}

enum Operation {
    AddSub,
    Compare(Comparison),
    AndOr(AndOr),
    Xor,
    Anor,
    JumpCall(JumpCall),
    Store,
    Return,
    Invalid,
}

impl Operation {
    fn from_instruction(instr: Instruction) -> Self {
        match instr.get_op3128() {
            0x0 => Self::AddSub,
            0x1 => Self::AddSub,
            0x2 => Self::Compare(Comparison::GT),
            0x3 => Self::Compare(Comparison::GE),
            0x4 => Self::Compare(Comparison::LT),
            0x5 => Self::Compare(Comparison::LE),
            0x6 => Self::Compare(Comparison::EQ),
            0x7 => Self::Compare(Comparison::NE),
            0x8 => Self::AndOr(AndOr::And),
            0x9 => Self::Xor,
            0xa => Self::AndOr(AndOr::Or),
            0xb => Self::Anor,
            0xc => Self::JumpCall(JumpCall::Call),
            0xd => Self::JumpCall(JumpCall::Jump),
            0xe => Self::Store,
            0xf => Self::Return,
            _ => Self::Invalid,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Instruction {
    pub word: u32,
}

impl Instruction {
    fn from_u32(word: u32) -> Self {
        Self { word }
    }

    fn get_op3128(&self) -> u8 {
        (self.word >> 28) as u8
    }

    fn get_op2727(&self) -> bool {
        ((self.word >> 27) & 1) != 0
    }

    fn get_rd(&self) -> u8 {
        ((self.word >> 22) & 0x1F) as u8
    }

    fn get_inv(&self) -> bool {
        ((self.word >> 21) & 1) != 0
    }

    fn get_shl(&self) -> bool {
        ((self.word >> 20) & 1) != 0
    }

    fn get_sh(&self) -> u8 {
        ((self.word >> 15) & 0x1F) as u8
    }

    fn get_rxryrs(&self) -> u16 {
        (self.word & 0x7FFF) as u16
    }

    fn get_rxry(&self) -> u16 {
        ((self.word >> 5) & 0x3FF) as u16
    }

    fn get_rx(&self) -> u8 {
        ((self.word >> 10) & 0x1F) as u8
    }

    fn get_ry(&self) -> u8 {
        ((self.word >> 5) & 0x1F) as u8
    }

    fn get_rs(&self) -> u8 {
        (self.word & 0x1F) as u8
    }

    fn get_imm16(&self) -> u16 {
        let high_bit: u16 = match self.get_shl() {
            true => 1 << 15,
            false => 0,
        };
        high_bit | self.get_rxryrs()
    }
}

pub struct Core<H: Hooks + Default> {
    current_pc: u16,
    next_pc: u16,
    call_buffer: CallBuffer,
    call_state: CallState,
    regfile: [u32; 15],
    im: [u32; IM_SIZE],
    hooks: H,
    current_exec_state: ExecState,
    next_exec_state: ExecState,
    next_r11: Option<u32>,
    instructions_retired: u64,
}

impl<H: Hooks + Default> Core<H> {
    pub fn new(hooks: H) -> Self {
        Self {
            current_pc: 0,
            next_pc: 0,
            call_buffer: CallBuffer::new(),
            call_state: CallState::NC,
            regfile: [0; 15],
            im: [0; IM_SIZE],
            hooks,
            current_exec_state: ExecState::Normal,
            next_exec_state: ExecState::Normal,
            next_r11: None,
            instructions_retired: 0,
        }
    }

    pub fn load_im<R: Read>(&mut self, mut reader: R) -> std::io::Result<()> {
        let mut buf = [0u8; 4];
        for word in self.im.iter_mut() {
            match reader.read_exact(&mut buf) {
                Ok(()) => *word = u32::from_le_bytes(buf),
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn get_pc(&self) -> u16 {
        match self.next_exec_state {
            ExecState::DelaySlot(delayed_pc, _) => delayed_pc,
            ExecState::Halt => 0,
            ExecState::Normal => self.next_pc,
        }
    }

    pub fn get_instructions_retired(&self) -> u64 {
        self.instructions_retired
    }

    fn reg_read_raw(&self, reg: Register) -> u32 {
        match reg {
            Register::R15 => self.get_pc().into(),
            Register::R31 => 0,
            _ => self.regfile[reg.to_usize()],
        }
    }

    fn reg_write_raw(&mut self, reg: Register, value: u32) {
        match reg {
            Register::R15 => (),
            Register::R31 => (),
            _ => self.regfile[reg.to_usize()] = value,
        }
    }

    fn handle_r11_read(&self) -> u32 {
        match self.call_state {
            CallState::NC => self.reg_read_raw(Register::R11),
            _ => self.regfile[self.reg_read_raw(Register::R11) as usize],
        }
    }

    fn handle_r11_write(&mut self, value: u32) {
        match self.call_state {
            CallState::NC => self.reg_write_raw(Register::R11, value),
            _ => self.regfile[self.reg_read_raw(Register::R11) as usize] = value,
        }
    }

    pub fn reg_read(&mut self, reg: Register) -> u32 {
        let regfile_value = match reg {
            Register::R11 => self.handle_r11_read(),
            _ => self.reg_read_raw(reg),
        };

        // The hook handler needs a mutable reference to the core, but the
        // hooks are also owned by the core. To satisfy the borrow checker, we
        // temporarily move the hooks out of the core, call the hook, and
        // then move them back.
        let mut hooks = std::mem::take(&mut self.hooks);
        let filter_result = hooks.reg_read_filter(self, reg, regfile_value);
        self.hooks = hooks;

        match filter_result {
            Some(filtered_value) => filtered_value,
            None => regfile_value,
        }
    }

    pub fn reg_write(&mut self, reg: Register, value: u32) {
        // The hook handler needs a mutable reference to the core, but the
        // hooks are also owned by the core. To satisfy the borrow checker, we
        // temporarily move the hooks out of the core, call the hook, and
        // then move them back.
        let mut hooks = std::mem::take(&mut self.hooks);
        let filter_result = hooks.reg_write_filter(self, reg, value);
        self.hooks = hooks;

        let write_value = match filter_result {
            Some(filtered_value) => filtered_value,
            None => value,
        };

        match reg {
            Register::R11 => self.handle_r11_write(write_value),
            _ => self.reg_write_raw(reg, write_value),
        };
    }

    pub fn mem_read(&mut self, addr: u32) -> Result<u32, ExitReason> {
        // The hook handler needs a mutable reference to the core, but the
        // hooks are also owned by the core. To satisfy the borrow checker, we
        // temporarily move the hooks out of the core, call the hook, and
        // then move them back.
        let mut hooks = std::mem::take(&mut self.hooks);
        let result = hooks.mem_read(self, addr);
        self.hooks = hooks;
        result
    }

    pub fn mem_write(&mut self, addr: u32, value: u32) -> Option<ExitReason> {
        // The hook handler needs a mutable reference to the core, but the
        // hooks are also owned by the core. To satisfy the borrow checker, we
        // temporarily move the hooks out of the core, call the hook, and
        // then move them back.
        let mut hooks = std::mem::take(&mut self.hooks);
        let result = hooks.mem_write(self, addr, value);
        self.hooks = hooks;
        result
    }

    fn fetch_im_word(&mut self) -> u32 {
        let word = self.im[self.next_pc as usize];
        self.next_pc += 1;
        word
    }

    fn fetch_instruction(&mut self) -> Instruction {
        Instruction::from_u32(self.fetch_im_word())
    }

    fn exec_add_sub_common(&mut self, instr: Instruction, value: u32) -> Option<ExitReason> {
        let rs = match Register::from_index(instr.get_rs()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rs_val = self.reg_read(rs);

        let rd = match Register::from_index(instr.get_rd()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rd_val = match instr.get_inv() {
            true => rs_val.wrapping_sub(value),
            false => rs_val.wrapping_add(value),
        };

        self.reg_write(rd, rd_val);

        None
    }

    fn exec_add_sub_reg_imm32(&mut self, instr: Instruction) -> Option<ExitReason> {
        let imm32 = self.fetch_im_word();
        let imm_val = match instr.get_shl() {
            true => match self.mem_read(imm32) {
                Ok(v) => v,
                Err(e) => return Some(e),
            },
            false => imm32,
        };

        self.exec_add_sub_common(instr, imm_val)
    }

    fn exec_add_sub_regs(&mut self, instr: Instruction) -> Option<ExitReason> {
        let rx = match Register::from_index(instr.get_rx()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rx_val = self.reg_read(rx);

        let shifted = match instr.get_shl() {
            true => rx_val << instr.get_sh(),
            false => rx_val >> instr.get_sh(),
        };

        self.exec_add_sub_common(instr, shifted)
    }

    fn exec_add_sub(&mut self, instr: Instruction) -> Option<ExitReason> {
        match instr.get_op2727() {
            true => self.exec_add_sub_reg_imm32(instr),
            false => self.exec_add_sub_regs(instr),
        }
    }

    fn exec_compare_common(
        &mut self,
        op: Comparison,
        instr: Instruction,
        value: u32,
    ) -> Option<ExitReason> {
        let signed_val = value as i32;

        let negated = match instr.get_inv() {
            true => signed_val,
            false => -signed_val,
        };

        let rs = match Register::from_index(instr.get_rs()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rs_val = self.reg_read(rs) as i32;

        let rd = match Register::from_index(instr.get_rd()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let result = match op {
            Comparison::GT => rs_val > negated,
            Comparison::GE => rs_val >= negated,
            Comparison::LT => rs_val < negated,
            Comparison::LE => rs_val <= negated,
            Comparison::EQ => rs_val == negated,
            Comparison::NE => rs_val != negated,
        };

        let rd_val = match result {
            true => 1,
            false => 0,
        };

        self.reg_write(rd, rd_val);

        None
    }

    fn exec_compare_reg_imm32(&mut self, op: Comparison, instr: Instruction) -> Option<ExitReason> {
        let imm32 = self.fetch_im_word();
        let imm_val = match instr.get_shl() {
            true => match self.mem_read(imm32) {
                Ok(v) => v,
                Err(e) => return Some(e),
            },
            false => imm32,
        };

        self.exec_compare_common(op, instr, imm_val)
    }

    fn exec_compare_regs(&mut self, op: Comparison, instr: Instruction) -> Option<ExitReason> {
        let rx = match Register::from_index(instr.get_rx()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rx_val = self.reg_read(rx);

        let shifted = match instr.get_shl() {
            true => rx_val << instr.get_sh(),
            false => rx_val >> instr.get_sh(),
        };

        self.exec_compare_common(op, instr, shifted)
    }

    fn exec_compare(&mut self, op: Comparison, instr: Instruction) -> Option<ExitReason> {
        match instr.get_op2727() {
            true => self.exec_compare_reg_imm32(op, instr),
            false => self.exec_compare_regs(op, instr),
        }
    }

    fn exec_and_or_common(
        &mut self,
        op: AndOr,
        instr: Instruction,
        value: u32,
    ) -> Option<ExitReason> {
        let inverted = match instr.get_inv() {
            true => !value,
            false => value,
        };

        let rs = match Register::from_index(instr.get_rs()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rs_val = self.reg_read(rs);

        let rd = match Register::from_index(instr.get_rd()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rd_val = match op {
            AndOr::And => rs_val & inverted,
            AndOr::Or => rs_val | inverted,
        };

        self.reg_write(rd, rd_val);

        None
    }

    fn exec_and_or_reg_imm32(&mut self, op: AndOr, instr: Instruction) -> Option<ExitReason> {
        let imm32 = self.fetch_im_word();
        let imm_val = match instr.get_shl() {
            true => match self.mem_read(imm32) {
                Ok(v) => v,
                Err(e) => return Some(e),
            },
            false => imm32,
        };

        self.exec_and_or_common(op, instr, imm_val)
    }

    fn exec_and_or_regs(&mut self, op: AndOr, instr: Instruction) -> Option<ExitReason> {
        let rx = match Register::from_index(instr.get_rx()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rx_val = self.reg_read(rx);

        let shifted = match instr.get_shl() {
            true => rx_val << instr.get_sh(),
            false => rx_val >> instr.get_sh(),
        };

        self.exec_and_or_common(op, instr, shifted)
    }

    fn exec_and_or(&mut self, op: AndOr, instr: Instruction) -> Option<ExitReason> {
        match instr.get_op2727() {
            true => self.exec_and_or_reg_imm32(op, instr),
            false => self.exec_and_or_regs(op, instr),
        }
    }

    fn exec_xor_common(&mut self, instr: Instruction, value: u32) -> Option<ExitReason> {
        // XOR instructions require the "inv" flag to be set.
        if !instr.get_inv() {
            return Some(ExitReason::Invalid(self.current_pc, instr));
        }

        let rs = match Register::from_index(instr.get_rs()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rs_val = self.reg_read(rs);

        let rd = match Register::from_index(instr.get_rd()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rd_val = rs_val ^ value;

        self.reg_write(rd, rd_val);

        None
    }

    fn exec_xor_reg_imm32(&mut self, instr: Instruction) -> Option<ExitReason> {
        let imm32 = self.fetch_im_word();
        let imm_val = match instr.get_shl() {
            true => match self.mem_read(imm32) {
                Ok(v) => v,
                Err(e) => return Some(e),
            },
            false => imm32,
        };

        self.exec_xor_common(instr, imm_val)
    }

    fn exec_xor_regs(&mut self, instr: Instruction) -> Option<ExitReason> {
        let rx = match Register::from_index(instr.get_rx()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rx_val = self.reg_read(rx);

        let shifted = match instr.get_shl() {
            true => rx_val << instr.get_sh(),
            false => rx_val >> instr.get_sh(),
        };

        self.exec_xor_common(instr, shifted)
    }

    fn exec_xor(&mut self, instr: Instruction) -> Option<ExitReason> {
        match instr.get_op2727() {
            true => self.exec_xor_reg_imm32(instr),
            false => self.exec_xor_regs(instr),
        }
    }

    fn exec_anor_common(
        &mut self,
        instr: Instruction,
        and_value: u32,
        or_value: u32,
    ) -> Option<ExitReason> {
        let inverted = match instr.get_inv() {
            true => !and_value,
            false => and_value,
        };

        let rs = match Register::from_index(instr.get_rs()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rs_val = self.reg_read(rs);

        let rd = match Register::from_index(instr.get_rd()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rd_val = (rs_val & inverted) | or_value;

        self.reg_write(rd, rd_val);

        None
    }

    fn exec_anor_reg_imm32(&mut self, instr: Instruction) -> Option<ExitReason> {
        let and_imm32 = self.fetch_im_word();
        let or_imm32 = self.fetch_im_word();

        let and_val = match instr.get_shl() {
            true => match self.mem_read(and_imm32) {
                Ok(v) => v,
                Err(e) => return Some(e),
            },
            false => and_imm32,
        };

        let or_val = match instr.get_shl() {
            true => match self.mem_read(or_imm32) {
                Ok(v) => v,
                Err(e) => return Some(e),
            },
            false => or_imm32,
        };

        self.exec_anor_common(instr, and_val, or_val)
    }

    fn exec_anor_regs(&mut self, instr: Instruction) -> Option<ExitReason> {
        let rx = match Register::from_index(instr.get_rx()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rx_val = self.reg_read(rx);

        let rx_val_shifted = match instr.get_shl() {
            true => rx_val << instr.get_sh(),
            false => rx_val >> instr.get_sh(),
        };

        let ry = match Register::from_index(instr.get_ry()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let ry_val = self.reg_read(ry);

        self.exec_anor_common(instr, rx_val_shifted, ry_val)
    }

    fn exec_anor(&mut self, instr: Instruction) -> Option<ExitReason> {
        match instr.get_op2727() {
            true => self.exec_anor_reg_imm32(instr),
            false => self.exec_anor_regs(instr),
        }
    }

    fn exec_jump_call_uncond(&mut self, op: JumpCall, instr: Instruction) -> Option<ExitReason> {
        let delayed_call_state = match op {
            JumpCall::Call => {
                let r11 = instr.get_rd().into();
                self.call_buffer.push(CallInfo {
                    link_register: self.next_pc + 1,
                    r11,
                });
                self.next_r11 = Some(r11);

                self.call_state.next()
            }
            JumpCall::Jump => self.call_state,
        };

        let delayed_pc = ((instr.get_sh() as u16) << 10) | instr.get_rxry();
        self.next_exec_state = ExecState::DelaySlot(delayed_pc, delayed_call_state);
        None
    }

    fn exec_jump_call_cond(&mut self, op: JumpCall, instr: Instruction) -> Option<ExitReason> {
        let rs = match Register::from_index(instr.get_rs()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rs_val = self.reg_read(rs);

        let do_jump = match instr.get_inv() {
            true => rs_val == 0,
            false => rs_val != 0,
        };

        match do_jump {
            true => self.exec_jump_call_uncond(op, instr),
            false => None,
        }
    }

    fn exec_jump_call(&mut self, op: JumpCall, instr: Instruction) -> Option<ExitReason> {
        match instr.get_op2727() {
            true => self.exec_jump_call_cond(op, instr),
            false => self.exec_jump_call_uncond(op, instr),
        }
    }

    fn exec_store_multi_imm32(&mut self, instr: Instruction) -> Option<ExitReason> {
        let word_count = instr.get_sh() as u32;

        if word_count < 1 {
            return Some(ExitReason::Invalid(self.current_pc, instr));
        }

        let addr = self.fetch_im_word();

        for i in 0..word_count {
            let value = self.fetch_im_word();
            if let Some(reason) = self.mem_write(addr + 4 * i, value) {
                return Some(reason);
            }
        }

        None
    }

    fn exec_store_multi_imm16_imm32(&mut self, instr: Instruction) -> Option<ExitReason> {
        let value = instr.get_imm16() as u32;

        let rd = match Register::from_index(instr.get_rd()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rd_val = self.reg_read(rd);

        if let Some(reason) = self.mem_write(rd_val, value) {
            return Some(reason);
        }

        let word_count_minus_2 = instr.get_sh() as u32;

        for i in 1..word_count_minus_2 + 2 {
            let value = self.fetch_im_word();
            if let Some(reason) = self.mem_write(rd_val + 4 * i, value) {
                return Some(reason);
            }
        }

        None
    }

    fn exec_store_multi(&mut self, instr: Instruction) -> Option<ExitReason> {
        match instr.get_inv() {
            true => self.exec_store_multi_imm32(instr),
            false => self.exec_store_multi_imm16_imm32(instr),
        }
    }

    fn exec_store_imm16(&mut self, instr: Instruction) -> Option<ExitReason> {
        let value = instr.get_imm16() as u32;

        let rd = match Register::from_index(instr.get_rd()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rd_val = self.reg_read(rd);

        self.mem_write(rd_val, value)
    }

    fn exec_store_regs(&mut self, instr: Instruction) -> Option<ExitReason> {
        let rs = match Register::from_index(instr.get_rs()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rs_val = self.reg_read(rs);

        let rd = match Register::from_index(instr.get_rd()) {
            Ok(r) => r,
            Err(_) => return Some(ExitReason::Invalid(self.current_pc, instr)),
        };

        let rd_val = self.reg_read(rd);

        self.mem_write(rd_val, rs_val)
    }

    fn exec_store_single(&mut self, instr: Instruction) -> Option<ExitReason> {
        match instr.get_inv() {
            true => self.exec_store_imm16(instr),
            false => self.exec_store_regs(instr),
        }
    }

    fn exec_store(&mut self, instr: Instruction) -> Option<ExitReason> {
        match instr.get_op2727() {
            true => self.exec_store_multi(instr),
            false => self.exec_store_single(instr),
        }
    }

    fn exec_return(&mut self) -> Option<ExitReason> {
        match self.call_state {
            CallState::NC => {
                self.next_exec_state = ExecState::Halt;
                self.current_exec_state = ExecState::Halt;
            }
            _ => {
                let call_info = self.call_buffer.pop();
                self.next_exec_state =
                    ExecState::DelaySlot(call_info.link_register, self.call_state.prev());
                self.next_r11 = Some(call_info.r11);
            }
        }

        // eprintln!(
        //     "Returned from {:?} at 0x{:04x}",
        //     self.call_state,
        //     self.current_pc * 4
        // );

        None
    }

    pub fn goto(&mut self, pc: u16) {
        self.call_state = CallState::NC;
        self.next_exec_state = ExecState::Normal;
        self.next_pc = pc;
    }

    pub fn step(&mut self) -> Option<ExitReason> {
        self.current_exec_state = self.next_exec_state.clone();
        self.current_pc = self.next_pc;
        // eprintln!(
        //     "Instruction 0x{:04x} (in call: {:?}, exec_state: {:?})",
        //     self.current_pc * 4,
        //     self.in_call,
        //     self.current_exec_state
        // );
        // for i in 0..self.regfile.len() {
        //     eprintln!("R{}: 0x{:08x}", i, self.regfile[i]);
        // }
        let instr = self.fetch_instruction();
        if let Some(reason) = match Operation::from_instruction(instr) {
            Operation::AddSub => self.exec_add_sub(instr),
            Operation::Compare(op) => self.exec_compare(op, instr),
            Operation::AndOr(op) => self.exec_and_or(op, instr),
            Operation::Xor => self.exec_xor(instr),
            Operation::Anor => self.exec_anor(instr),
            Operation::JumpCall(op) => self.exec_jump_call(op, instr),
            Operation::Store => self.exec_store(instr),
            Operation::Return => self.exec_return(),
            Operation::Invalid => Some(ExitReason::Invalid(self.current_pc, instr)),
        } {
            return Some(reason);
        }
        self.instructions_retired += 1;

        match self.current_exec_state {
            ExecState::DelaySlot(delayed_pc, delayed_call_state) => {
                self.next_pc = delayed_pc;
                self.call_state = delayed_call_state;
                if let Some(r11) = self.next_r11 {
                    self.reg_write_raw(Register::R11, r11);
                    self.next_r11 = None;
                }
                self.next_exec_state = ExecState::Normal;
                None
            }
            ExecState::Halt => Some(ExitReason::Halt(self.next_pc)),
            ExecState::Normal => None,
        }
    }

    pub fn run(&mut self) -> ExitReason {
        loop {
            if let Some(reason) = self.step() {
                return reason;
            }
        }
    }
}
