const std = @import("std");
const ArrayList = std.ArrayList;
const elf = std.elf;
const mem = std.mem;
const Allocator = mem.Allocator;
const File = std.fs.File;

const MEM_SIZE = 0x4000;

const Register = enum(u5) {
    // zig fmt: off
    x0,  x1,  x2,  x3,  x4,  x5,  x6,  x7,
    x8,  x9,  x10, x11, x12, x13, x14, x15, 
    x16, x17, x18, x19, x20, x21, x22, x23,
    x24, x25, x26, x27, x28, x29, x30, x31,
    // zig fmt: on
};

fn j_immediate(instruction: u32) u32 {
    // TODO shrink returned int size
    var immediate: u32 = 0;
    immediate |= ((instruction >> 21) & 0b1111111111) << 1;
    immediate |= ((instruction >> 20) & 0b1) << 11;
    immediate |= ((instruction >> 12) & 0b11111111) << 12;
    immediate |= ((instruction >> 31) & 0b1) << 20;
    return immediate;
}

fn b_immediate(instruction: u32) i13 {
    var immediate: u13 = 0;
    immediate |= @truncate(u13, ((instruction >> 7) & 0b1) << 11);
    immediate |= @truncate(u13, ((instruction >> 8) & 0b1111) << 1);
    immediate |= @truncate(u13, ((instruction >> 25) & 0b111111) << 5);
    immediate |= @truncate(u13, ((instruction >> 31) & 0b1) << 12);
    return @bitCast(i13, immediate);
}

fn s_immediate(instruction: u32) u12 {
    var immediate: u12 = 0;
    immediate |= @truncate(u12, (instruction >> 7) & 0b11111);
    immediate |= @truncate(u12, instruction >> 25);
    return immediate;
}

fn u_immediate(instruction: u32) u32 {
    return instruction & ~((@as(u32, 1) << 12) - 1);
}

fn i_immediate(instruction: u32) u12 {
    return @truncate(u12, instruction >> 20);
}

fn rd(instruction: u32) Register {
    return @intToEnum(Register, instruction >> 7);
}

fn rs1(instruction: u32) Register {
    return @intToEnum(Register, (instruction >> 15) & 0b11111);
}

fn rs2(instruction: u32) Register {
    return @intToEnum(Register, (instruction >> 20) & 0b11111);
}

fn funct3(instruction: u32) u3 {
    return @truncate(u3, instruction >> 12);
}

fn funct7(instruction: u32) u7 {
    return @truncate(u7, instruction >> 25);
}

/// This is a hacky way of adding a signed offset to a unsigned number
/// This function doesn't perform any safety checks, only call this when you know what you are doing (never)
/// Note that the zig spec guarantees that signed integers are represented in two's complement.
/// If that were not the case, this would not work.
/// (https://github.com/ziglang/zig/issues/1723)
fn unsigned_add_signed(base: anytype, offset: anytype) @TypeOf(base) {
    // Build a few types
    const nbits = @typeInfo(@TypeOf(base)).Int.bits;
    const signed = @Type(.{ .Int = std.builtin.Type.Int{
        .signedness = .signed,
        .bits = nbits,
    } });
    const sign_extended = @Type(.{ .Int = std.builtin.Type.Int{
        .signedness = .signed,
        .bits = nbits + 1,
    } });

    const unsigned_extended = @Type(.{ .Int = std.builtin.Type.Int{
        .signedness = .signed,
        .bits = nbits + 1,
    } });

    // Add a sign bit to the unsigned value (always zero), then add the signed value as you usually would
    // and remove the extra bit again
    var signed_base: sign_extended = @bitCast(sign_extended, @as(unsigned_extended, base));
    signed_base += offset; // all of this work for one line
    return @bitCast(@TypeOf(base), @truncate(signed, signed_base));
}

const Core = struct {
    // starts at 0x80000000
    memory: [MEM_SIZE]u8 = [_]u8{0} ** MEM_SIZE,
    registers: [32]u32 = [_]u32{0} ** 32,
    pc: u32 = 0x80000000,

    const Self = @This();
    const Address = u64;

    pub fn r32(self: *const Self, addr: Address) u32 {
        const adjusted = addr - 0x80000000;
        std.debug.assert(0 <= adjusted and adjusted + 4 < MEM_SIZE);
        return std.mem.readIntLittle(u32, self.memory[adjusted..][0..4]);
    }

    pub fn write(self: *Self, addr: Address, val: []u8) void {
        const adjusted = addr - 0x80000000;
        std.debug.assert(0 <= adjusted and adjusted + val.len < MEM_SIZE);
        std.mem.copy(u8, self.memory[adjusted .. adjusted + val.len], val);
    }

    pub fn reg_write(self: *Self, reg: Register, val: u32) void {
        if (reg == Register.x0) {
            return;
        } else {
            self.registers[@enumToInt(reg)] = val;
        }
    }

    pub fn reg_read(self: *const Self, reg: Register) u32 {
        return self.registers[@enumToInt(reg)];
    }

    /// Debug-print the cpu state to stdout
    pub fn dump(self: *const Self) void {
        var x: u6 = 0;
        while (x < 32) : (x += 1) {
            if (x < 10) {
                std.debug.print(" x{d}: 0x{x:0>8} ", .{ x, self.registers[x] });
            } else {
                std.debug.print("x{d}: 0x{x:0>8} ", .{ x, self.registers[x] });
            }

            if (x % 8 == 7) {
                std.debug.print("\n", .{});
            }
        }
        std.debug.print("PC:  0x{x:0>8}\n\n", .{self.pc});
    }

    pub fn step(self: *Self) bool {
        // fetch next instruction
        const instruction = self.r32(self.pc);
        const opcode = instruction & 0b1111111;

        // decode & execute
        switch (opcode) {
            0b1101111 => {
                // JAL
                self.reg_write(rd(instruction), self.pc);
                self.pc += j_immediate(instruction);
                return true; // don't increment pc again
            },
            0b1100111 => {
                // JALR
                std.debug.assert(funct3(instruction) == 0); // expecting only JALR
                // last bit of address is never set
                const addr = unsigned_add_signed(self.reg_read(rs1(instruction)), @bitCast(i12, i_immediate(instruction))) & ~@as(u32, 1);

                self.reg_write(rd(instruction), self.pc + 4);
                self.pc = addr;
                return true; // don't increment pc again
            },
            0b0110111 => {
                // LUI
                std.debug.assert(u_immediate(instruction) & 0b111111111111 == 0);
                self.reg_write(rd(instruction), u_immediate(instruction));
            },
            0b0010011 => {
                switch (funct3(instruction)) {
                    0b000 => {
                        // ADDI
                        // Immediate is considered to be signed
                        const signed_immediate = @bitCast(i12, i_immediate(instruction));
                        self.reg_write(rd(instruction), unsigned_add_signed(self.reg_read(rs1(instruction)), signed_immediate));
                    },
                    0b001 => {
                        // SLLI
                        self.reg_write(rd(instruction), std.math.shl(u32, self.reg_read(rs1(instruction)), i_immediate(instruction)));
                    },
                    0b101 => {
                        // SRLI
                        self.reg_write(rd(instruction), std.math.shr(u32, self.reg_read(rs1(instruction)), i_immediate(instruction)));
                    },
                    0b110 => {
                        // ORI
                        self.reg_write(rd(instruction), self.reg_read(rs1(instruction)) | i_immediate(instruction));
                    },
                    else => {
                        std.debug.print("unimplemented funct3 for I-Instruction: 0b{b:0>3}\n", .{funct3(instruction)});
                        return false;
                    },
                }
            },
            0b0010111 => {
                // AUIPC
                self.reg_write(rd(instruction), self.pc + u_immediate(instruction));
            },
            0b0100011 => {
                // Store instructions
                // These store part of rs2 in [rs1 + imm]

                switch (funct3(instruction)) {
                    0b010 => {
                        // SW
                        var buffer: [4]u8 = undefined;
                        std.mem.writeIntSliceLittle(u32, &buffer, self.reg_read(rs2(instruction)));
                        self.write(self.reg_read(rs1(instruction)) + s_immediate(instruction), &buffer);
                    },
                    else => {
                        std.debug.print("unimplemented funct3 for S-Instruction: 0b{b:0>3}\n", .{funct3(instruction)});
                        return false;
                    },
                }
            },
            0b0110011 => {
                switch (funct3(instruction)) {
                    0b000 => {
                        switch (funct7(instruction)) {
                            0b0000000 => {
                                // ADD
                                self.reg_write(rd(instruction), self.reg_read(rs1(instruction)) + self.reg_read(rs2(instruction)));
                            },
                            else => {
                                std.debug.print("unimplemented funct7 for R-Instruction: 0b{b:0>7}\n", .{funct7(instruction)});
                                return false;
                            },
                        }
                    },
                    0b111 => {
                        // AND
                        std.debug.assert(funct7(instruction) == 0b0000000);
                        self.reg_write(rd(instruction), self.reg_read(rs1(instruction)) & self.reg_read(rs2(instruction)));
                    },
                    else => {
                        std.debug.print("unimplemented funct3 for R-Instruction: 0b{b:0>3}\n", .{funct3(instruction)});
                        return false;
                    },
                }
            },
            0b1100011 => {
                switch (funct3(instruction)) {
                    0b000 => {
                        // BEQ
                        if (self.reg_read(rs1(instruction)) == self.reg_read(rs2(instruction))) {
                            self.pc = unsigned_add_signed(self.pc, b_immediate(instruction));
                            return true;
                        }
                    },
                    0b001 => {
                        // BNE
                        if (self.reg_read(rs1(instruction)) != self.reg_read(rs2(instruction))) {
                            self.pc = unsigned_add_signed(self.pc, b_immediate(instruction));
                            return true;
                        }
                    },
                    0b100 => {
                        // BLT
                        if (@bitCast(i32, self.reg_read(rs1(instruction))) < @bitCast(i32, self.reg_read(rs2(instruction)))) {
                            self.pc = unsigned_add_signed(self.pc, b_immediate(instruction));
                            return true;
                        }
                    },
                    else => {
                        std.debug.print("unimplemented funct3 for B-Instruction: 0b{b:0>3}\n", .{funct3(instruction)});
                        return false;
                    },
                }
            },
            0b1110011 => {
                switch (funct3(instruction)) {
                    0b000 => {
                        // Environment instruction
                        std.debug.assert(rd(instruction) == Register.x0);
                        std.debug.assert(rs1(instruction) == Register.x0);

                        switch (i_immediate(instruction)) {
                            0 => {
                                // ECALL
                                if (self.reg_read(Register.x17) == 93) {
                                    return false; // exit
                                } else {
                                    std.debug.print("unimplemented ecall {x}\n", .{self.reg_read(Register.x17)});
                                }
                            },
                            1 => {
                                // EBREAK
                            },
                            0b001100000010 => {
                                // TODO: implement MRET
                                // doesn't seem to do anything important, so I'll ignore it for now...
                            },
                            else => {
                                std.debug.print("unimplemented immediate for Environment-Instruction: 0b{b:0>12}\n", .{i_immediate(instruction)});
                                return false;
                            },
                        }
                    },
                    else => {
                        // CSRW
                        // std.debug.print("TODO: implement csrw instructions\n", .{});
                    },
                }
            },
            0b0001111 => {
                // FENCE, noop for now
                // https://stackoverflow.com/questions/26374435/what-is-meant-by-the-fence-instruction-in-the-risc-v-instruction-set
            },
            else => {
                std.debug.print("Unimplemented instruction: 0x{x:0>8}(0b{b:0>32})\n", .{ instruction, instruction });
                // std.debug.print("Unimplemented instruction: 0b{b:0>32}\n", .{instruction});
                return false;
            },
        }
        self.pc += 4;
        return true;
    }
};

pub fn main() !void {
    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(!general_purpose_allocator.deinit());
    const gpa = general_purpose_allocator.allocator();

    var tests_dir = try std.fs.cwd().openIterableDir("riscv-tests/isa", .{});
    var iterator = tests_dir.iterate();
    const stdout = std.io.getStdOut().writer();
    while (try iterator.next()) |entry| {
        if (entry.kind == .File) {
            if (std.mem.startsWith(u8, entry.name, "rv32ui-p") and std.mem.startsWith(u8, entry.name, "rv32") and !std.mem.endsWith(u8, entry.name, ".dump")) {
                std.debug.print("running {s} ...\n", .{entry.name});
                _ = try std.fmt.format(stdout, "{s:<20}", .{entry.name});

                var core = Core{};

                const file = try tests_dir.dir.openFile(entry.name, .{});
                const elf_header = try elf.Header.read(file);
                var section_headers = elf_header.section_header_iterator(file);

                var shdrs = try ArrayList(elf.Elf64_Shdr).initCapacity(gpa, elf_header.shnum);
                defer shdrs.deinit();

                // read section headers
                while (try section_headers.next()) |shdr| {
                    try shdrs.append(shdr);
                }

                // read shstrtab
                var shstrtab = ArrayList(u8).init(gpa);
                defer shstrtab.deinit();

                const hdr = shdrs.items[elf_header.shstrndx];
                const buffer = try read_section_contents(hdr, file, gpa);
                try shstrtab.appendSlice(buffer);
                gpa.free(buffer);

                // resolve section names and load important sections
                for (shdrs.items) |shdr| {
                    const name = std.mem.sliceTo(@ptrCast([*:0]u8, shstrtab.items.ptr + shdr.sh_name), 0x0);
                    // std.debug.print("{s:<20}: 0x{x:0>8} - 0x{x:0>8}\n", .{ name, shdr.sh_addr, shdr.sh_size });

                    if (std.mem.eql(u8, name, ".text") or std.mem.eql(u8, name, ".text.init")) {
                        const section_data = try read_section_contents(shdr, file, gpa);
                        core.write(shdr.sh_addr, section_data);
                        gpa.free(section_data);
                    }
                }

                // Run program
                while (core.step()) {
                    core.dump();
                }
                const exit_code = core.reg_read(Register.x10);
                if (exit_code == 0) {
                    _ = try stdout.write("Success!\n");
                } else {
                    _ = try stdout.write("Failed.\n");

                    std.debug.print("Fail: Execution stopped at 0x{x:0>8} with exit code {d}\n", .{ core.pc, exit_code });
                }
            }
        }
    }
}

/// Caller owns returned memory
fn read_section_contents(hdr: elf.Elf64_Shdr, file: File, gpa: Allocator) ![]u8 {
    var buffer = try gpa.alloc(u8, hdr.sh_size);
    const bytes_read = try file.preadAll(buffer, hdr.sh_offset);
    std.debug.assert(bytes_read == hdr.sh_size);
    return buffer;
}
