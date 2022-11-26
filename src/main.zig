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

const J_Instruction = struct {
    immediate: u32,
    rd: Register,

    const Self = @This();

    pub fn parse(instruction: u32) Self {
        var immediate: u32 = 0;
        immediate |= ((instruction >> 21) & 0b1111111111) << 1;
        immediate |= ((instruction >> 20) & 0b1) << 11;
        immediate |= ((instruction >> 12) & 0b11111111) << 12;
        immediate |= ((instruction >> 31) & 0b1) << 20;

        return Self{
            .immediate = immediate,
            .rd = @intToEnum(Register, instruction >> 7),
        };
    }
};

const B_Instruction = struct {
    immediate: i13,
    rs1: Register,
    rs2: Register,
    funct3: u3,

    const Self = @This();

    pub fn parse(instruction: u32) Self {
        const rs1 = @intToEnum(Register, (instruction >> 15) & 0b11111);
        const rs2 = @intToEnum(Register, (instruction >> 20) & 0b11111);
        const funct3 = @truncate(u3, instruction >> 12);

        // The immediate is actually a signed value but we do a bitcast later
        var immediate: u13 = 0;
        immediate |= @truncate(u13, ((instruction >> 7) & 0b1) << 11);
        immediate |= @truncate(u13, ((instruction >> 8) & 0b1111) << 1);
        immediate |= @truncate(u13, ((instruction >> 25) & 0b111111) << 5);
        immediate |= @truncate(u13, ((instruction >> 31) & 0b1) << 12);

        return Self{
            .immediate = @bitCast(i13, immediate),
            .rs1 = rs1,
            .rs2 = rs2,
            .funct3 = funct3,
        };
    }
};

const I_Instruction = struct {
    immediate: u12,
    rs1: Register,
    rd: Register,
    funct3: u3,

    const Self = @This();

    pub fn parse(instruction: u32) Self {
        const immediate = @truncate(u12, instruction >> 20);
        const rd = @intToEnum(Register, (instruction >> 7) & 0b11111);
        const rs1 = @intToEnum(Register, (instruction >> 15) & 0b11111);
        const funct3 = @truncate(u3, instruction >> 12);

        return Self{
            .immediate = immediate,
            .rs1 = rs1,
            .rd = rd,
            .funct3 = funct3,
        };
    }
};

const U_Instruction = struct {
    /// First 12 bits are not used
    immediate: u32,
    rd: Register,

    const Self = @This();

    pub fn parse(instruction: u32) Self {
        // mask off lower 12 bits
        const immediate = instruction & ~((@as(u32, 1) << 12) - 1);
        const rd = @intToEnum(Register, (instruction >> 7) & 0b11111);

        return Self{
            .immediate = immediate,
            .rd = rd,
        };
    }
};

const R_Instruction = struct {
    funct7: u7,
    rs2: Register,
    rs1: Register,
    funct3: u3,
    rd: Register,

    const Self = @This();

    pub fn parse(instruction: u32) Self {
        const rd = @intToEnum(Register, @truncate(u5, instruction >> 7));
        const funct3 = @truncate(u3, instruction >> 12);
        const rs1 = @intToEnum(Register, @truncate(u5, instruction >> 15));
        const rs2 = @intToEnum(Register, @truncate(u5, instruction >> 20));
        const funct7 = @truncate(u7, instruction >> 25);

        return Self{
            .rd = rd,
            .funct3 = funct3,
            .rs1 = rs1,
            .rs2 = rs2,
            .funct7 = funct7,
        };
    }
};

const S_Instruction = struct {
    immediate: u12,
    rs1: Register,
    rs2: Register,
    funct3: u3,

    const Self = @This();

    pub fn parse(instruction: u32) Self {
        const funct3 = @truncate(u3, instruction >> 12);
        const rs1 = @intToEnum(Register, @truncate(u5, instruction >> 15));
        const rs2 = @intToEnum(Register, @truncate(u5, instruction >> 20));
        var immediate: u12 = 0;
        immediate |= @truncate(u12, (instruction >> 7) & 0b11111);
        immediate |= @truncate(u12, instruction >> 25);

        return Self{
            .immediate = immediate,
            .rs1 = rs1,
            .rs2 = rs2,
            .funct3 = funct3,
        };
    }
};

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
                const j = J_Instruction.parse(instruction);
                self.reg_write(j.rd, self.pc);
                self.pc += j.immediate;
                return true; // don't increment pc again
            },
            0b1100111 => {
                // JALR
                const i = I_Instruction.parse(instruction);
                std.debug.assert(i.funct3 == 0); // expecting only JALR
                // last bit of address is never set
                const addr = (self.registers[@enumToInt(i.rs1)] + i.immediate) & ~@as(u32, 1);

                // TODO spec says we need to add 4 to the addr but stuff breaks if i do
                self.reg_write(i.rd, addr);
                self.pc = addr;
            },
            0b0110111 => {
                // LUI
                const u = U_Instruction.parse(instruction);
                std.debug.assert(u.immediate & 0b111111111111 == 0);
                self.reg_write(u.rd, u.immediate);
            },
            0b0010011 => {
                const i = I_Instruction.parse(instruction);
                switch (i.funct3) {
                    0b000 => {
                        // ADDI
                        // Immediate is considered to be signed
                        const signed_immediate = @bitCast(i12, i.immediate);
                        // std.debug.print("signed immediate {d}\n", .{signed_immediate});
                        self.reg_write(i.rd, unsigned_add_signed(self.reg_read(i.rs1), signed_immediate));
                    },
                    0b001 => {
                        // SLLI
                        self.reg_write(i.rd, std.math.shl(u32, self.reg_read(i.rs1), i.immediate));
                    },
                    0b101 => {
                        // SRLI
                        self.reg_write(i.rd, std.math.shr(u32, self.reg_read(i.rs1), i.immediate));
                    },
                    0b110 => {
                        // ORI
                        self.reg_write(i.rd, self.reg_read(i.rs1) | i.immediate);
                    },
                    else => {
                        std.debug.print("unimplemented funct3 for I-Instruction: 0b{b:0>3}\n", .{i.funct3});
                        return false;
                    },
                }
            },
            0b0010111 => {
                // AUIPC
                const u = U_Instruction.parse(instruction);
                self.reg_write(u.rd, self.pc + u.immediate);
            },
            0b0100011 => {
                // Store instructions
                // These store part of rs2 in [rs1 + imm]
                const s = S_Instruction.parse(instruction);

                switch (s.funct3) {
                    0b010 => {
                        // SW
                        std.debug.print("imm 0x{x:0>8}\n", .{s.immediate});
                        std.debug.print("{s} {s}\n", .{ @tagName(s.rs1), @tagName(s.rs2) });
                        self.dump();
                        var buffer: [4]u8 = undefined;
                        std.mem.writeIntSliceLittle(u32, &buffer, self.reg_read(s.rs2));
                        self.write(self.reg_read(s.rs1) + s.immediate, &buffer);
                    },
                    else => {
                        std.debug.print("unimplemented funct3 for S-Instruction: 0b{b:0>3}\n", .{s.funct3});
                        return false;
                    },
                }
            },
            0b0110011 => {
                const r = R_Instruction.parse(instruction);
                switch (r.funct3) {
                    0b000 => {
                        switch (r.funct7) {
                            0b0000000 => {
                                // ADD
                                self.reg_write(r.rd, self.reg_read(r.rs1) + self.reg_read(r.rs2));
                            },
                            else => {
                                std.debug.print("unimplemented funct7 for R-Instruction: 0b{b:0>7}\n", .{r.funct7});
                                return false;
                            },
                        }
                    },
                    0b111 => {
                        // AND
                        std.debug.assert(r.funct7 == 0b0000000);
                        self.reg_write(r.rd, self.reg_read(r.rs1) & self.reg_read(r.rs2));
                    },
                    else => {
                        std.debug.print("unimplemented funct3 for R-Instruction: 0b{b:0>3}\n", .{r.funct3});
                        return false;
                    },
                }
            },
            0b1100011 => {
                const b = B_Instruction.parse(instruction);
                switch (b.funct3) {
                    0b000 => {
                        // BEQ
                        if (self.reg_read(b.rs1) == self.reg_read(b.rs2)) {
                            self.pc = unsigned_add_signed(self.pc, b.immediate);
                            return true;
                        }
                    },
                    0b001 => {
                        // BNE
                        if (self.reg_read(b.rs1) != self.reg_read(b.rs2)) {
                            self.pc = unsigned_add_signed(self.pc, b.immediate);
                            return true;
                        }
                    },
                    0b100 => {
                        // BLT
                        if (@bitCast(i32, self.reg_read(b.rs1)) < @bitCast(i32, self.reg_read(b.rs2))) {
                            self.pc = unsigned_add_signed(self.pc, b.immediate);
                            return true;
                        }
                    },
                    else => {
                        std.debug.print("unimplemented funct3 for B-Instruction: 0b{b:0>3}\n", .{b.funct3});
                        return false;
                    },
                }
            },
            0b1110011 => {
                const i = I_Instruction.parse(instruction);

                switch (i.funct3) {
                    0b000 => {
                        // Environment instruction
                        std.debug.assert(i.rd == Register.x0);
                        std.debug.assert(i.rs1 == Register.x0);

                        switch (i.immediate) {
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
                                std.debug.print("unimplemented immediate for Environment-Instruction: 0b{b:0>12}\n", .{i.immediate});
                                self.dump();
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
            if (std.mem.startsWith(u8, entry.name, "rv32ui-p-") and std.mem.startsWith(u8, entry.name, "rv32") and !std.mem.endsWith(u8, entry.name, ".dump")) {
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

/// Wait for user input, used for debugging only
fn wait() !void {
    const stdin = std.io.getStdIn();
    _ = try stdin.reader().readByte();
}
