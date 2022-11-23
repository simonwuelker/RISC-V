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

const I_Instruction = struct {
    immediate: u12,
    rs1: Register,
    rd: Register,
    funct3: u3,

    const Self = @This();

    pub fn parse(instruction: u32) Self {
        const immediate = @truncate(u12, instruction >> 19);
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
        const immediate = instruction & ~@as(u12, 0);
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
                const i = I_Instruction.parse(instruction);
                std.debug.assert(i.funct3 == 0); // expecting only JALR
                // last bit of address is never set
                const addr = (self.registers[@enumToInt(i.rs1)] + i.immediate) & ~@as(u32, 1);

                // TODO spec says we need to add 4 to the addr but stuff breaks if i do
                self.reg_write(i.rd, addr);
                self.pc = addr;
            },
            0b0010011 => {
                const i = I_Instruction.parse(instruction);
                switch (i.funct3) {
                    0b000 => {
                        // ADDI
                        self.reg_write(i.rd, self.reg_read(i.rs1) + i.immediate);
                    },
                    0b001 => {
                        // SLLI
                        self.reg_write(i.rd, std.math.shl(u32, self.reg_read(i.rs1), i.immediate));
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
                    else => {
                        std.debug.print("unimplemented funct3 for R-Instruction: 0b{b:0>3}\n", .{r.funct3});
                        return false;
                    },
                }
            },
            0b1110011 => {
                // CSRW
                std.debug.print("TODO: implement csrw instructions\n", .{});
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
    while (try iterator.next()) |entry| {
        if (entry.kind == .File) {
            if (std.mem.startsWith(u8, entry.name, "rv32ui") and std.mem.startsWith(u8, entry.name, "rv32") and !std.mem.endsWith(u8, entry.name, ".dump")) {
                std.debug.print("running {s}\n", .{entry.name});

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

                    if (std.mem.eql(u8, name, ".text") or std.mem.eql(u8, name, ".text.init")) {
                        const section_data = try read_section_contents(shdr, file, gpa);
                        core.write(shdr.sh_addr, section_data);
                        gpa.free(section_data);
                    }
                }

                // Run program
                while (core.step()) {
                    if (core.pc == 0x800000b0) {
                        break; // debug
                    }
                    core.dump();
                }
                std.debug.print("Execution stopped at 0x{x:0>8}\n", .{core.pc});

                std.os.linux.exit(0);
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
