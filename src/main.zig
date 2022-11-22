const std = @import("std");
const ArrayList = std.ArrayList;
const elf = std.elf;
const mem = std.mem;
const Allocator = mem.Allocator;
const File = std.fs.File;

const MEM_SIZE = 0x4000;

const J_Instruction = struct {
    immediate: u32,
    register: u5,

    const Self = @This();

    pub fn parse(instruction: u32) Self {
        // not done!
        var immediate: u32 = 0;
        immediate |= ((instruction >> 21) & 0b111) << 1;
        immediate |= ((instruction >> 25) & 0b11111) << 5;
        immediate |= (instruction & 1 << 20) << 11;
        // std.debug.print("0b{b:0>32}\n", .{instruction});
        // std.debug.print("0b{b:0>32}\n", .{immediate});
        // std.debug.print("0b{b:0>32}\n", .{0x8000000c});
        return Self{
            .immediate = immediate,
            .register = @truncate(u5, instruction >> 7),
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

    pub fn step(self: *Self) bool {
        // fetch next instruction
        const instruction = self.r32(self.pc);
        const opcode = instruction & 0b1111111;
        switch (opcode) {
            0b1101111 => {
                const i = J_Instruction.parse(instruction);
                self.pc = i.immediate + 0x80000000;
            },
            else => {
                std.debug.print("Unimplemented instruction: 0x{x:0>8}\n", .{instruction});
                return false;
            },
        }
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
            if (std.mem.startsWith(u8, entry.name, "rv32") and std.mem.startsWith(u8, entry.name, "rv32") and !std.mem.endsWith(u8, entry.name, ".dump")) {
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
                    }
                }

                // Run program
                while (core.step()) {}

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
