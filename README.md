This is (*read: will be*) a virtual RISC-V core, implemented in zig. 
You can find the relevant spec [here](https://riscv.org/wp-content/uploads/2019/12/riscv-spec-20191213.pdf).

# Usage
The core expects unit tests at `riscv-tests/isa`. Download the git submodule and follow its instructions to compile the [RISC-V unit tests](https://github.com/riscv-software-src/riscv-tests).
You need to have the [RISC-V GNU Toolchain](https://github.com/riscv-collab/riscv-gnu-toolchain) installed.
In theory, it can run any RISC-V Elf.
