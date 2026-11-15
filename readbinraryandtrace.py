from unicorn import *
from unicorn.x86_const import *
from capstone import *
from keystone import *

registers = {
    "RAX": UC_X86_REG_RAX,
    "RBX": UC_X86_REG_RBX,
    "RCX": UC_X86_REG_RCX,
    "RDX": UC_X86_REG_RDX,
    "RSI": UC_X86_REG_RSI,
    "RDI": UC_X86_REG_RDI,
    "RBP": UC_X86_REG_RBP,
    "RSP": UC_X86_REG_RSP,
    "RIP": UC_X86_REG_RIP,
}

segs = [
    {
        "base": 0x00404000,
        "size": 0x8c000,
        "filename": "sample.vmp_00404000.bin",
        "data": None
    },
    {
        "base": 0x0019B000,
        "size": 0x5000,
        "filename": "sample.vmp_0019B000.bin",
        "data": None
    },
]

STACK = 1
ENTRY_POINT = 0

dis = Cs(CS_ARCH_X86, CS_MODE_64)
mu = Uc(UC_ARCH_X86, UC_MODE_64)

for i in range(len(segs)):
    seg = segs[i]
    # map the code, it's a real hassle.
    mu.mem_map(seg["base"], seg["size"])
    # write the data
    with open(seg["filename"], "rb") as f:
        seg["data"] = f.read()
    mu.mem_write(seg["base"], seg["data"])


mu.reg_write(UC_X86_REG_RAX, None)
mu.reg_write(UC_X86_REG_RBX, None)
mu.reg_write(UC_X86_REG_RCX, None)
mu.reg_write(UC_X86_REG_RDX, None)
mu.reg_write(UC_X86_REG_RSI, None)
mu.reg_write(UC_X86_REG_RDI, None)
mu.reg_write(UC_X86_REG_RFLAGS, None)
# set the stack
mu.reg_write(UC_X86_REG_RSP, None)
mu.reg_write(UC_X86_REG_RBP, None)
# where do i need to start?
mu.reg_write(UC_X86_REG_RIP, ENTRY_POINT)

# read registers for saving
def read_regs():
    return {
        name: mu.reg_read(reg)
        for name, reg in registers.items()
    }

# set a auto callback func to print hooked informations
before_regs = {}
def hook_code(uc, address, size, user_data):
    global before_regs
    # save original register values
    before_regs = read_regs()
    code = uc.mem_read(address, size)
    for insn in dis.disasm(bytes(code), address):
        print(
            f"\n0x{insn.address:016X}: "
            f"{insn.mnemonic} {insn.op_str}"
        )
# add
mu.hook_add(
    UC_HOOK_CODE,
    hook_code,
)
# start!
count = 0
try:
    while True:
        rip = mu.reg_read(UC_X86_REG_RIP)
        # execute one instruction
        mu.emu_start(
            rip,
            0,
            count=1
        )
        # read registers after execution
        after_regs = read_regs()
        # compare original values and new values
        for name in registers:
            old = before_regs[name]
            new = after_regs[name]
            if old != new:
                print(
                    f"    {name}: "
                    f"0x{old:016X} -> 0x{new:016X}"
                )
        count += 1

except UcError as e:
    print(f"[!] Unicorn Error: {e}")

# show our results
for name, reg in registers.items():
    value = mu.reg_read(reg)
    print(f"{name} = 0x{value:016X}")

def print_stack(rsp):
    for i in range(10):
        value = mu.mem_read(rsp, 8)
        val = int.from_bytes(value, "little")
        print(f"|[{rsp:016X}]: {val:016X}|")
        rsp += 8
print_stack(mu.reg_read(UC_X86_REG_RSP))