from unicorn import *
from unicorn.x86_const import *
from capstone import *
from keystone import *

BASE_ADDRESS = 0x1000000
STACK_ADDRESS = 0x7FF0000
STACK_SIZE = 0x10000

asm = Ks(KS_ARCH_X86, KS_MODE_32)
dis = Cs(CS_ARCH_X86, CS_MODE_32)
mu = Uc(UC_ARCH_X86, UC_MODE_32)

assembly = b"""
mov eax, 0x1234
add eax, 1
nop
""".strip()

code_data, count = asm.asm(assembly)

if code_data is None: # code_data -> none, so we need to add a exception handling to ignore our code lance
    raise RuntimeError("Keystone assembly failed!")


print(f"assembly code count: {count}, len: {len(code_data)}")
print("machine code:", bytes(code_data).hex())

# map the code, it's a real hassle.
mu.mem_map(BASE_ADDRESS, 4 * 1024 * 1024)
mu.mem_write(BASE_ADDRESS, bytes(code_data))
# set the stack
mu.mem_map(STACK_ADDRESS - STACK_SIZE, STACK_SIZE)
mu.reg_write(UC_X86_REG_ESP, STACK_ADDRESS)
mu.reg_write(UC_X86_REG_EBP, STACK_ADDRESS)

# set a auto callback func to print hooked informations
def hook_code(uc, address, size, user_data):
    code = uc.mem_read(address, size)

    for insn in dis.disasm(bytes(code), address):
        print(
            f"0x{insn.address:08X}: "
            f"{insn.mnemonic} {insn.op_str}"
        )

# add
mu.hook_add(
    UC_HOOK_CODE,
    hook_code,
    begin=BASE_ADDRESS,
    end=BASE_ADDRESS + len(code_data) - 1
)

# start!
mu.emu_start(
    BASE_ADDRESS,
    BASE_ADDRESS + len(code_data)
)

# show our results
print("EAX = 0x%X" % mu.reg_read(UC_X86_REG_EAX))
print("ESP = 0x%X" % mu.reg_read(UC_X86_REG_ESP))
