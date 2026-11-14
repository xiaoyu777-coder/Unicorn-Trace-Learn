# we haven't solved the problems of TEB/PEB, imports, relocation, TLS callback
import pefile
from unicorn import *
from unicorn.x86_const import *
from capstone import *

PE_PATH = "test.exe"

# init some basic data
STACK_ADDRESS = 0x70000000
STACK_SIZE = 0x100000
PAGE_SIZE = 0x1000
MAX_INSTRUCTIONS = 10000

# why aglign? because unicorn needs (math i hate you)
def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)

# parse pe :) 
pe = pefile.PE(PE_PATH)
image_base = pe.OPTIONAL_HEADER.ImageBase
size_image = pe.OPTIONAL_HEADER.SizeOfImage
size_headers = pe.OPTIONAL_HEADER.SizeOfHeaders

entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
entry_point = image_base + entry_rva

print(f"ImageBase : 0x{image_base:08X}")
print(f"SizeImage : 0x{size_image:X}")
print(f"EntryRVA  : 0x{entry_rva:X}")
print(f"EntryPoint: 0x{entry_point:08X}")

mu = Uc(UC_ARCH_X86, UC_MODE_32)
dis = Cs(CS_ARCH_X86, CS_MODE_32)
image_size_aligned = align_up(size_image, PAGE_SIZE)

if image_base % PAGE_SIZE != 0:
    raise RuntimeError("ImageBase is not aligned by page")

# map the whole pe
mu.mem_map(image_base, image_size_aligned)
# write the headers
header_data = pe.__data__[:size_headers]
mu.mem_write(image_base, header_data)

# write sections such as .data
for section in pe.sections:
    section_name = section.Name.rstrip(b"\x00").decode(
        errors="replace"
    )
    virtual_address = section.VirtualAddress
    virtual_size = section.Misc_VirtualSize
    raw_data = section.get_data()
    section_address = image_base + virtual_address
    print(
        f"Section: {section_name:8s} "
        f"RVA=0x{virtual_address:08X} "
        f"VA=0x{section_address:08X} "
        f"VirtualSize=0x{virtual_size:X} "
        f"RawSize=0x{section.SizeOfRawData:X}"
    )
    # write
    if raw_data:
        mu.mem_write(section_address, raw_data)

# set the stack
mu.mem_map(STACK_ADDRESS, STACK_SIZE)
stack_top = STACK_ADDRESS + STACK_SIZE - 0x10

mu.reg_write(UC_X86_REG_ESP, stack_top)
mu.reg_write(UC_X86_REG_EBP, stack_top)
mu.reg_write(UC_X86_REG_EIP, entry_point)

# capstone hook
instruction_count = 0
def hook_code(uc, address, size, user_data):
    global instruction_count
    instruction_count += 1
    code = uc.mem_read(address, size)
    instructions = list(
        dis.disasm(bytes(code), address)
    )
    for insn in instructions:
        print(
            f"[{instruction_count:06d}] "
            f"0x{insn.address:08X}: "
            f"{insn.mnemonic:10s} "
            f"{insn.op_str}"
        )    
    # limit the number of execution instructions
    if instruction_count >= MAX_INSTRUCTIONS:
        print("reach the maximum number of instructions, then stop execution")
        uc.emu_stop()

mu.hook_add(
    UC_HOOK_CODE,
    hook_code
)

# invalid memory hook (by AI because im cute and stupid)
def hook_mem_invalid(uc, access, address, size, value, user_data):
    print(
        f"invalid memory access: "
        f"address=0x{address:08X}, "
        f"size={size}"
    )

    return False
mu.hook_add(
    UC_HOOK_MEM_INVALID,
    hook_mem_invalid
)

# cool
print("\n========== TRACE START ==========\n")
try:
    mu.emu_start(
        entry_point,
        0
    )
except UcError as e:
    print(f"\n[!] Unicorn Error: {e}")
print("\n========== TRACE END ==========\n")

registers = {
    "EAX": UC_X86_REG_EAX,
    "EBX": UC_X86_REG_EBX,
    "ECX": UC_X86_REG_ECX,
    "EDX": UC_X86_REG_EDX,
    "ESI": UC_X86_REG_ESI,
    "EDI": UC_X86_REG_EDI,
    "EBP": UC_X86_REG_EBP,
    "ESP": UC_X86_REG_ESP,
    "EIP": UC_X86_REG_EIP,
}

for name, reg in registers.items():
    value = mu.reg_read(reg)
    print(f"{name} = 0x{value:08X}")

print(f"\ntotal instructions: {instruction_count}")
pe.close()







