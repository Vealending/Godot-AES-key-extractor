import lief
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

FILE_NAME = "binaries/Project.elf"
AES_KEY_SIZE = 32


def is_valid_lea_instruction(inst):
    """Check if the given instruction is a valid LEA instruction."""

    return (inst.reg_name(inst.operands[0].value.reg) in ("r12", "r13", "r14", "r15") and
            inst.reg_name(inst.operands[1].value.mem.base) == "rip")


def is_address_within_section_bounds(address, section):
    """Check if the given address is within the bounds of the given section."""

    return (address >= section.virtual_address and 
            address < section.virtual_address + section.size)


def main():
    """
    This script uses LIEF and Capstone to detect possible AES keys in a Godot game binary. It
    searches for LEA instructions of the form "lea rXX, [rip + disp32]" where XX is one of r12, r13,
    r14, or r15. Then, it verifies if the address obtained from the LEA instruction corresponds to a
    location within the binary's .data section. If it is, the script extracts a sequence of bytes of
    AES_KEY_SIZE length from that address and checks if the sequence contains null bytes. 
    Although an AES key can include null bytes, filtering them reduces the false positive rate.
    """

    binary = lief.parse(FILE_NAME)

    text_section = binary.get_section(".text")
    data_section = binary.get_section(".data")

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = md.skipdata = True

    for inst in md.disasm(bytes(text_section.content), text_section.virtual_address):
        if inst.mnemonic == "lea" and is_valid_lea_instruction(inst):
            ref_address = inst.address + inst.size + inst.operands[1].value.mem.disp
            if is_address_within_section_bounds(ref_address, data_section):
                ref_bytes = bytes(binary.get_content_from_virtual_address(ref_address, AES_KEY_SIZE))
                if b"\x00" not in ref_bytes:
                    print(f"Potential AES key found at address 0x{ref_address:x}: {''.join(f'{byte:02x}' for byte in ref_bytes)}")


if __name__ == '__main__':
    main()
