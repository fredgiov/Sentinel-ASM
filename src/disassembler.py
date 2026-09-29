"""Disassemble machine-code bytes with Capstone.

Choose an architecture and mode that match the bytes being decoded. For example:

    from capstone import CS_ARCH_X86, CS_MODE_64
    from disassembler import disassemble

    code = bytes.fromhex("90 c3")
    for instruction in disassemble(code, CS_ARCH_X86, CS_MODE_64):
        print(f"{instruction.address:#x}: {instruction.mnemonic} {instruction.op_str}")

Capstone provides architecture and mode constants for its supported targets;
consult its documentation for the correct pair for your binary.
"""

from capstone import Cs, CsInsn

def disassemble(
    code: bytes,
    architecture: int,
    mode: int,
    address: int = 0,
) -> list[CsInsn]:
    """Return the instructions decoded from ``code`` starting at ``address``."""
    engine = Cs(architecture, mode)
    return list(engine.disasm(code, address))
