"""Disassemble machine-code bytes with Capstone.

Choose an architecture and mode that match the bytes being decoded. For example:

    from capstone import CS_ARCH_X86, CS_MODE_64
    from src.disassembler import disassemble

    code = bytes.fromhex("90 c3")
    for instruction in disassemble(code, CS_ARCH_X86, CS_MODE_64):
        print(f"{instruction.address:#x}: {instruction.mnemonic} {instruction.op_str}")

Steps:

1. Import Capstone (put this at the top of the file, above the function).
   - Need: ``Cs`` (the disassembler engine) and ``CsInsn`` (one decoded instruction).
   - If you get ``ModuleNotFoundError``: ``pip install -r requirements.txt``.

2. Understand the four inputs (already in the signature below).
   - ``code``: raw bytes to decode (bytes, bytearray and memoryview all work).
   - ``architecture``: CPU family, e.g. CS_ARCH_X86, CS_ARCH_ARM, CS_ARCH_ARM64.
   - ``mode``: variant of that CPU, e.g. CS_MODE_64, CS_MODE_32, CS_MODE_THUMB.
   - ``address``: where the first byte lives in memory (default 0).
   - Architecture and mode must match the bytes, or the output is wrong.

3. Create the engine: ``Cs(architecture, mode)``.
   - Happens: Capstone is configured for that architecture and mode.
   - Returns: a ``Cs`` object. Nothing is decoded yet.
   - Bad architecture or mode raises ``CsError``. Do NOT catch it; the tests
     expect it to propagate.

4. Decode: ``engine.disasm(code, address)``.
   - Happens: Capstone walks the bytes from the start, one instruction at a time.
     Each instruction's address is the start address plus the sizes before it.
   - Returns: a lazy generator of ``CsInsn``, not a list.
   - Decoding stops at the first undecodable/truncated bytes. It does not guess
     and does not raise, so ``b""`` or a lone ``b"\\x0f"`` yields nothing.
   - Non-bytes input (``"90"``, ``None``) raises ``TypeError``. Don't catch it.

5. Turn the generator into a list and return it: ``list(...)``.
   - Returns: ``list[CsInsn]``. Empty input gives ``[]``.
   - Each item has ``.address``, ``.mnemonic``, ``.op_str``, ``.size``, ``.bytes``.
     Example: ``48 89 d8`` at 0x1000 -> 0x1000, "mov", "rax, rbx", 3, b"\\x48\\x89\\xd8".

6. Check your work (run from the project root, not from src/):

       make test-disassembly

   Expected quick manual result for ``90 48 89 d8 c3`` at 0x4000, x86-64:

       0x4000: nop
       0x4001: mov rax, rbx
       0x4004: ret
"""
# import Capstone
from capstone import Cs, CsInsn, CsError


def disassemble(
    code: bytes,
    architecture: int,
    mode: int,
    address: int = 0,
) -> "list[CsInsn]":
    """Return the instructions decoded from ``code`` starting at ``address``."""
    # engine creation
    engine = Cs(architecture, mode)
    # use engine to decode
    instructions = engine.disasm(code, address)
    # put instructions into list
    return list(instructions)
