"""Tests for ``src.disassembler.disassemble``.

Run with ``make test-disassembly``.

Every assertion compares ``received`` (what your function returned) against
``expected`` (what it should return), so a failure shows both side by side.
"""

import pytest
from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_X86,
    CS_MODE_16,
    CS_MODE_32,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_THUMB,
    CsError,
    CsInsn,
)

from src.disassembler import disassemble


def x86(code, mode=CS_MODE_64, address=0):
    return disassemble(code, CS_ARCH_X86, mode, address)


def summary(instructions, *fields):
    """Reduce instructions to plain tuples so failures are easy to read."""
    return [tuple(getattr(i, f) for f in fields) for i in instructions]


# --- return type -----------------------------------------------------------

class TestReturnType:
    def test_returns_a_list_of_capstone_instructions(self):
        received = x86(b"\x90")
        assert type(received) is list, "expected a list, not a generator"
        assert len(received) == 1
        assert isinstance(received[0], CsInsn)


# --- single instruction fields ---------------------------------------------

class TestInstructionFields:
    def test_nop_fields(self):
        i = x86(b"\x90")[0]
        received = (i.mnemonic, i.op_str, i.address, i.size, i.bytes)
        expected = ("nop", "", 0, 1, b"\x90")
        assert received == expected

    @pytest.mark.parametrize(
        "hexbytes, mnemonic, op_str",
        [
            ("48 89 d8", "mov", "rax, rbx"),
            ("b8 78 56 34 12", "mov", "eax, 0x12345678"),
            ("48 8b 03", "mov", "rax, qword ptr [rbx]"),
            ("48 b8 88 77 66 55 44 33 22 11", "movabs", "rax, 0x1122334455667788"),
            ("f3 90", "pause", ""),
            ("0f 0b", "ud2", ""),
        ],
        ids=["register", "immediate", "memory", "multi-byte", "prefix", "ud2"],
    )
    def test_decodes_operands(self, hexbytes, mnemonic, op_str):
        code = bytes.fromhex(hexbytes)
        i = x86(code)[0]
        received = (i.mnemonic, i.op_str, i.size, i.bytes)
        expected = (mnemonic, op_str, len(code), code)
        assert received == expected


# --- multiple instructions and addresses -----------------------------------

class TestSequences:
    def test_decodes_multiple_instructions_in_order(self):
        received = summary(x86(bytes.fromhex("90 c3 cc")), "mnemonic", "op_str")
        expected = [("nop", ""), ("ret", ""), ("int3", "")]
        assert received == expected

    def test_addresses_advance_by_decoded_size(self):
        received = summary(x86(bytes.fromhex("90 48 89 d8 c3"), address=0x4000), "address", "size")
        expected = [(0x4000, 1), (0x4001, 3), (0x4004, 1)]
        assert received == expected

    def test_relative_branch_target_uses_start_address(self):
        i = x86(bytes.fromhex("e8 00 00 00 00"), address=0x1000)[0]
        received = (i.mnemonic, i.op_str)
        expected = ("call", "0x1005")
        assert received == expected


# --- start address ---------------------------------------------------------

class TestStartAddress:
    def test_default_is_zero(self):
        received = disassemble(b"\x90", CS_ARCH_X86, CS_MODE_64)[0].address
        assert received == 0

    @pytest.mark.parametrize("address", [0x10, 0x123456, 0x1_0000_0000])
    def test_start_address_is_preserved(self, address):
        received = x86(b"\x90", address=address)[0].address
        assert received == address

    def test_each_call_uses_its_own_address(self):
        received = [x86(b"\x90", address=a)[0].address for a in (0x10, 0x20)]
        expected = [0x10, 0x20]
        assert received == expected

    def test_repeated_calls_are_consistent(self):
        code = bytes.fromhex("48 89 d8 c3")
        fields = ("address", "mnemonic", "op_str")
        received = summary(x86(code, address=0x2000), *fields)
        expected = summary(x86(code, address=0x2000), *fields)
        assert received == expected
        assert received, "expected at least one instruction"


# --- architectures and modes -----------------------------------------------

class TestModes:
    @pytest.mark.parametrize(
        "mode, hexbytes, expected",
        [
            (CS_MODE_16, "b8 34 12 c3", [("mov", "ax, 0x1234", 3), ("ret", "", 1)]),
            (CS_MODE_32, "b8 34 12 00 00 c3", [("mov", "eax, 0x1234", 5), ("ret", "", 1)]),
            (CS_MODE_64, "48 89 d8", [("mov", "rax, rbx", 3)]),
        ],
        ids=["x86-16", "x86-32", "x86-64"],
    )
    def test_x86_mode_changes_decoding(self, mode, hexbytes, expected):
        received = summary(x86(bytes.fromhex(hexbytes), mode), "mnemonic", "op_str", "size")
        assert received == expected

    @pytest.mark.parametrize(
        "arch, mode, hexbytes, size",
        [
            (CS_ARCH_ARM, CS_MODE_ARM, "00 f0 20 e3", 4),
            (CS_ARCH_ARM, CS_MODE_THUMB, "00 bf", 2),
            (CS_ARCH_ARM64, CS_MODE_ARM, "1f 20 03 d5", 4),
        ],
        ids=["arm", "thumb", "arm64"],
    )
    def test_other_architectures_decode_a_nop(self, arch, mode, hexbytes, size):
        i = disassemble(bytes.fromhex(hexbytes), arch, mode)[0]
        received = (i.mnemonic, i.size)
        expected = ("nop", size)
        assert received == expected

    def test_architecture_specific_address_is_reported(self):
        received = disassemble(bytes.fromhex("00 bf"), CS_ARCH_ARM, CS_MODE_THUMB, address=0x8000)[0].address
        assert received == 0x8000


# --- empty and truncated input ---------------------------------------------

class TestIncompleteInput:
    def test_empty_input_returns_empty_list(self):
        assert x86(b"") == []

    def test_lone_incomplete_opcode_returns_nothing(self):
        assert x86(b"\x0f") == []

    def test_trailing_incomplete_instruction_is_dropped(self):
        received = summary(x86(bytes.fromhex("90 0f")), "mnemonic", "address")
        expected = [("nop", 0)]
        assert received == expected

    def test_truncated_arm64_instruction_is_dropped(self):
        received = disassemble(bytes.fromhex("1f 20 03"), CS_ARCH_ARM64, CS_MODE_ARM)
        assert received == []


# --- accepted input types --------------------------------------------------

class TestInputTypes:
    @pytest.mark.parametrize("wrap", [bytes, bytearray, memoryview], ids=["bytes", "bytearray", "memoryview"])
    def test_bytes_like_input_is_accepted(self, wrap):
        received = [i.mnemonic for i in x86(wrap(b"\x90"))]
        assert received == ["nop"]


# --- errors must propagate -------------------------------------------------

class TestErrors:
    def test_invalid_architecture_raises_cserror(self):
        with pytest.raises(CsError):
            disassemble(b"\x90", -1, CS_MODE_64)

    def test_invalid_mode_raises_cserror(self):
        with pytest.raises(CsError):
            disassemble(b"\x90", CS_ARCH_X86, 12345)

    @pytest.mark.parametrize("bad", ["90", None], ids=["str", "None"])
    def test_non_bytes_input_raises_typeerror(self, bad):
        with pytest.raises(TypeError):
            x86(bad)
