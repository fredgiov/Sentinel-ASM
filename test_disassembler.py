"""Readable contract tests for ``src.disassembler.disassemble``.

Run with ``python -m unittest -v test_disassembler``.
"""

import unittest

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


class DisassembleTests(unittest.TestCase):
    """Exercise the supported inputs and externally visible decode results."""

    def decode_x86(self, code: bytes, mode: int = CS_MODE_64, address: int = 0):
        return disassemble(code, CS_ARCH_X86, mode, address)

    def test_returns_a_list_of_capstone_instructions(self):
        instructions = self.decode_x86(b"\x90")

        self.assertIs(type(instructions), list)
        self.assertEqual(len(instructions), 1)
        self.assertIsInstance(instructions[0], CsInsn)

    def test_decodes_a_single_nop(self):
        instruction = self.decode_x86(b"\x90")[0]

        self.assertEqual(instruction.mnemonic, "nop")
        self.assertEqual(instruction.op_str, "")
        self.assertEqual(instruction.address, 0)
        self.assertEqual(instruction.size, 1)
        self.assertEqual(instruction.bytes, b"\x90")

    def test_decodes_multiple_instructions_in_order(self):
        instructions = self.decode_x86(bytes.fromhex("90 c3 cc"))

        self.assertEqual(
            [(item.mnemonic, item.op_str) for item in instructions],
            [("nop", ""), ("ret", ""), ("int3", "")],
        )

    def test_instruction_addresses_advance_by_decoded_size(self):
        instructions = self.decode_x86(bytes.fromhex("90 48 89 d8 c3"), address=0x4000)

        self.assertEqual(
            [(item.address, item.size) for item in instructions],
            [(0x4000, 1), (0x4001, 3), (0x4004, 1)],
        )

    def test_zero_address_is_the_default(self):
        instruction = disassemble(b"\x90", CS_ARCH_X86, CS_MODE_64)[0]

        self.assertEqual(instruction.address, 0)

    def test_nonzero_start_address_is_preserved(self):
        instruction = self.decode_x86(b"\x90", address=0x123456)[0]

        self.assertEqual(instruction.address, 0x123456)

    def test_large_start_address_is_preserved(self):
        address = 0x1_0000_0000
        instruction = self.decode_x86(b"\x90", address=address)[0]

        self.assertEqual(instruction.address, address)

    def test_relative_branch_target_uses_the_start_address(self):
        instruction = self.decode_x86(bytes.fromhex("e8 00 00 00 00"), address=0x1000)[0]

        self.assertEqual(instruction.mnemonic, "call")
        self.assertEqual(instruction.op_str, "0x1005")

    def test_decodes_register_operands(self):
        instruction = self.decode_x86(bytes.fromhex("48 89 d8"))[0]

        self.assertEqual(instruction.mnemonic, "mov")
        self.assertEqual(instruction.op_str, "rax, rbx")

    def test_decodes_immediate_operands(self):
        instruction = self.decode_x86(bytes.fromhex("b8 78 56 34 12"))[0]

        self.assertEqual(instruction.mnemonic, "mov")
        self.assertEqual(instruction.op_str, "eax, 0x12345678")

    def test_decodes_memory_operands(self):
        instruction = self.decode_x86(bytes.fromhex("48 8b 03"))[0]

        self.assertEqual(instruction.mnemonic, "mov")
        self.assertEqual(instruction.op_str, "rax, qword ptr [rbx]")

    def test_decodes_a_multi_byte_instruction_as_one_instruction(self):
        code = bytes.fromhex("48 b8 88 77 66 55 44 33 22 11")
        instruction = self.decode_x86(code)[0]

        self.assertEqual(instruction.mnemonic, "movabs")
        self.assertEqual(instruction.op_str, "rax, 0x1122334455667788")
        self.assertEqual(instruction.size, len(code))
        self.assertEqual(instruction.bytes, code)

    def test_decodes_instruction_prefixes(self):
        instruction = self.decode_x86(bytes.fromhex("f3 90"))[0]

        self.assertEqual(instruction.mnemonic, "pause")
        self.assertEqual(instruction.size, 2)

    def test_x86_mode_changes_operand_width_in_16_bit_mode(self):
        instructions = self.decode_x86(bytes.fromhex("b8 34 12 c3"), CS_MODE_16)

        self.assertEqual(
            [(item.mnemonic, item.op_str, item.size) for item in instructions],
            [("mov", "ax, 0x1234", 3), ("ret", "", 1)],
        )

    def test_x86_mode_changes_operand_width_in_32_bit_mode(self):
        instructions = self.decode_x86(bytes.fromhex("b8 34 12 00 00 c3"), CS_MODE_32)

        self.assertEqual(
            [(item.mnemonic, item.op_str, item.size) for item in instructions],
            [("mov", "eax, 0x1234", 5), ("ret", "", 1)],
        )

    def test_x86_mode_decodes_64_bit_registers(self):
        instruction = self.decode_x86(bytes.fromhex("48 89 d8"), CS_MODE_64)[0]

        self.assertEqual(instruction.op_str, "rax, rbx")

    def test_empty_input_returns_an_empty_list(self):
        self.assertEqual(self.decode_x86(b""), [])

    def test_input_with_only_an_incomplete_opcode_returns_no_instructions(self):
        self.assertEqual(self.decode_x86(b"\x0f"), [])

    def test_incomplete_instruction_after_valid_code_is_not_fabricated(self):
        instructions = self.decode_x86(bytes.fromhex("90 0f"))

        self.assertEqual([item.mnemonic for item in instructions], ["nop"])
        self.assertEqual(instructions[0].address, 0)

    def test_incomplete_instruction_at_another_architecture_width_is_omitted(self):
        instructions = disassemble(
            bytes.fromhex("1f 20 03"),
            CS_ARCH_ARM64,
            CS_MODE_ARM,
        )

        self.assertEqual(instructions, [])

    def test_valid_undefined_x86_instruction_is_still_returned_by_capstone(self):
        instruction = self.decode_x86(bytes.fromhex("0f 0b"))[0]

        self.assertEqual(instruction.mnemonic, "ud2")
        self.assertEqual(instruction.bytes, bytes.fromhex("0f 0b"))

    def test_arm_instruction_decodes_in_arm_mode(self):
        instruction = disassemble(
            bytes.fromhex("00 f0 20 e3"),
            CS_ARCH_ARM,
            CS_MODE_ARM,
        )[0]

        self.assertEqual(instruction.mnemonic, "nop")
        self.assertEqual(instruction.size, 4)

    def test_arm_instruction_decodes_in_thumb_mode(self):
        instruction = disassemble(
            bytes.fromhex("00 bf"),
            CS_ARCH_ARM,
            CS_MODE_THUMB,
        )[0]

        self.assertEqual(instruction.mnemonic, "nop")
        self.assertEqual(instruction.size, 2)

    def test_arm64_instruction_decodes(self):
        instruction = disassemble(
            bytes.fromhex("1f 20 03 d5"),
            CS_ARCH_ARM64,
            CS_MODE_ARM,
        )[0]

        self.assertEqual(instruction.mnemonic, "nop")
        self.assertEqual(instruction.size, 4)

    def test_architecture_specific_address_is_reported(self):
        instruction = disassemble(
            bytes.fromhex("00 bf"),
            CS_ARCH_ARM,
            CS_MODE_THUMB,
            address=0x8000,
        )[0]

        self.assertEqual(instruction.address, 0x8000)

    def test_invalid_architecture_error_is_not_swallowed(self):
        with self.assertRaises(CsError):
            disassemble(b"\x90", -1, CS_MODE_64)

    def test_invalid_mode_error_is_not_swallowed(self):
        with self.assertRaises(CsError):
            disassemble(b"\x90", CS_ARCH_X86, 12345)

    def test_non_bytes_input_error_is_not_swallowed(self):
        with self.assertRaises(TypeError):
            self.decode_x86("90")

    def test_none_input_error_is_not_swallowed(self):
        with self.assertRaises(TypeError):
            self.decode_x86(None)

    def test_bytearray_is_accepted_as_bytes_like_input(self):
        instructions = self.decode_x86(bytearray(b"\x90"))

        self.assertEqual([item.mnemonic for item in instructions], ["nop"])

    def test_memoryview_is_accepted_as_bytes_like_input(self):
        instructions = self.decode_x86(memoryview(b"\x90"))

        self.assertEqual([item.mnemonic for item in instructions], ["nop"])

    def test_repeated_calls_return_consistent_results(self):
        code = bytes.fromhex("48 89 d8 c3")

        first = self.decode_x86(code, address=0x2000)
        second = self.decode_x86(code, address=0x2000)

        self.assertEqual(
            [(item.address, item.mnemonic, item.op_str) for item in first],
            [(item.address, item.mnemonic, item.op_str) for item in second],
        )

    def test_each_call_uses_its_own_start_address(self):
        first = self.decode_x86(b"\x90", address=0x10)[0]
        second = self.decode_x86(b"\x90", address=0x20)[0]

        self.assertEqual(first.address, 0x10)
        self.assertEqual(second.address, 0x20)


if __name__ == "__main__":
    unittest.main()
