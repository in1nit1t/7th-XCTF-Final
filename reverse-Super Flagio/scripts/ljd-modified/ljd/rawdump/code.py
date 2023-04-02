#
# Copyright (C) 2013 Andrian Nord. See Copyright Notice in main.py
#

from ljd.util.log import errprint

import ljd.bytecode.instructions as instructions


_OPCODES = (
	(0x0, instructions.ISLT),
	(0x1, instructions.ISGE),
	(0x2, instructions.ISLE),
	(0x3, instructions.ISGT),
	(0x4, instructions.ISEQV),
	(0x5, instructions.ISNEV),
	(0x6, instructions.ISEQS),
	(0x7, instructions.ISNES),
	(0x8, instructions.ISEQN),
	(0x9, instructions.ISNEN),
	(0xa, instructions.ISEQP),
	(0xb, instructions.ISNEP),
	(0xc, instructions.KSTR),
	(0xd, instructions.KCDATA),
	(0xe, instructions.KSHORT),
	(0xf, instructions.KNUM),
	(0x10, instructions.KPRI),
	(0x11, instructions.KNIL),
	(0x12, instructions.ISTC),
	(0x13, instructions.ISFC),
	(0x14, instructions.IST),
	(0x15, instructions.ISF),
	(0x16, instructions.ISTYPE),
	(0x17, instructions.ISNUM),
	(0x18, instructions.MOV),
	(0x19, instructions.NOT),
	(0x1a, instructions.UNM),
	(0x1b, instructions.LEN),
	(0x1c, instructions.RETM),
	(0x1d, instructions.RET),
	(0x1e, instructions.RET0),
	(0x1f, instructions.RET1),
	(0x20, instructions.ADDVN),
	(0x21, instructions.SUBVN),
	(0x22, instructions.MULVN),
	(0x23, instructions.DIVVN),
	(0x24, instructions.MODVN),
	(0x25, instructions.ADDNV),
	(0x26, instructions.SUBNV),
	(0x27, instructions.MULNV),
	(0x28, instructions.DIVNV),
	(0x29, instructions.MODNV),
	(0x2a, instructions.ADDVV),
	(0x2b, instructions.SUBVV),
	(0x2c, instructions.MULVV),
	(0x2d, instructions.DIVVV),
	(0x2e, instructions.MODVV),
	(0x2f, instructions.POW),
	(0x30, instructions.CAT),
	(0x31, instructions.UGET),
	(0x32, instructions.USETV),
	(0x33, instructions.USETS),
	(0x34, instructions.USETN),
	(0x35, instructions.USETP),
	(0x36, instructions.UCLO),
	(0x37, instructions.FNEW),
	(0x38, instructions.TNEW),
	(0x39, instructions.TDUP),
	(0x3a, instructions.GGET),
	(0x3b, instructions.GSET),
	(0x3c, instructions.TGETV),
	(0x3d, instructions.TGETS),
	(0x3e, instructions.TGETB),
	(0x3f, instructions.TGETR),
	(0x40, instructions.TSETV),
	(0x41, instructions.TSETS),
	(0x42, instructions.TSETB),
	(0x43, instructions.TSETM),
	(0x44, instructions.TSETR),
	(0x45, instructions.CALLM),
	(0x46, instructions.CALL),
	(0x47, instructions.CALLMT),
	(0x48, instructions.CALLT),
	(0x49, instructions.ITERC),
	(0x4a, instructions.ITERN),
	(0x4b, instructions.VARG),
	(0x4c, instructions.ISNEXT),
	(0x4d, instructions.FORI),
	(0x4e, instructions.JFORI),
	(0x4f, instructions.FORL),
	(0x50, instructions.IFORL),
	(0x51, instructions.JFORL),
	(0x52, instructions.ITERL),
	(0x53, instructions.IITERL),
	(0x54, instructions.JITERL),
	(0x55, instructions.LOOP),
	(0x56, instructions.ILOOP),
	(0x57, instructions.JLOOP),
	(0x58, instructions.JMP),
	(0x59, instructions.FUNCF),
	(0x5a, instructions.IFUNCF),
	(0x5b, instructions.JFUNCF),
	(0x5c, instructions.FUNCV),
	(0x5d, instructions.IFUNCV),
	(0x5e, instructions.JFUNCV),
	(0x5f, instructions.FUNCC),
	(0x60, instructions.FUNCCW)
)


_MAP = [None] * 256


def read(parser):
	global _MAP

	codeword = parser.stream.read_uint(4)

	opcode = codeword & 0xFF

	instruction_class = _MAP[opcode]

	if instruction_class is None:
		errprint("Warning: unknown opcode {0:08x}", opcode)
		instruction_class = instructions.UNKNW  # @UndefinedVariable #zzw.20180714

	instruction = instruction_class()

	if instruction_class.opcode != opcode:
		instruction.opcode = opcode

	_set_instruction_operands(parser, codeword, instruction)

	return instruction


def _set_instruction_operands(parser, codeword, instruction):
	if instruction.args_count == 3:
		A = (codeword >> 8) & 0xFF
		CD = (codeword >> 16) & 0xFF
		B = (codeword >> 24) & 0xFF
	else:
		A = (codeword >> 8) & 0xFF
		CD = (codeword >> 16) & 0xFFFF

	if instruction.A_type is not None:
		instruction.A = _process_operand(parser, instruction.A_type, A)

	if instruction.B_type is not None:
		instruction.B = _process_operand(parser, instruction.B_type, B)

	if instruction.CD_type is not None:
		instruction.CD = _process_operand(parser, instruction.CD_type, CD)

	if instruction.opcode == instructions.KSTR.opcode:
		instruction.A -= 1
	if instruction.opcode == instructions.MOV.opcode:
		instruction.A -= 1
	if instruction.opcode == instructions.CAT.opcode:
		instruction.A -= 1
		instruction.B -= 1
		instruction.CD -= 1


def _process_operand(parser, operand_type, operand):
	if operand_type == instructions.T_STR			\
			or operand_type == instructions.T_TAB	\
			or operand_type == instructions.T_FUN	\
			or operand_type == instructions.T_CDT:
		return parser.complex_constants_count - operand - 1
	elif operand_type == instructions.T_JMP:
		return operand - 0x8000
	else:
		return operand


def _init():
	global _OPCODES, _MAP
	opcode = 0
	for instruction in _OPCODES:
		_MAP[opcode] = instruction[1]
		opcode = opcode + 1

	del globals()["_init"]
	del globals()["_OPCODES"]

_init()
