# purpose: Insert instrumentation to code branch
import random
import enum

TrampolineSymbols = ['__afl_maybe_log', '__trace_pc']

class PayloadMode(enum.IntEnum):
    AFL_MODE = 0
    TRACE_MODE = 1

class AFLTrampoline:
    MAP_SIZE = 1 << 20
    reloc_symbol = '__afl_maybe_log'
    reloc_offset = 7
    size = 16

    """
    90 
    68 xx xx xx xx                  push    0%xh
    E8 xx xx xx xx                  call    __afl_maybe_log
    48 8D 64 24 08                  lea     rsp, [rsp+8]      ; "add rsp, 8" will change eflags register
    """
    @staticmethod
    def GetBytes():
        result = b'\x90\x68'
        result += random.randrange(AFLTrampoline.MAP_SIZE).to_bytes(4, 'little', signed=False)
        result += b'\xE8\x00\x00\x00\x00'
        result += b'\x48\x8D\x64\x24\x08'
        
        return result


class TraceTrampoline:
    reloc_symbol = '__trace_pc'
    reloc_offset = 1
    size = 5

    """
    E8 xx xx xx xx                  call    __trace_pc
    """
    @staticmethod
    def GetBytes():
        return b'\xE8\x00\x00\x00\x00'
