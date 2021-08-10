import re
from idc import *
from idaapi import *

pat1 = re.compile(r"dq\s+offset")
pat2 = re.compile(r"xmmword\s+offset")
cnt = 0
# recognize some possible pointers, which points inside the PE address range
def SearchInSeg(segStart, segEnd):
    global cnt
    for addr in range(segStart, segEnd, 8):
        line = GetDisasm(addr)
        if pat1.search(line):                   # skip the recognized pointer
            continue
        if pat2.search(line):
            MakeUnknown(addr, 16, 2)
            MakeQword(addr)
            MakeQword(addr+8)
            continue
        value = Qword(addr)
        if value>=MinEA() and value<=MaxEA():   # a suspicious address
            # if there is no Xref to this, then it could be a pointer
            foundXref = False
            for o in [2,4,6]:
                if RfirstB(addr+o) != BADADDR or DfirstB(addr+o) != BADADDR:
                    foundXref = True
                    break
            if foundXref:
                continue
            MakeUnknown(addr, 8, 2)
            MakeQword(addr)
            print('[!] check suspicious pointer at:0x%x'%addr)
            cnt+=1

addr = get_imagebase()
while addr != BADADDR:
    segname = SegName(addr)
    if segname == '.data' or segname == '.rdata':
        SearchInSeg(addr, SegEnd(addr))
    addr = NextSeg(addr)