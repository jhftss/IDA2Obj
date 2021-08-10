import re
from idc import *
from idaapi import *


ImageBase = get_imagebase()


def fix(addr):
    #print("[-] FixRVA at 0x%x"%addr)
    op1Type = GetOpType(addr, 0)
    op2Type = GetOpType(addr, 1)
    if op1Type != 4 and op2Type != 4: raise Exception('Not found OpType 4(Base + Index + Displacement) at 0x%x'%addr)
    #OpOffEx(addr, 0, REF_OFF64|REFINFO_RVA, -1, 0, 0) # not work, add custom reference as a workaround

pat1 = re.compile(r"lea\s+([a-z0-9]+),\s*__ImageBase")
pat2 = re.compile(r"\[([a-z0-9]+)\+([a-z0-9]+)(\*[0-9]+)?\+([0-9A-F]+)h\]")
pat3 = re.compile(r"mov\s+([a-z0-9]+),\s*([a-z0-9]+)")

keyRegs = []
addr = NextFunction(0)
funcEnd = GetFunctionAttr(addr, FUNCATTR_END)
while addr != BADADDR:
    if addr > funcEnd:
        funcEnd = GetFunctionAttr(addr, FUNCATTR_END)
        keyRegs = []
    line = GetDisasm(addr)
    
    m1 = pat1.search(line)
    m2 = pat2.search(line)
    m3 = pat3.search(line)
    if m1:
        keyRegs.append(m1.group(1))
    elif m2:
        firstReg = m2.group(1)
        secReg = m2.group(2)
        offset = int(m2.group(4), 16)
        if (firstReg in keyRegs or secReg in keyRegs) and offset>0x1000:
            fix(addr)
            # workaround: add an Informational data reference.
            toAddr = ImageBase + offset
            add_dref(addr, toAddr, ida_xref.dr_I)
            MakeComm(addr, 'ref to 0x%x'%toAddr)
            if Name(toAddr) == '' and Name(ItemHead(toAddr)) == '': MakeName(toAddr, 'myref_%x'%toAddr)
    elif m3:
        firstReg = m3.group(1)
        secReg = m3.group(2)
        if firstReg in keyRegs:
            keyRegs.remove(firstReg)
        elif secReg in keyRegs:
            keyRegs.append(firstReg)
    addr = FindCode(addr, 1)
print("RVA fixed.")