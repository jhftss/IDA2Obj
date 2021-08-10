from idc import *
from idaapi import *


ImageBase = get_imagebase()
filterSet = set()

def TailExplore(addr):
    if Dword(addr) != 0 or Name(addr) != "":
        return False
    MakeUnknown(addr, 4, 2)
    MakeDword(addr)
    return True

def ParseTypeDes(addr):
    if addr in filterSet:
        return
    filterSet.add(addr)
    MakeQword(addr)
    addr+=8
    MakeQword(addr) # void *space
    addr+=8
    MakeStr(addr, BADADDR)
    while Byte(addr) != 0:
        addr+=1
    addr+=1 # skip '\0'
    algnBase = addr
    while Byte(addr) == 0:
        addr+=1
    MakeAlign(algnBase, addr-algnBase, 0)

def ParseBaseClassDes(addr):
    if addr in filterSet:
        return
    filterSet.add(addr)
    MakeUnknown(addr, 28, 2)
    
    MakeDword(addr)
    OpOffEx(addr, 0, REF_OFF64|REFINFO_RVA, -1, 0, 0)
    ParseTypeDes(ImageBase + Dword(addr))
    addr+=4
    
    for i in range(0, 5):
        MakeDword(addr)
        addr+=4
    
    MakeDword(addr)
    OpOffEx(addr, 0, REF_OFF64|REFINFO_RVA, -1, 0, 0)
    ParseClassHier(ImageBase + Dword(addr))
    addr+=4
    
    while TailExplore(addr):
        addr+=4

def ParseBaseClassArray(addr, size):
    if addr in filterSet:
        return
    filterSet.add(addr)
    MakeUnknown(addr, size*4, 2)
    
    for i in range(0, size):
        MakeDword(addr)
        OpOffEx(addr, 0, REF_OFF64|REFINFO_RVA, -1, 0, 0)
        ParseBaseClassDes(ImageBase + Dword(addr))
        addr+=4
    
    while TailExplore(addr):
        addr+=4

def ParseClassHier(addr):
    if addr in filterSet:
        return
    filterSet.add(addr)
    MakeUnknown(addr, 16, 2)
    
    for i in range(0, 4):
        MakeDword(addr)
        addr+=4
    
    OpOffEx(addr-4, 0, REF_OFF64|REFINFO_RVA, -1, 0, 0)
    ParseBaseClassArray(ImageBase + Dword(addr-4), Dword(addr-8))
    
    while TailExplore(addr):
        addr+=4

def ParseObjLocator(addr):
    if addr in filterSet:
        return
    filterSet.add(addr)
    MakeUnknown(addr, 24, 2)
    
    ParseTypeDes(ImageBase + Dword(addr+12))
    ParseClassHier(ImageBase + Dword(addr+16))
    
    for i in range(0, 3):
        MakeDword(addr)
        addr+=4
    
    for i in range(0, 3):
        MakeDword(addr)
        OpOffEx(addr, 0, REF_OFF64|REFINFO_RVA, -1, 0, 0)
        addr+=4
    
    while TailExplore(addr):
        addr+=4

cnt = 0
rdataStart = SegByBase(SegByName(".rdata"))
rdataEnd = SegEnd(rdataStart)
for addr in range(rdataStart, rdataEnd, 4):
    dname = Demangle(Name(addr), 0)
    if dname and 'RTTI Complete Object Locator' in dname:
        ParseObjLocator(addr)
        cnt += 1
print("%d RTTI structures has been fixed."%cnt)