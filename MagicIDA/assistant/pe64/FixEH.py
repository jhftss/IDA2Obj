from idc import *
from idaapi import *


ImageBase = get_imagebase()
filterSet = set()

structMap = dict()
def MyMakeStruct(addr, dummy, structName):
    (structSize, structLayout) = structMap[structName] # structName must be registered to the structMap
    MakeUnknown(addr, structSize, 2)
    MakeComm(addr, 'struct %s (size = %d)'%(structName, structSize))
    for c in structLayout:
        if c == 'r': # dd rva
            MakeDword(addr)
            if Dword(addr) > 8: OpOffEx(addr, 0, REF_OFF64|REFINFO_RVA, -1, 0, 0)
            addr += 4
        elif c == '8':
            MakeQword(addr) # if it is a pointer, it will display as "dq offset"
            addr += 8
        elif c == '4':
            MakeDword(addr)
            addr += 4
        elif c == '2':
            MakeWord(addr)
            addr += 2
        elif c == '1':
            MakeByte(addr)
            addr += 1
        else:
            print('[!] Error, unknown struct %s with layout %s'%(structName, structLayout))
            return

def ParseCHandlerData(addr):
    if addr in filterSet:
        return
    filterSet.add(addr)
    
    (arrSize, addr) = ReadDword(addr)
    
    MakeUnknown(addr, arrSize * 16, 2)
    for i in range(0, arrSize):
        MyMakeStruct(addr, -1, "C_SCOPE_TABLE")
        addr += 16
    return addr

def ParseUnwindInfo(infoAddr):
    if infoAddr == ImageBase:
        return False

    flag = Byte(infoAddr) >> 3
    if infoAddr in filterSet:
        return True
    filterSet.add(infoAddr)

    MakeName(infoAddr, "unwindinfo_%x"%(infoAddr))
    MakeStructEx(infoAddr, -1, "UNWIND_INFO_HDR")
    numOfCodes = Byte(infoAddr + 2)
    infoAddr+=4
    
    for i in range(0, numOfCodes):
        MakeStructEx(infoAddr, -1, "UNWIND_CODE")
        infoAddr+=2
    if numOfCodes%2 == 1:
        infoAddr += 2
    if flag >= 4:   # RUNTIME_FUNCTION
        MakeUnknown(infoAddr, 12, 2)
        MyMakeStruct(infoAddr, -1, "RUNTIME_FUNCTION")
        infoAddr+=12
    elif flag != 0: # has SEH
        (dispLSH, infoAddr) = ReadRVA(infoAddr)   # language specific handler
        lshName = Name(ImageBase + dispLSH)
        if 'CxxFrameHandler' in lshName:
            (dispFuncInfo, _) = ReadRVA(infoAddr)
            ParseFuncInfo(ImageBase + dispFuncInfo)
        elif 'C_specific_handler' in lshName:
            ParseCHandlerData(infoAddr)
        elif lshName == "__GSHandlerCheck":
            ReadDword(infoAddr)
        elif lshName == "__GSHandlerCheck_SEH":
            infoAddr = ParseCHandlerData(infoAddr)
            ReadDword(infoAddr)
        elif "GSHandlerCheck_EH" in lshName:
            (dispFuncInfo, infoAddr) = ReadRVA(infoAddr)
            ParseFuncInfo(ImageBase + dispFuncInfo)
            ReadDword(infoAddr)
        else:
            print('0x%x: unknown language specific handler:%s'%(infoAddr, lshName))
    return True

def ParseFuncInfo3(funcInfoAddr):
    if funcInfoAddr in filterSet:
        return
    filterSet.add(funcInfoAddr)
    
    MakeUnknown(funcInfoAddr, 40, 2)
    
    MakeName(funcInfoAddr, "funcInfo_%x"%(funcInfoAddr))
    MyMakeStruct(funcInfoAddr, -1, "FuncInfo")
    
    unwindArrSize = Dword(funcInfoAddr+4)
    if unwindArrSize > 0:
        base1 = ImageBase + Dword(funcInfoAddr+8)
        MakeName(base1, "unwindMap_%x"%(base1))
        for r1 in range(0, unwindArrSize):
            ParseUnwindMapEntry(base1 + r1*8)
    
    tryBlockArrSize = Dword(funcInfoAddr+12)
    if tryBlockArrSize > 0:
        base2 = ImageBase + Dword(funcInfoAddr+16)
        MakeName(base2, "tryBlock_%x"%(base2))
        for r2 in range(0, tryBlockArrSize):
            ParseTryBlockMapEntry(base2 + r2*20)
    
    stateArrSize = Dword(funcInfoAddr+20)
    if stateArrSize > 0:
        base3 = ImageBase + Dword(funcInfoAddr+24)
        MakeName(base3, "ip2state_%x"%(base3))
        for r3 in range(0, stateArrSize):
            ParseIP2StateMapEntry(base3 + r3*8)
    
    ParseExpectedList(ImageBase + Dword(funcInfoAddr+32))

def ParseUnwindMapEntry(addr):
    if addr in filterSet:
        return
    filterSet.add(addr)
    
    MakeUnknown(addr, 8, 2)
    MyMakeStruct(addr, -1, "UnwindMapEntry")

def ParseTryBlockMapEntry(addr):
    if addr in filterSet:
        return
    filterSet.add(addr)
    
    MakeUnknown(addr, 20, 2)
    MyMakeStruct(addr, -1, "TryBlockMapEntry")
    
    size = Dword(addr+12)
    if size > 0:
        base = ImageBase + Dword(addr+16)
        MakeName(base, "catchBlock_%x"%(base))
        for r4 in range(0, size):
            ParseCatchBlockMapEntry(base + r4*20)

def ParseCatchBlockMapEntry(addr):
    if addr in filterSet:
        return
    filterSet.add(addr)
    
    MakeUnknown(addr, 20, 2)
    MyMakeStruct(addr, -1, "HandlerType")

def ParseIP2StateMapEntry(addr):
    if addr in filterSet:
        return
    filterSet.add(addr)
    
    MakeUnknown(addr, 8, 2)
    MyMakeStruct(addr, -1, "IPtoStateMap")

def ParseExpectedList(addr):
    if addr == ImageBase or addr in filterSet:
        return
    filterSet.add(addr)
    
    MakeUnknown(addr, 8, 2)
    MyMakeStruct(addr, -1, "ESTypeList")
    size = Dword(addr)
    if size > 0:
        base = ImageBase + Dword(addr+4)
        MakeName(base, "expectedList_%x"%(base))
        for i in range(0, size):
            MyMakeStruct(base + i*20, -1, "HandlerType")

# below parse functions is for FH4 (new feature in VS2019 link program, to reduce EH data size)
# reference1: https://devblogs.microsoft.com/cppblog/making-cpp-exception-handling-smaller-x64/
# reference2: https://github.com/light-tech/MSCpp/blob/master/include/msvc/ehdata4_export.h

# Constants for decompression.
# XXX0: 0,2,4,6,8,10,12,14
# XX01: 1,5,9,13
# X011: 3,11
# 0111: 7
# 1111: 15
s_negLengthTab = [
    -1,    # 0
    -2,    # 1
    -1,    # 2
    -3,    # 3

    -1,    # 4
    -2,    # 5
    -1,    # 6
    -4,    # 7

    -1,    # 8
    -2,    # 9
    -1,    # 10
    -3,    # 11

    -1,    # 12
    -2,    # 13
    -1,    # 14
    -5    # 15
]

s_shiftTab = [
    32 - 7 * 1,    # 0
    32 - 7 * 2,    # 1
    32 - 7 * 1,    # 2
    32 - 7 * 3,    # 3

    32 - 7 * 1,    # 4
    32 - 7 * 2,    # 5
    32 - 7 * 1,    # 6
    32 - 7 * 4,    # 7

    32 - 7 * 1,    # 8
    32 - 7 * 2,    # 9
    32 - 7 * 1,    # 10
    32 - 7 * 3,    # 11

    32 - 7 * 1,    # 12
    32 - 7 * 2,    # 13
    32 - 7 * 1,    # 14
    0             # 15
]


def ReadDword(p):
    MakeUnknown(p, 4, 2)
    MakeDword(p)
    return (Dword(p), p+4)

def ReadRVA(p):
    MakeUnknown(p, 4, 2)
    MakeDword(p)
    OpOffEx(p, 0, REF_OFF64|REFINFO_RVA, -1, 0, 0)
    return (Dword(p), p+4)

# .NET uint32_t integer compression scheme:
# Compresses up to 32 bits into 1-5 bytes, depending on value
# Lower 4 bits of the MSB determine the number of bytes to read:
# XXX0: 1 byte
# XX01: 2 bytes
# X011: 3 bytes
# 0111: 4 bytes
# 1111: 5 bytes
#def getNETencoded(value):
#    if value < 128:
#        return ((value << 1) + 0, 1)
#    elif value < 128 * 128:
#        return ((value << 2) + 1, 2)
#    elif value < 128 * 128 * 128:
#        return ((value << 3) + 3, 3)
#    elif value < 128 * 128 * 128 * 128:
#        return ((value << 4) + 7, 4)
#    else:
#        return ((value<<8) + 15, 5)

#def Decompress(value):
#    lengthBits = value & 0x0F
#    negLength = s_negLengthTab[lengthBits]
#    shift = s_shiftTab[lengthBits]
#    return value >>(shift-(4+negLength)*8)

def ReadCompressedInt(p):
    pori = p
    lengthBits = Byte(p) & 0x0F
    negLength = s_negLengthTab[lengthBits]
    shift = s_shiftTab[lengthBits]
    p -= negLength
    v = Dword(p - 4)
    v >>= shift
    
    MakeUnknown(pori, p-pori, 2)
    MakeByte(pori)
    MakeArray(pori, p-pori)
    return (v, p)

def ParseUnwindMap4(p):
    if p in filterSet:
        return
    filterSet.add(p)
    pp = p
    (numEntries, p) = ReadCompressedInt(p)
    for i in range(numEntries):
        (nextOffset, p) = ReadCompressedInt(p)
        type = nextOffset & 3
        nextOffset >>= 2
        #print("type: %d, nextOffset: %x"%(type, nextOffset))
        if type == 1 or type == 2:
            (_, p) = ReadRVA(p) # action
            (_, p) = ReadCompressedInt(p) # object
        elif type == 3:
            (_, p) = ReadRVA(p) # action
    MakeName(pp, "unwindMap4_%x"%pp)

def ParseTryBlock4(p):
    if p in filterSet:
        return
    filterSet.add(p)
    pp = p
    (numEntries, p) = ReadCompressedInt(p)
    for i in range(numEntries):
        (_, p) = ReadCompressedInt(p) # tryLow
        (_, p) = ReadCompressedInt(p) # tryHigh
        (_, p) = ReadCompressedInt(p) # catchHigh
        (dispHandlerArray, p) = ReadRVA(p)
        ParseCatchBlock4(ImageBase + dispHandlerArray)
    MakeName(pp, "tryBlock4_%x"%pp)

def ParseCatchBlock4(p):
    if p in filterSet:
        return
    filterSet.add(p)
    MakeName(p, "catchBlock4_%x"%p)
    (numEntries, p) = ReadCompressedInt(p)
    for i in range(numEntries):
        MakeUnkn(p, 0)
        MakeByte(p)
        header = Byte(p)
        p += 1
        if header & 1:
            (_, p) = ReadCompressedInt(p) # adjectives
        if header & 2:
            (dispType, p) = ReadRVA(p)
        if header & 4:
            (_, p) = ReadCompressedInt(p) # dispCatchObj
        (dispOfHandler, p) = ReadRVA(p)
        
        # read continuationAddress[2]
        contAddr = (header>>4) & 3
        if header & 8: # is RVA
            if contAddr == 1:
                (_, p) = ReadRVA(p)
            elif contAddr == 2:
                (_, p) = ReadRVA(p)
                (_, p) = ReadRVA(p)
        else: # _functionStart
            funcName = "tag_%x"%(currentFuncAddr)
            MakeName(currentFuncAddr, funcName)
            if contAddr == 1:
                (cont0, pnext) = ReadCompressedInt(p)
                if cont0 != 0:
                    continuation0 = currentFuncAddr + cont0
                    contName = "tag_%x"%continuation0
                    MakeName(continuation0, contName)
                    MakeName(p, "%s_FIXME_%s_unique%x"%(contName, funcName, p)) # avoid name confliction, using SN_FORCE(0x800) in IDA7
                p = pnext
            elif contAddr == 2:
                (cont0, pnext) = ReadCompressedInt(p)
                if cont0 != 0:
                    continuation0 = currentFuncAddr + cont0
                    contName = "tag_%x"%continuation0
                    MakeName(continuation0, contName)
                    MakeName(p, "%s_FIXME_%s_unique%x"%(contName, funcName, p))
                p = pnext
                (cont1, pnext) = ReadCompressedInt(p)
                if cont1 != 0:
                    continuation1 = currentFuncAddr + cont1
                    contName = "tag_%x"%continuation1
                    MakeName(continuation1, contName)
                    MakeName(p, "%s_FIXME_%s_unique%x"%(contName, funcName, p))
                p = pnext


def ParseIP2State4(p, funcStart):
    if p in filterSet:
        return
    filterSet.add(p)
    pp = p
    prevIp = funcStart
    prevName = "tag_%x"%(prevIp)
    MakeName(prevIp, prevName)
    (numEntries, p) = ReadCompressedInt(p)
    for i in range(numEntries):
        (deltaIp, pnext) = ReadCompressedInt(p)
        if deltaIp != 0: # some state cover funcStart
            currIp = prevIp + deltaIp
            currName = 'tag_%x'%currIp
            if Byte(currIp) == 0xcc: MakeUnknown(currIp, 1, 0) # align bytes at the function end cause rename failure
            MakeName(currIp, currName)
            MakeName(p, '%s_FIXME_%s'%(currName, prevName))
            prevIp = currIp
            prevName = currName
        p = pnext
        (EHState, p) = ReadCompressedInt(p) # EHState is an index like -1,0,1,2,3
    MakeName(pp, "ip2State4_%x"%pp)

def ParseSepIp2State4(p):
    if p in filterSet:
        return
    filterSet.add(p)
    pp = p
    (numEntries, p) = ReadCompressedInt(p)
    for i in range(numEntries):
        (funcRVA, p) = ReadRVA(p)
        (dispIPtoStateMap, p) = ReadRVA(p)
        ParseIP2State4(ImageBase + dispIPtoStateMap, ImageBase + funcRVA)
    MakeName(pp, "sepIp2State4_%x"%pp)

def ParseFuncInfo4(p):
    if p in filterSet:
        return
    filterSet.add(p)
    MakeName(p, "funcInfo4_%x"%p)
    MakeUnkn(p, 0)
    MakeByte(p)
    header = Byte(p)
    p += 1

    if header & 4: # bbtFlags
        (_, p) = ReadCompressedInt(p)

    if header & 8: # UnwindMap
        (dispUnwindMap, p) = ReadRVA(p)
        ParseUnwindMap4(ImageBase + dispUnwindMap)

    if header & 16: # TryBlockMap
        (dispTryBlockMap, p) = ReadRVA(p)
        ParseTryBlock4(ImageBase + dispTryBlockMap)

    # Find the correct one if this is a separated segment
    if header & 2: # isSeparated
        (dispSepIPtoStateMap, p) = ReadRVA(p)
        ParseSepIp2State4(ImageBase + dispSepIPtoStateMap)
    # Otherwise, the table is directly encoded in the function info
    else:
        (dispIPtoStateMap, p) = ReadRVA(p)
        ParseIP2State4(ImageBase + dispIPtoStateMap, currentFuncAddr)

    if header & 1: # isCatch
        (_, p) = ReadCompressedInt(p) # dispFrame


def ParseFuncInfo(p):
    if Dword(p)>>4 == 0x1993052: # 0x19930520, 0x19930521, 0x19930522
        ParseFuncInfo3(p)
    else:
        ParseFuncInfo4(p)



def ParseThrowInfo(addr):
    if addr in filterSet:
        return
    filterSet.add(addr)
    
    MyMakeStruct(addr, -1, "_ThrowInfo")

    pCatchableTypeArray = ImageBase + Dword(addr+12)
    if pCatchableTypeArray != ImageBase:
        (size, _) = ReadDword(pCatchableTypeArray)
        for i in range(1, size+1):
            p = (pCatchableTypeArray + i*4)
            (dispCatchableType, _) = ReadRVA(p)
            ParseCatchableType(ImageBase + dispCatchableType)

def ParseCatchableType(addr):
    if addr in filterSet:
        return
    filterSet.add(addr)
    
    MyMakeStruct(addr, -1, "CatchableType")

structMap['RUNTIME_FUNCTION'] = (12, 'rrr')
structMap['FuncInfo'] = (0x28, '44r4r4r4r4')
#sid = AddStrucEx(-1, "FuncInfo", 0)
#if sid != BADADDR:
#    memNames = ["magicNumber", "maxState", "pUnwindMap", "nTryBlocks", "pTryBlockMap",
#    "nIPMapEntries", "pIPtoStateMap", "unknown", "pESTypeList", "EHFlags"]
#    memComments = ["compiler version", "number of entries in unwind table", 
#    "table of unwind destructors", "number of try blocks in the function", 
#    "mapping of catch blocks to try blocks","number of IP2State entries", "IPtoState map", 
#    "unknown", "expected exceptions list", "bit 0 set if function was compiled with /EHs"]
#    for i in range(0, 10):
#        if i%2 == 0 and i > 0:
#            AddStrucMember(sid, memNames[i], i*4, 0x25500400, ImageBase, 4, 0XFFFFFFFFFFFFFFFF, 0, 0x000039)
#        else:
#            AddStrucMember(sid, memNames[i], -1, (FF_DWRD|FF_DATA), -1, 4)
#        SetMemberComment(sid, i*4, memComments[i], 1)

structMap['UnwindMapEntry'] = (8, '4r')
#sid = AddStrucEx(-1, "UnwindMapEntry", 0)
#if sid != BADADDR:
#    AddStrucMember(sid, "toState", -1, (FF_DWRD|FF_DATA), -1, 4)
#    SetMemberComment(sid, 0, "target state", 1)
#    AddStrucMember(sid, "action", 4, 0x25500400, ImageBase, 4, 0XFFFFFFFFFFFFFFFF, 0, 0x000039)
#    SetMemberComment(sid, 4, "action to perform (unwind funclet address)", 1)

structMap['IPtoStateMap'] = (8, 'r4')
#sid = AddStrucEx(-1, "IPtoStateMap", 0)
#if sid != BADADDR:
#    AddStrucMember(sid, "action", 0, 0x25500400, ImageBase, 4, 0XFFFFFFFFFFFFFFFF, 0, 0x000039)
#    SetMemberComment(sid, 0, "action to perform", 1)
#    AddStrucMember(sid, "toState", -1, (FF_DWRD|FF_DATA), -1, 4)
#    SetMemberComment(sid, 0, "target state", 1)

structMap['TryBlockMapEntry'] = (0x14, '4444r')
#sid = AddStrucEx(-1, "TryBlockMapEntry", 0)
#if sid != BADADDR:
#    memNames = ["tryLow", "tryHigh", "catchHigh", "nCatches"]
#    memComments = ["", "", "highest state inside catch handlers of this try", "number of catch handlers"]
#    for i in range(0, 4):
#        AddStrucMember(sid, memNames[i], -1, (FF_DWRD|FF_DATA), -1, 4)
#        SetMemberComment(sid, i*4, memComments[i], 1)
#    AddStrucMember(sid, "pHandlerArray", 16, 0x25500400, ImageBase, 4, 0XFFFFFFFFFFFFFFFF, 0, 0x000039)
#    SetMemberComment(sid, 16, "catch handlers table", 1)

structMap['HandlerType'] = (0x14, '4r4r4')
#sid = AddStrucEx(-1, "HandlerType", 0)
#if sid != BADADDR:
#    AddStrucMember(sid, "adjectives", -1, (FF_DWRD|FF_DATA), -1, 4)
#    SetMemberComment(sid, 0, "0x01: const, 0x02: volatile, 0x08: reference", 1)
#    AddStrucMember(sid, "pType", 4, 0x25500400, ImageBase, 4, 0XFFFFFFFFFFFFFFFF, 0, 0x000039)
#    SetMemberComment(sid, 4, "RTTI descriptor of the exception type. 0=any (ellipsis)", 1)
#    AddStrucMember(sid, "dispCatchObj", -1, (FF_DWRD|FF_DATA), -1, 4)
#    SetMemberComment(sid, 8, "ebp-based offset of the exception object in the function stac", 1)
#    AddStrucMember(sid, "addressOfHandler", 12, 0x25500400, ImageBase, 4, 0XFFFFFFFFFFFFFFFF, 0, 0x000039)
#    SetMemberComment(sid, 12, "address of the catch handler code", 1)
#    AddStrucMember(sid, "unknown", -1, (FF_DWRD|FF_DATA), -1, 4)

structMap['ESTypeList'] = (8, '4r')
#sid = AddStrucEx(-1, "ESTypeList", 0)
#if sid != BADADDR:
#    AddStrucMember(sid, "nCount", -1, (FF_DWRD|FF_DATA), -1, 4)
#    SetMemberComment(sid, 0, "number of entries in the list", 1)
#    AddStrucMember(sid, "pTypeArray", 4, 0x25500400, ImageBase, 4, 0XFFFFFFFFFFFFFFFF, 0, 0x000039)
#    SetMemberComment(sid, 4, "list of exceptions", 1)

structMap['C_SCOPE_TABLE'] = (0x10, 'rrrr')
#sid = GetStrucIdByName("C_SCOPE_TABLE")
#if sid != BADADDR:
#    SetMemberType(sid, 12, 0x25500400, ImageBase, 1, 0XFFFFFFFFFFFFFFFF, 0, 0x000039)

structMap['_ThrowInfo'] = (0x10, '4rrr')
#sid = AddStrucEx(-1, "_ThrowInfo", 0)
#if sid != BADADDR:
#    AddStrucMember(sid, "attributes", -1, (FF_DWRD|FF_DATA), -1, 4)
#    SetMemberComment(sid, 0, "Throw Info attributes (Bit field)", 1)
#    AddStrucMember(sid, "pmfnUnwind", 4, 0x25500400, ImageBase, 4, 0XFFFFFFFFFFFFFFFF, 0, 0x000039)
#    SetMemberComment(sid, 4, "rva of Destructor to call when exception has been handled or aborted", 1)
#    AddStrucMember(sid, "pForwardCompat", 8, 0x25500400, ImageBase, 4, 0XFFFFFFFFFFFFFFFF, 0, 0x000039)
#    SetMemberComment(sid, 8, "rva of Forward compatibility frame handler", 1)
#    AddStrucMember(sid, "pCatchableTypeArray", 12, 0x25500400, ImageBase, 4, 0XFFFFFFFFFFFFFFFF, 0, 0x000039)
#    SetMemberComment(sid, 12, "rva of CatchableTypeArray", 1)

structMap['CatchableType'] = (0x1c, '4r4444r')
#sid = AddStrucEx(-1, "CatchableType", 0)
#if sid != BADADDR:
#    AddStrucMember(sid, "properties", -1, (FF_DWRD|FF_DATA), -1, 4)
#    SetMemberComment(sid, 0, "Catchable Type properties (Bit field)", 1)
#    AddStrucMember(sid, "pType", 4, 0x25500400, ImageBase, 4, 0XFFFFFFFFFFFFFFFF, 0, 0x000039)
#    SetMemberComment(sid, 4, "rva of TypeDescriptor", 1)
#    AddStrucMember(sid, "PMD0", -1, (FF_DWRD|FF_DATA), -1, 4)
#    SetMemberComment(sid, 8, "Pointer to instance of catch type within thrown object.", 1)
#    AddStrucMember(sid, "PMD1", -1, (FF_DWRD|FF_DATA), -1, 4)
#    AddStrucMember(sid, "PMD2", -1, (FF_DWRD|FF_DATA), -1, 4)
#    AddStrucMember(sid, "sizeOrOffset", -1, (FF_DWRD|FF_DATA), -1, 4)
#    SetMemberComment(sid, 0x14, "Size of simple-type object or offset into buffer of 'this' pointer for catch object", 1)
#    AddStrucMember(sid, "copyFunction", 0x18, 0x25500400, ImageBase, 4, 0XFFFFFFFFFFFFFFFF, 0, 0x000039)
#    SetMemberComment(sid, 0x18, "rva of Copy constructor or CC-closure", 1)

addr = LocByName('_CxxThrowException')
if addr == BADADDR: addr = LocByName('_CxxThrowException_0')
if addr != BADADDR:
    codeTo = RfirstB(addr)
    while codeTo != BADADDR:
        disasm = GetDisasm(codeTo)
        if disasm.startswith('call') or disasm.startswith('jmp'):
            prevAddr = codeTo
            MAX_TRY_TIMES = 6
            foundThrownInfo = False
            for tryTimes in range(MAX_TRY_TIMES):
                prevAddr = PrevHead(prevAddr)
                disasm = GetDisasm(prevAddr)
                if disasm.startswith('xor     edx, edx'): # empty
                    foundThrownInfo = True
                    break
                elif disasm.startswith('lea     rdx,'):
                    throwInfoAddr = LocByName(disasm.split(',')[1].split(';')[0].strip()) # lea     rdx, _TI1?AVCAtlException@ATL@@ ; pThrowInfo
                    if throwInfoAddr != BADADDR:
                        foundThrownInfo = True
                        ParseThrowInfo(throwInfoAddr)
                        break
            if not foundThrownInfo:
                print('[!]warning: Not found throwInfoAddr at reference address:%x'%codeTo)
        codeTo = RnextB(addr, codeTo)
else:
    print("Not found _CxxThrowException")

def CoagulateAddress(addr):
    len = FindExplored(addr, 1) - addr
    MakeArray(addr, len)

startEA = SegByBase(SegByName(".pdata"))
endEA = SegEnd(startEA)
currentFuncAddr = BADADDR

for addr in range(startEA, endEA, 12):
    if Dword(addr) == 0:
        CoagulateAddress(addr)
        print("The SEH/EH autoanalysis has been finished.")
        break
    MyMakeStruct(addr, -1, "RUNTIME_FUNCTION")
    Wait() # wait for get name unk_xxx
    currentFuncAddr = ImageBase + Dword(addr) # Used for function relative offset
    tailAddr = ImageBase + Dword(addr+4)
    unwindInfoAddr = ImageBase + Dword(addr + 8)
    if Name(tailAddr).startswith('unk_'): # unexplored tail align
        CoagulateAddress(tailAddr)
    ParseUnwindInfo(unwindInfoAddr)