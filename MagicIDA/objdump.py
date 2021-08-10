from idautils import *
from idc import *
from idaapi import *
from cough import *
from Trampoline import *
import enum, re, ctypes, os


InputModule = GetInputFile()
InputModule = InputModule[:InputModule.rfind('.')]
OBJS_DUMP_DIR = os.path.join(InputModule, 'objs', 'afl')
trampoline = AFLTrampoline # default mode
if os.path.exists('TRACE_MODE'):
    print('found hint file, using TRACE_MODE')
    trampoline = TraceTrampoline
    OBJS_DUMP_DIR = os.path.join(InputModule, 'objs', 'trace')

if not os.path.exists(OBJS_DUMP_DIR): os.makedirs(OBJS_DUMP_DIR)

class RelType64(enum.IntEnum):
    IMAGE_REL_AMD64_ABSOLUTE=0x0
    IMAGE_REL_AMD64_ADDR64=0x1
    IMAGE_REL_AMD64_ADDR32=0x2
    IMAGE_REL_AMD64_ADDR32NB=0x3
    IMAGE_REL_AMD64_REL32=0x4
    IMAGE_REL_AMD64_REL32_1=0x5
    IMAGE_REL_AMD64_REL32_2=0x6
    IMAGE_REL_AMD64_REL32_3=0x7
    IMAGE_REL_AMD64_REL32_4=0x8
    IMAGE_REL_AMD64_REL32_5=0x9
    IMAGE_REL_AMD64_SECTION=0xa
    IMAGE_REL_AMD64_SECREL=0xb
    IMAGE_REL_AMD64_SECREL7=0xc
    IMAGE_REL_AMD64_TOKEN=0xd
    IMAGE_REL_AMD64_SREL32=0xe
    IMAGE_REL_AMD64_PAIR=0xf
    IMAGE_REL_AMD64_SSPAN32=0x10

class RelType32(enum.IntEnum):
    IMAGE_REL_I386_ABSOLUTE=0x0
    IMAGE_REL_I386_DIR16=0x1
    IMAGE_REL_I386_REL16=0x2
    IMAGE_REL_I386_DIR32=0x6
    IMAGE_REL_I386_DIR32NB=0x7
    IMAGE_REL_I386_SEG12=0x9
    IMAGE_REL_I386_SECTION=0xa
    IMAGE_REL_I386_SECREL=0xb
    IMAGE_REL_I386_TOKEN=0xc
    IMAGE_REL_I386_SECREL7=0xd
    IMAGE_REL_I386_REL32=0x14

class SegDumper:
    def __init__(self, segBegin): # some segments have the same name, so use segBegin as the identity
        self.segBegin = segBegin
        self.segEnd = SegEnd(segBegin)
        self.segname = SegName(segBegin)
        self.segPerm = GetSegmentAttr(segBegin, SEGATTR_PERM)
        self.permFlags = 0
        if self.segPerm & 1: self.permFlags |= SectionFlags.MEM_EXECUTE | SectionFlags.ALIGN_16BYTES | SectionFlags.CNT_CODE
        if (self.segPerm>>1) & 1: self.permFlags |= SectionFlags.MEM_WRITE
        if (self.segPerm>>2) & 1: self.permFlags |= SectionFlags.MEM_READ
        if self.segname == '.pdata': # workaround for error LNK1223: invalid or corrupt file: file contains invalid .pdata contributions
            self.permFlags |= SectionFlags.MEM_WRITE
        self.module = ObjectModule()
        self.section = Section(self.segname.encode(), self.permFlags)
        self.section.data = b''
        self.strMap = {}
        self.strIndex = 4
        self.symMap= {}
        self.symIndex = 0
    
    def AddString(self, aStr):
        if aStr not in self.strMap.keys():
            self.strMap[aStr] = self.strIndex
            self.strIndex += len(aStr) + 1
            self.module.string_table.append(aStr.encode())
        
        return self.strMap[aStr]
    
    def AddSymbol(self, symName, value, section_number=0, storage_class=StorageClass.EXTERNAL, overwrite=False):
        if symName not in self.symMap.keys():
            if len(symName) > 8:
                index = self.AddString(symName)
                name = b'\0\0\0\0' + index.to_bytes(4, 'little', signed=False)
            else:
                name = symName.encode()
            sym = SymbolRecord(name, section_number=section_number, storage_class=storage_class)
            sym.value = value
            self.symMap[symName] = self.symIndex
            self.symIndex += 1
            self.module.symbols.append(sym)
        elif overwrite: # PublicSymbol overwrite exist symbol added by ReferenceSymbol
            symIndex = self.symMap[symName]
            self.module.symbols[symIndex].value = value
        
        return self.symMap[symName]
    
    def AddRelocation(self, va, symIndex, type):
        reloc = Relocation()
        reloc.virtual_address = va
        reloc.symbol_table_index = symIndex
        reloc.type = type # 0x04 -> REL32
        self.section.relocations.append(reloc)
    
    def ReferenceSymbol(self, addr, newAddr, symAddr, symName, relType):
        if (Name(symAddr) != symName and symName not in TrampolineSymbols) or '' == symName:
            raise Exception('[!] 0x%x unable to resolve symbol: %s to 0x%x'%(addr, symName, symAddr))
        if self.segBegin < symAddr and symAddr < self.segEnd: # symbol is defined in the current segment
            section_number = 1
            value = symAddr - self.segBegin # wrong value will be overwriten by PublicSymbol
        else:
            section_number = 0
            value = 0
        symIndex = self.AddSymbol(symName, value, section_number=section_number)
        self.AddRelocation(newAddr-self.segBegin, symIndex, relType)
    
    def PublicSymbol(self, newAddr, symName):
        self.AddSymbol(symName, newAddr - self.segBegin, section_number=1, overwrite=True)
    
    def FillSymbol(self, symLen, addr, newAddr, symAddr, symName, symOffset, type):
        self.section.data += symOffset.to_bytes(symLen, 'little', signed=False)
        self.ReferenceSymbol(addr, newAddr, symAddr-symOffset, symName.strip(), type)
    
    def FillSymbolByAddress(self, symLen, addr, newAddr, symAddr, type):
        symName = Name(symAddr)
        symOffset = 0
        # if the symbol is within the unexported HEADER
        if SegName(symAddr) == 'HEADER': # e.g. function __scrt_is_nonwritable_in_current_image read new NT header from off_18000003C
            symName = '__ImageBase' # defined by linker automatically
            symOffset = (symAddr - get_imagebase())
        elif symName == '': # e.g. movzx   eax, word ptr cs:a0123456789+8 ; "89"
            headAddr = ItemHead(symAddr)
            symOffset = symAddr - headAddr
            symName = Name(headAddr)
        
        self.FillSymbol(symLen, addr, newAddr, symAddr, symName, symOffset, type)
    
    def FillSymbolByName(self, symLen, addr, newAddr, symName, type):
        symAddr = LocByName(symName)
        if symAddr == BADADDR: raise Exception('[!] 0x%x unable to resolve symbol: %s'%(addr, symName))
        symOffset = 0
        sp = symName.split('+')
        if len(sp) > 1:
            symName = sp[0]
            symOffset = int(sp[1], 16)
            symAddr += symOffset
        self.FillSymbol(symLen, addr, newAddr, symAddr, symName, symOffset, type)
    
    # override the method
    def FillData(self):
        raise Exception('[!] abstract method called')
    
    def align(self, newAddr, bytes, fillVal, name): # bytes must be 2,4,8,16,...
        tailLen = newAddr & (bytes - 1)
        if tailLen:
            delta = bytes - tailLen
            self.section.data += (fillVal * delta)
            self.PublicSymbol(newAddr + delta, name) # republic will overwrite
            return delta
        else:
            return 0
    
    def final(self):
        for e in Entries(): # enumerate Exports symbols
            addr = e[2]
            name = e[3]
            symName = Name(addr)
            if addr < self.segBegin or addr > self.segEnd: continue
            if name and symName != name: # multiple symbols share the same location.
                if symName not in self.symMap.keys(): raise Exception('%s(%s) not dumped yet.'%(symName, name))
                symIndex = self.symMap[symName]
                value = self.module.symbols[symIndex].value
                self.AddSymbol(name, value, section_number=1, overwrite=True) # PublicSymbol
    
    def Dump(self):
        if self.FillData():
            self.final()
            print('[*] FillData Done, ready to dump file.')
            self.section.number_of_relocations = len(self.section.relocations)
            if self.section.number_of_relocations > 0xffff:
                # handle reloc number overflow, use a new reloc entry's va to store the real number.
                reloc = Relocation()
                reloc.virtual_address = self.section.number_of_relocations + 1
                reloc.symbol_table_index = 0
                reloc.type = 0
                self.section.relocations.insert(0, reloc)
                self.section.number_of_relocations = 0xffff
                self.section.flags |= SectionFlags.LNK_NRELOC_OVFL
            self.section.size_of_raw_data = len(self.section.data)
            self.module.sections.append(self.section)
            file_buffer = self.module.get_buffer()
            filename = '%s_%x'%(self.segname, self.segBegin)
            with open(os.path.join(OBJS_DUMP_DIR, filename+'.obj'), 'wb') as f:
                f.write(file_buffer)
            print('[*] Segment:%s has been dumped to obj coff file'%filename)



# .NET uint32_t integer compression scheme:
# Compresses up to 32 bits into 1-5 bytes, depending on value
# Lower 4 bits of the MSB determine the number of bytes to read:
# XXX0: 1 byte
# XX01: 2 bytes
# X011: 3 bytes
# 0111: 4 bytes
# 1111: 5 bytes
def getNETencoded(value):
    if value < 128:
        return ((value << 1) + 0, 1)
    elif value < 128 * 128:
        return ((value << 2) + 1, 2)
    elif value < 128 * 128 * 128:
        return ((value << 3) + 3, 3)
    elif value < 128 * 128 * 128 * 128:
        return ((value << 4) + 7, 4)
    else:
        return ((value<<8) + 15, 5)

def getSymbolNewAddress(symName, oldAddr):
    mgr = SegManager()
    dumper = mgr.GetSegDumperByAddr(oldAddr, forceDump=True)
    if symName not in dumper.symMap:
        raise Exception('[!] Unable to locate:' + symName)
    symIndex = dumper.symMap[symName]
    return dumper.module.symbols[symIndex].value + dumper.segBegin

def getTagNewAddress(tagName):
    return getSymbolNewAddress(tagName, int(tagName[4:], 16))



class DataSegDumper(SegDumper):
    def __init__(self, segBegin):
        super().__init__(segBegin)
    
    def FillData(self):
        ImageBase = get_imagebase()
        newAddr = addr = self.segBegin
        self.section.data += (b'\0' * (addr&0xf)) # corner case: segBegin not aligned with 16 bytes
        self.segBegin -= (addr&0xf)
        while addr < self.segEnd:
            #print('[-] dumping 0x%x'%addr)
            itemSize = ItemSize(addr)
            name = Name(addr)
            if name != "":
                self.PublicSymbol(newAddr, name)
                if name.startswith('unwindinfo_') or name.startswith('funcInfo'):
                    newAddr += self.align(newAddr, 4, b'\0', name) # align (4) for '_FIXME_'
                elif name.startswith('qword_') and (addr&7) == 0: # itemSize%8 == 0
                    newAddr += self.align(newAddr, 8, b'\0', name)
                elif itemSize%16 == 0 and (addr&0xf) == 0:
                    #print('0x%x vs 0x%x'%(addr, newAddr))
                    newAddr += self.align(newAddr, 16, b'\0', name)
            refAddrList = []
            for x in XrefsFrom(addr):
                if ImageBase <= x.to and x.to < ImageBase+0x40: # ignore the reference
                    continue
                if (x.to & 0xffff000000000000) == 0xff00000000000000: # ignore struc reference
                    continue
                refAddrList.append(x.to)
            refNum = len(refAddrList)
            if refNum == 0:
                if '_FIXME_' in name:
                    sp = name.split(' ')[0].split('_FIXME_')
                    tag1 = sp[0]
                    tag2 = sp[1].split('_unique')[0]
                    addr1 = getTagNewAddress(tag1)
                    addr2 = getTagNewAddress(tag2)
                    delta = addr1 - addr2
                    (v, n) = getNETencoded(delta)
                    self.section.data += v.to_bytes(n, 'little', signed=False)
                    newAddr += (n-itemSize)
                else:
                    if isLoaded(addr+itemSize-1): # the item last byte is initialized data
                        self.section.data += GetManyBytes(addr, itemSize, 0)
                    else:
                        self.section.data += bytes(itemSize) # uninitialized data (?), then fill 0
            elif refNum == 1:
                symAddr = refAddrList[0]
                disasm = GetDisasm(addr).split(';')[0].strip()
                filledLen = 8
                if disasm.startswith('dq offset '):
                    self.FillSymbolByAddress(8, addr, newAddr, symAddr, RelType64.IMAGE_REL_AMD64_ADDR64)
                elif disasm.startswith('dq rva '):
                    self.FillSymbolByAddress(4, addr, newAddr, symAddr, RelType64.IMAGE_REL_AMD64_ADDR32NB)
                    self.section.data += b'\0\0\0\0'
                elif disasm.startswith('dd rva '):
                    self.FillSymbolByAddress(4, addr, newAddr, symAddr, RelType64.IMAGE_REL_AMD64_ADDR32NB)
                    filledLen = 4
                else:
                    raise Exception('[!] not dump 0x%x -> %s (Unknown reference type)'%(addr, disasm))
                if itemSize > filledLen: self.section.data += GetManyBytes(addr+filledLen, itemSize-filledLen, 0)
            else: # multiple xrefs
                disasm = GetDisasmEx(addr, GENDSM_MULTI_LINE)
                i = 0
                for line in disasm.split('\n'):
                    line = line.split(';')[0].strip()
                    if line == '': continue
                    if line.startswith('dq offset '):
                        symLen = 8
                        type = RelType64.IMAGE_REL_AMD64_ADDR64
                    elif line.startswith('dd rva '):
                        symLen = 4
                        type = RelType64.IMAGE_REL_AMD64_ADDR32NB
                    else:
                        raise Exception('[!] not dump 0x%x -> %s (Unknown reference type)'%(addr, disasm))
                    
                    for item in line[2:].split(','):
                        symName = item.split(' ')[2]
                        self.FillSymbolByName(symLen, addr+i*symLen, newAddr+i*symLen, symName, type)
                        i += 1
            addr += itemSize
            newAddr += itemSize
        return True



class CodeSegDumper(SegDumper):
    JccShort2Long = {
        0x70 : b'\x0f\x80', # jo
        0x71 : b'\x0f\x81', # jno
        0x72 : b'\x0f\x82', # jb, jnae
        0x73 : b'\x0f\x83', # jae, jnb, jnc
        0x74 : b'\x0f\x84', # jz, je
        0x75 : b'\x0f\x85', # jnz, jne
        0x76 : b'\x0f\x86', # jbe, jna
        0x77 : b'\x0f\x87', # ja, jnbe
        0x78 : b'\x0f\x88', # js
        0x79 : b'\x0f\x89', # jns
        0x7a : b'\x0f\x8a', # jp, jpe
        0x7b : b'\x0f\x8b', # jnp, jpo
        0x7c : b'\x0f\x8c', # jl, jnge
        0x7d : b'\x0f\x8d', # jge, jnl
        0x7e : b'\x0f\x8e', # jle, jng
        0x7f : b'\x0f\x8f'  # jg, jnle
    }
    
    def __init__(self, segBegin):
        super().__init__(segBegin)
    
    def FillData(self):
        pat = re.compile(r"(call|jmp)\s+cs:")
        pat2 = re.compile(r"(call|jmp)\s+r(ax|bx|cx|dx|si|di|8|9|10|11|12|13|14|15)")
        ImageBase = get_imagebase()
        newAddr = addr = self.segBegin
        while addr < self.segEnd:
            #print('[-] dumping 0x%x'%addr)
            itemSize = ItemSize(addr)
            name = Name(addr)
            if name != "": self.PublicSymbol(newAddr, name)
            
            disasm = GetDisasm(addr)
            if 'InstrumentHere' in disasm:
                self.section.data += trampoline.GetBytes()
                self.ReferenceSymbol(0, newAddr+trampoline.reloc_offset, 0, trampoline.reloc_symbol, RelType64.IMAGE_REL_AMD64_REL32)
                newAddr += trampoline.size
            
            refAddrList = []
            patMatch = pat.search(disasm)
            if not pat2.search(disasm) and 'retn' not in disasm: # ignore all references from instruction "call/jmp register"
                for x in XrefsFrom(addr): # ida_xref.XREF_FAR, use default ida_xref.XREF_ALL in case ignored
                    #print(hex(x.frm), hex(x.to), XrefTypeName(x.type), x.user, x.iscode)
                    if x.type == ida_xref.fl_F: # just ignore "Ordinary flow"
                        continue
                    if x.to < 0x1000: # ida bug? -> movss   xmm5, dword ptr ds:0[rcx*4]
                        continue
                    if ImageBase == x.to and '__ImageBase' not in disasm: # e.g. mov     ecx, ds:rva dword_180174B70[r9+rax*4]
                        continue
                    # this instruction has 2 refs(dr_R, fl_XX), ignore the fl_XX
                    if patMatch and x.type != ida_xref.dr_R:
                        continue
                    if (x.to & 0xffff000000000000) == 0xff00000000000000: # it is an id value for struc.member
                        continue
                    refAddrList.append(x.to)
            refNum = len(refAddrList)
            if refNum == 0:
                self.section.data += GetManyBytes(addr, itemSize, 0)
            elif refNum == 1:
                symAddr = refAddrList[0]
                
                # bnd short jump
                # https://stackoverflow.com/questions/43057460/meaning-of-bnd-ret-in-x86
                if itemSize == 3 and Byte(addr) == 0xf2:
                    self.section.data += b'\xf2'
                    addr += 1
                    newAddr += 1
                    itemSize = 2
                    # handle the tail part as usual
                
                if itemSize == 2: # short jump
                    opcode = Byte(addr)
                    newOpcodeLen = 1
                    if opcode == 0xeb: # jmp short
                        self.section.data += b'\xe9'
                    elif opcode in CodeSegDumper.JccShort2Long:
                        self.section.data += CodeSegDumper.JccShort2Long[opcode]
                        newOpcodeLen = 2
                    else:
                        raise Exception('[!] not dump 0x%x -> %s (Unknown opcode 0x%x)'%(addr, disasm, opcode))
                    self.FillSymbolByAddress(4, addr+1, newAddr+newOpcodeLen, symAddr, RelType64.IMAGE_REL_AMD64_REL32)
                    newAddr += (newOpcodeLen + 4 - 2)
                elif itemSize > 4:
                    refType = RelType64.IMAGE_REL_AMD64_REL32
                    refPos = itemSize - 4
                    while refPos > 0: # find the refPos and refType in the current instruction
                        symVal = Dword(addr+refPos)
                        if symAddr == (addr + itemSize + ctypes.c_int32(symVal).value):
                            break
                        if symAddr == (ImageBase + symVal): # ImageBase Relative
                            refType = RelType64.IMAGE_REL_AMD64_ADDR32NB
                            break
                        refPos -= 1
                    if refPos == 0:
                        raise Exception('[!] not dump 0x%x -> %s (Reference position not found)'%(addr, disasm))
                    # Copy opcode
                    self.section.data += GetManyBytes(addr, refPos, 0)
                    # Fill the referenced symbol
                    tailLen = itemSize - refPos - 4
                    if tailLen > 0 and refType == RelType64.IMAGE_REL_AMD64_REL32:
                        if tailLen > 5: raise Exception('[!] not dump 0x%x -> %s (tailLen:%d too long)'%(addr, disasm, tailLen))
                        refType += tailLen # IMAGE_REL_AMD64_REL32_1/2/3/4/5
                    self.FillSymbolByAddress(4, addr+refPos, newAddr+refPos, symAddr, refType)
                    # Copy the tail
                    if tailLen > 0:
                        self.section.data += GetManyBytes(addr+refPos+4, tailLen, 0)
                else:
                    OpHex(addr, -1) # Make Hex may clear the invalid reference.
                    self.section.data += GetManyBytes(addr, itemSize, 0)
                    print('[!] Please check 0x%x -> %s (Unknown reference type with itemSize:%d)'%(addr, disasm, itemSize))
            else: # multiple xrefs
                if 'dd offset' in disasm: # jump table
                    newAddr += self.align(newAddr, 8, b'\xcc', name)
                    disasm = GetDisasmEx(addr, GENDSM_MULTI_LINE)
                    i = 0
                    for line in disasm.split('\n'):
                        line = line.split(';')[0].strip()
                        if line == '': continue
                        # line like this:
                        # dd offset loc_1800C2B54 - 180000000h, offset loc_1800C2B73 - 180000000h; jump table for switch statement
                        for item in line[2:].split(','):
                            symName = item.split(' ')[2]
                            self.FillSymbolByName(4, addr+i*4, newAddr+i*4, symName, RelType64.IMAGE_REL_AMD64_ADDR32NB)
                            i += 1
                else:
                    raise Exception('[!] not dump 0x%x -> %s (Unknown reference type)'%(addr, disasm))
            addr += itemSize
            newAddr += itemSize
        return True



class SegManager(object):
    # Singleton
    _instance = None
    def __new__(cls, *args, **kw):
        if cls._instance is None:
            cls._instance = object.__new__(cls, *args, **kw)
            cls._instance.inited = False
        return cls._instance
    
    def __init__(self):
        if not self.inited:
            self.segMap = dict()
            self.inited = True
    
    def DumpSeg(self, segBegin):
        if segBegin not in self.segMap:
            segtype = GetSegmentAttr(segBegin, SEGATTR_TYPE)
            dumper = None
            if segtype == SEG_DATA:
                dumper = DataSegDumper(segBegin)
                dumper.Dump()
            elif segtype == SEG_CODE:
                dumper = CodeSegDumper(segBegin)
                dumper.Dump()
            else:
                raise Exception('[!] Unsupport segment type:%d to dump'%segtype)
            
            if dumper: self.segMap[segBegin] = dumper
    
    def GetSegDumperByAddr(self, addr, forceDump = False):
        segBegin = SegStart(addr)
        if forceDump: self.DumpSeg(segBegin)
        if segBegin in self.segMap:
            return self.segMap[segBegin]
        else:
            return None
    
