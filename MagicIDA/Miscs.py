from idc import *
from idautils import *
from idaapi import *
import os


# Rename some keywords to avoid conflicting with MASM
keywords = ["sub", "str", "substr", "name", "neg", "add", "addr", "and", "adc", "addss", "mul",
"imul", "inc", "dec", "cwd", "ptr", "end", "mask", "width", "length", "crc32",
"loop", "looped", "offset", "db", "size", "lock", "in", "out", "type"]  # and so on, add if you need.
filterSet = set()

# '__guard_eh_cont_table' defined in vs2019 linker, but not in vs2015
link_builtin_symbols = ['__guard_iat_table', '__guard_fids_table', '__guard_longjmp_table', '__guard_eh_cont_table']
for name in Names():
    addr = name[0]
    oldname = name[1]
    if 'jmp     cs:__imp_' in GetDisasm(addr): # some names redefined in import libs
        MakeName(addr, "%s__ftss"%(oldname))
    lowername = oldname.lower()
    if lowername in keywords+link_builtin_symbols or lowername in filterSet or lowername.startswith('__import_descriptor'):
        MakeName(addr, "%s_%x"%(oldname, addr))
    else:
        filterSet.add(lowername)

InputModule = GetInputFile()
InputModule = InputModule[:InputModule.rfind('.')]
if not os.path.exists(InputModule): os.makedirs(InputModule)

addr = ImageBase = get_imagebase()
while addr < ImageBase + 0x1000:
    disAsm = GetDisasm(addr)
    if disAsm.endswith('Virtual address'): #'Export Directory'
        with open(os.path.join(InputModule, 'hint.txt'), 'w') as w:
            if Dword(addr) != 0:
                MakeName(Dword(addr)+ImageBase, 'ExportDir')
                w.write('ExportDirSize:0x%x\n'%Dword(addr+4))
            if Dword(addr+8*3) != 0:
                MakeName(Dword(addr+8*3)+ImageBase, 'ExceptionDir')
                w.write('ExceptionDirSize:0x%x\n'%Dword(addr+8*3+4))
            if Dword(addr+8*9) != 0:
                #MakeName(Dword(addr+8*9)+ImageBase, '_tls_used')
                w.write('_tls_used_size:0x%x\n'%Dword(addr+8*9+4))
            if Dword(addr+8*10) != 0:
                MakeName(Dword(addr+8*10)+ImageBase, '_load_config_used')
                w.write('_load_config_used_size:0x%x\n'%Dword(addr+8*10+4))
            
            rsrc_rva = SegByBase(SegByName('.rsrc')) - ImageBase
            w.write('rsrc_rva:0x%x\n'%rsrc_rva)
        break
    addr = FindData(addr, 1)

f1 = open(os.path.join(InputModule, 'exports_trace.def'), 'w')
f2 = open(os.path.join(InputModule, 'exports_afl.def'), 'w')
f1.write('EXPORTS\n')
f2.write('EXPORTS\n')
for e in Entries():
    ord = e[1]
    addr = e[2]
    name = e[3]
    type = ''
    if ord == addr: continue # ignore main entry point
    if GetSegmentAttr(addr, SEGATTR_TYPE) == SEG_DATA:
        type = 'DATA'
    if name is None: name = Name(addr)
    if name == '': print('[!] unknown export symbol at 0x%x with ord=%d'%(addr, ord))
    f1.write('    %s    @%d    %s\n'%(name, ord, type))
    f2.write('    %s    @%d    %s\n'%(name, ord, type))

f1.write('    __trace_cur_count_ptr       DATA\n    __trace_max_count_ptr       DATA\n    __trace_store_ptr           DATA\n')
f2.write('    __afl_area_ptr      DATA\n    __afl_prev_locs     DATA\n')
f1.close()
f2.close()

