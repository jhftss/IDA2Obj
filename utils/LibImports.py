import idaapi
import os
import subprocess

lib_exe_path = os.path.join(os.path.dirname(__file__), 'bin', 'lib.exe')
InputModule = GetInputFile()
InputModule = InputModule[:InputModule.rfind('.')]
LIBS_DUMP_DIR = os.path.join(InputModule, 'libs')
if not os.path.exists(LIBS_DUMP_DIR): os.makedirs(LIBS_DUMP_DIR)
print('LIBS_DUMP_DIR: "%s"'%LIBS_DUMP_DIR)

for i in range(idaapi.get_import_module_qty()):
    module = idaapi.get_import_module_name(i)
    if not module:
        print('[!] no module name')
        continue
    
    indef = os.path.join(LIBS_DUMP_DIR, module+'.def')
    outlib = os.path.join(LIBS_DUMP_DIR, module+'.lib')
    f = open(indef, 'w')
    f.write('EXPORTS\n')
    def cb(ea, symbol, ordinal):
        symbol = symbol.replace('__imp_', '')
        f.write('\t'+symbol+'\n')
        if symbol.startswith('_o_'):
            f.write('\t'+symbol[3:]+'\n')
        return True  # continue enumeration

    idaapi.enum_import_names(i, cb)
    f.close()

    cmd = r'"%s" /ERRORREPORT:PROMPT /MACHINE:X64 /DEF:"%s" /OUT:"%s"'%(lib_exe_path, indef, outlib)
    #print(cmd)
    subprocess.call(cmd, shell=True)
    os.remove(indef)
    os.remove(os.path.join(LIBS_DUMP_DIR, module+'.exp'))
