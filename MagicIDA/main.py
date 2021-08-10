import os
from idc import *


if SegByName("HEADER") == BADADDR: raise Exception('You must load all segments, including "HEADER"!')

path = os.path.dirname(__file__)
print("current path: " + os.getcwd())
print("tool path: " + path)

def execfile(filepath):
    filename = os.path.basename(filepath)
    with open(filepath) as f:
        code = compile(f.read(), filename, 'exec')
    exec(code, {})

execfile(os.path.join(path, "InstrumentPoints.py"))
execfile(os.path.join(path, "assistant", "pe64", "FixEH.py"))
execfile(os.path.join(path, "assistant", "pe64", "FixRTTI.py"))
execfile(os.path.join(path, "assistant", "pe64", "FixRVA.py"))
execfile(os.path.join(path, "assistant", "pe64", "FixPointer.py"))
execfile(os.path.join(path, "Miscs.py"))

print("wait for re-analysis done...")
Wait()
execfile(os.path.join(path, "Coagulate.py")) # coagulate data to speed up the dumping process
execfile(os.path.join(path, "DumpSegments.py"))
