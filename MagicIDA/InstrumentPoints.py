from idautils import *
from idaapi import *
from idc import *

# wait for auto analysis done.
Wait()

cnt = 0

for start in Segments():
    segtype = GetSegmentAttr(start, SEGATTR_TYPE)
    if segtype != SEG_CODE:
        continue
    
    end = SegEnd(start)
    for func_ea in Functions(start, end):
        if Name(func_ea) in ['_guard_dispatch_icall_nop']: # skip some special functions
            continue
        f = get_func(func_ea)
        if not f:
            continue
        for block in FlowChart(f):
            if Name(block.start_ea).startswith('jpt_'): continue # Bug fix: Sometimes IDA will recognize jump table as a part of code flow!
            if start <= block.start_ea < end:
                MakeComm(block.start_ea, 'InstrumentHere')
                cnt += 1
            else:
                print("[!] function:0x%x with block: 0x%x, broken CFG?"%(func_ea, block.start_ea))

print(str(cnt) + ' code blocks have been found.')