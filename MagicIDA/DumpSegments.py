from idc import *
from idautils import *
from objdump import *

mgr = SegManager()
for segBegin in Segments():
    segname = SegName(segBegin)
    if segname in ['HEADER', '.reloc', 'OVERLAY']: # TODO: Hijack link.exe to not generate HEADER, and use the dumped HEADER
        continue
    segtype = GetSegmentAttr(segBegin, SEGATTR_TYPE)
    if segtype == SEG_DATA or segtype == SEG_CODE: # ignore idata extern (pink segment)
        mgr.DumpSeg(segBegin)
