from idc import *
from idautils import *


def IsUnexplored(addr):
    return FindUnexplored(addr-1, SEARCH_NOSHOW|SEARCH_DOWN) == addr

# Unexplored data range [0x18031C028, 0x18031C038)
# MakeArray(0x18031C028, 8)
# MakeArray(0x18031C030, 8)
#.data:000000018031C028                 db    0
#.data:000000018031C029                 db    0
#.data:000000018031C02A                 db    0
#.data:000000018031C02B                 db    0
#.data:000000018031C02C                 db    0
#.data:000000018031C02D                 db    0
#.data:000000018031C02E                 db    0
#.data:000000018031C02F                 db    0
#.data:000000018031C030   unk_18031C030 db  60h ; `
#.data:000000018031C031                 db    0
#.data:000000018031C032                 db    0
#.data:000000018031C033                 db    0
#.data:000000018031C034                 db    0
#.data:000000018031C035                 db    0
#.data:000000018031C036                 db    0
#.data:000000018031C037                 db    0
#.data:000000018031C038 ; HINSTANCE hInstance
#.data:000000018031C038 hInstance       dq 180000000h  
def CoagulateUnexplored_old(begin, end):
    addr = FindUnexplored(begin, SEARCH_NOSHOW|SEARCH_DOWN)
    while addr < end:
        for s in range(addr+1, FindExplored(addr, SEARCH_NOSHOW|SEARCH_DOWN)+1):
            if Name(s) != "": break
        MakeArray(addr, s-addr)
        addr = FindUnexplored(addr, SEARCH_NOSHOW|SEARCH_DOWN)

def FindBestSizeForUnexplored(addr, max_size):
    size = max_size
    while not MakeArray(addr, size): # failed because unk_xxx is inside the range
        max_size = size
        size //= 2
    
    MakeUnkn(addr, DOUNK_SIMPLE)
    if size == max_size or Name(addr+size) != '': # recursive exit
        return size
    return size + FindBestSizeForUnexplored(addr+size, max_size-size)

def CoagulateUnexplored(begin, end): # optimized for large unexplored data segment
    addr = FindUnexplored(begin, SEARCH_NOSHOW|SEARCH_DOWN)
    while addr < end:
        #print(hex(addr))
        size = FindExplored(addr, SEARCH_NOSHOW|SEARCH_DOWN) - addr
        size = FindBestSizeForUnexplored(addr, size)
        MakeArray(addr, size)
        addr = FindUnexplored(addr, SEARCH_NOSHOW|SEARCH_DOWN)

def CoagulateDataSegments():
    for seg in Segments():
        start = SegStart(seg)
        end = SegEnd(seg)
        segname = SegName(seg)
        if segname in ['.data', '.rdata']:
            CoagulateUnexplored_old(start, end) # Not use fast solution because MakeArray could overlay the unk_xxx labels
            print('%s segment coagulate unexplored data done.'%segname)

# select "Coagulate data segments in the final pass" from analysis option 2 will do the same work, but has the same issue(overlay the unk_xxx labels
# do it manually after delete structures
CoagulateDataSegments()
