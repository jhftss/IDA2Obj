# purpose: fix export table, exception table
# usage: sys.argv[0] /path/to/pe
import os, sys, subprocess
PY3 = sys.version_info[0] == 3
import struct
import time
from binascii import hexlify, unhexlify

#ref: https://github.com/zeroq/peanalysis/blob/master/classPEfile.py

class PEFile:
    def __init__(self, fn):
        self.isPEfile = False
        self.is32bit = True
        self.filename = fn
        self.filecontent = None
        self.filelength = None
        self.readFileContent()

        self.datadirNames = {}
        self.datadirNames[0] = "Export symbols table"
        self.datadirNames[1] = "Import symbols table"
        self.datadirNames[2] = "Resource table"
        self.datadirNames[3] = "Exception table"
        self.datadirNames[4] = "Certificate table"
        self.datadirNames[5] = "Base relocation table"
        self.datadirNames[6] = "Debugging information"
        self.datadirNames[7] = "Architecture-specific data"
        self.datadirNames[8] = "Global pointer register"
        self.datadirNames[9] = "Thread local storage table"
        self.datadirNames[10] = "Load configuration table"
        self.datadirNames[11] = "Bound import table"
        self.datadirNames[12] = "Import address table"
        self.datadirNames[13] = "Delay import descriptor"
        self.datadirNames[14] = "CLR header"
        self.datadirNames[15] = "Reserved"

        self.rsrc_sec_index = None
        self.rsrc_patchpoints = {}

        self.peHeader = None

        if self.filelength>64:
            self.msdosDict = {}
            self.msdosHeader = self.filecontent[:64]
            if self.msdosHeader[0:2]==b'MZ':
                self.readMSDOSHeader(self.msdosHeader)
        else:
            print("file too small")

        try:
            PESignature = self.filecontent[self.msdosDict['15_pPEHeader']:self.msdosDict['15_pPEHeader']+4]
            self.isPEfile = True
        except:
            print("no PE file!")
        else:
            if type(PESignature) == type(bytes()):
                PESignature = PESignature.decode('ascii')
            if PESignature == '\x50\x45\x00\x00':
                self.peHeader = self.filecontent[self.msdosDict['15_pPEHeader']+4:self.msdosDict['15_pPEHeader']+4+20]
                self.peDict = {}
                self.readPEHeader(self.peHeader)

                self.peoptDict = {}
                self.peOptionalHeader = self.filecontent[self.msdosDict['15_pPEHeader']+4+20:self.msdosDict['15_pPEHeader']+4+20+self.peDict['06_sizeoptheader']]
                self.readPEOptHeader(self.peOptionalHeader)

                beginFirstSection = self.msdosDict['15_pPEHeader']+4+20+self.peDict['06_sizeoptheader']
                endFirstSection = self.msdosDict['15_pPEHeader']+4+20+self.peDict['06_sizeoptheader']+40
                self.sectionDict = {}
                self.secionDataDict = {}
                for i in range(0, self.peDict['02_numberofsections']):
                    self.sectionHeader = self.filecontent[beginFirstSection:endFirstSection]
                    self.carvedFileSize = self.readSectionHeader(self.sectionHeader, i)
                    self.secionDataDict[i] = self.filecontent[self.sectionDict[i]['ptorawdata']:self.sectionDict[i]['ptorawdata']+self.sectionDict[i]['sizeofrawdata']]
                    beginFirstSection += 40
                    endFirstSection += 40
                
                if self.rsrc_rva: self.recursiveReadTree(self.rsrc_sec_index, 0, 16)
            else:
                print("PE Signature wrong: %s" % PESignature)
        if not self.peHeader:
            print("PE Header is None")
            self.isPEfile = False

    def readFileContent(self):
        fp = open(self.filename, 'rb')
        self.filecontent = fp.read()
        fp.close()
        self.filelength = len(self.filecontent)

    def readSectionHeader(self, sectionHeader, i):
        self.sectionDict[i] = {}
        self.sectionDict[i]['name'] = b"".join(struct.unpack('8c', sectionHeader[0:8])).decode('ascii')
        self.sectionDict[i]['misc'] = struct.unpack('I', sectionHeader[8:12])[0]
        self.sectionDict[i]['physaddress'] = struct.unpack('I', sectionHeader[8:12])[0]
        self.sectionDict[i]['virtualsize'] = struct.unpack('I', sectionHeader[8:12])[0]
        self.sectionDict[i]['virtualaddress'] = struct.unpack('I', sectionHeader[12:16])[0]
        self.sectionDict[i]['sizeofrawdata'] = struct.unpack('I', sectionHeader[16:20])[0]
        self.sectionDict[i]['ptorawdata'] = struct.unpack('I', sectionHeader[20:24])[0]
        self.sectionDict[i]['ptorelocations'] = struct.unpack('I', sectionHeader[24:28])[0]
        self.sectionDict[i]['ptolinenumbers'] = struct.unpack('I', sectionHeader[28:32])[0]
        self.sectionDict[i]['numofrelocs'] = struct.unpack('H', sectionHeader[32:34])[0]
        self.sectionDict[i]['numoflinenums'] = struct.unpack('H', sectionHeader[34:36])[0]
        self.sectionDict[i]['characteristics'] = struct.unpack('I', sectionHeader[36:40])[0]
        self.sectionDict[i]['data'] = self.filecontent[self.sectionDict[i]['ptorawdata']:self.sectionDict[i]['ptorawdata']+self.sectionDict[i]['sizeofrawdata']]
        
        if self.sectionDict[i]['virtualaddress'] == self.rsrc_rva:
            self.rsrc_sec_index = i
        return self.sectionDict[i]['virtualaddress']+self.sectionDict[i]['virtualsize']

    def recursiveReadTree(self, i, offset, size, isDataEntry = False):
            if size == 8 and not isDataEntry:
                """ _IMAGE_RESOURCE_DIRECTORY_ENTRY """
                #name = struct.unpack('I', self.sectionDict[i]['data'][offset:offset+4])[0]
                offsetToData = struct.unpack('H', self.sectionDict[i]['data'][offset+4:offset+6])[0]
                dtype = struct.unpack('H', self.sectionDict[i]['data'][offset+6:offset+8])[0]
                self.recursiveReadTree(i, offsetToData, 16, isDataEntry = (dtype==0))
            elif size == 16 and not isDataEntry:
                """ _IMAGE_RESOURCE_DIRECTORY """
                #Characteristics = struct.unpack('I', self.sectionDict[i]['data'][offset:offset+4])[0]
                #Timestamp = struct.unpack('I', self.sectionDict[i]['data'][offset+4:offset+8])[0]
                #MajorVersion = self.sectionDict[i]['data'][offset+8:offset+10]
                #MinorVersion = self.sectionDict[i]['data'][offset+10:offset+12]
                NumberOfNamedEntries = struct.unpack('H', self.sectionDict[i]['data'][offset+12:offset+14])[0]
                NumberOfIdEntries = struct.unpack('H', self.sectionDict[i]['data'][offset+14:offset+16])[0]
                counter = 0
                while counter < NumberOfNamedEntries + NumberOfIdEntries:
                    self.recursiveReadTree(i, offset+16+counter*8, 8)
                    counter += 1
            elif size == 16 and isDataEntry:
                """ _IMAGE_RESOURCE_DATA_ENTRY """
                OffsetToData = struct.unpack('I', self.sectionDict[i]['data'][offset:offset+4])[0]
                Size = struct.unpack('I', self.sectionDict[i]['data'][offset+4:offset+8])[0]
                CodePage = struct.unpack('I', self.sectionDict[i]['data'][offset+8:offset+12])[0]
                Reserved = struct.unpack('I', self.sectionDict[i]['data'][offset+12:offset+16])[0]
                print('OffsetToData=0x%x, Size=0x%x, CodePage=0x%x, Reserved=0x%x'%(OffsetToData, Size, CodePage, Reserved))
                self.rsrc_patchpoints[offset] = OffsetToData

    def fillOptHeaderFields(self, peOptionalHeader):
        last_index = 96
        if self.is32bit:
            try: # Python3
                self.peoptDict['02_majorlnkv'] = struct.unpack('b', bytes([peOptionalHeader[2]]))[0]
                self.peoptDict['03_minorlnkv'] = struct.unpack('b', bytes([peOptionalHeader[3]]))[0]
            except: # Python2
                self.peoptDict['02_majorlnkv'] = struct.unpack('b', peOptionalHeader[2])[0]
                self.peoptDict['03_minorlnkv'] = struct.unpack('b', peOptionalHeader[3])[0]
            self.peoptDict['04_codesize'] = struct.unpack('i', peOptionalHeader[4:8])[0]
            self.peoptDict['05_initsize'] = struct.unpack('i', peOptionalHeader[8:12])[0]
            self.peoptDict['06_uninitsize'] = struct.unpack('i', peOptionalHeader[12:16])[0]
            self.peoptDict['07_entrypoint'] = struct.unpack('i', peOptionalHeader[16:20])[0]
            self.peoptDict['08_baseofcode'] = struct.unpack('i', peOptionalHeader[20:24])[0]
            self.peoptDict['09_baseofdata'] = struct.unpack('i', peOptionalHeader[24:28])[0]
            self.peoptDict['10_imagebase'] = struct.unpack('i', peOptionalHeader[28:32])[0]
            self.peoptDict['11_sectionalignment'] = struct.unpack('i', peOptionalHeader[32:36])[0]
            self.peoptDict['12_filealignment'] = struct.unpack('I', peOptionalHeader[36:40])[0]
            self.peoptDict['13_majorop'] = struct.unpack('h', peOptionalHeader[40:42])[0]
            self.peoptDict['14_minorop'] = struct.unpack('h', peOptionalHeader[42:44])[0]
            self.peoptDict['15_majorimage'] = struct.unpack('h', peOptionalHeader[44:46])[0]
            self.peoptDict['16_minorimage'] = struct.unpack('h', peOptionalHeader[46:48])[0]
            self.peoptDict['17_majorsubver'] = struct.unpack('h', peOptionalHeader[48:50])[0]
            self.peoptDict['18_minorsubver'] = struct.unpack('h', peOptionalHeader[50:52])[0]
            self.peoptDict['19_win32verval'] = struct.unpack('i', peOptionalHeader[52:56])[0]
            self.peoptDict['20_sizeofimage'] = struct.unpack('i', peOptionalHeader[56:60])[0]
            self.peoptDict['21_sizeofheaders'] = struct.unpack('i', peOptionalHeader[60:64])[0]
            self.peoptDict['22_checksum'] = struct.unpack('i', peOptionalHeader[64:68])[0]
            self.peoptDict['23_subsystem'] = struct.unpack('h', peOptionalHeader[68:70])[0]
            self.peoptDict['24_DllCharacteristics'] = bin(int(hex(struct.unpack('h', peOptionalHeader[70:72])[0]), 16))[2:]
            self.peoptDict['25_SizeOfStackReserve'] = struct.unpack('i', peOptionalHeader[72:76])[0]
            self.peoptDict['26_SizeOfStackCommit'] = struct.unpack('i', peOptionalHeader[76:80])[0]
            self.peoptDict['27_SizeOfHeapReserve'] = struct.unpack('i', peOptionalHeader[80:84])[0]
            self.peoptDict['28_SizeOfHeapCommit'] = struct.unpack('i', peOptionalHeader[84:88])[0]
            self.peoptDict['29_loaderflags'] = struct.unpack('I', peOptionalHeader[88:92])[0]
            self.peoptDict['30_NumberOfRvaAndSizes'] = struct.unpack('I', peOptionalHeader[92:96])[0]
            return last_index
        else:
            # 64bit binary
            try: # Python3
                self.peoptDict['02_majorlnkv'] = struct.unpack('b', bytes([peOptionalHeader[2]]))[0]
                self.peoptDict['03_minorlnkv'] = struct.unpack('b', bytes([peOptionalHeader[3]]))[0]
            except: # Python2
                self.peoptDict['02_majorlnkv'] = struct.unpack('b', peOptionalHeader[2])[0]
                self.peoptDict['03_minorlnkv'] = struct.unpack('b', peOptionalHeader[3])[0]
            self.peoptDict['04_codesize'] = struct.unpack('i', peOptionalHeader[4:8])[0]
            self.peoptDict['05_initsize'] = struct.unpack('i', peOptionalHeader[8:12])[0]
            self.peoptDict['06_uninitsize'] = struct.unpack('i', peOptionalHeader[12:16])[0]
            self.peoptDict['07_entrypoint'] = struct.unpack('i', peOptionalHeader[16:20])[0]
            self.peoptDict['08_baseofcode'] = struct.unpack('i', peOptionalHeader[20:24])[0]
            self.peoptDict['09_baseofdata'] = 0
            self.peoptDict['10_imagebase'] = struct.unpack('q', peOptionalHeader[24:32])[0]
            self.peoptDict['11_sectionalignment'] = struct.unpack('i', peOptionalHeader[32:36])[0]
            self.peoptDict['12_filealignment'] = struct.unpack('I', peOptionalHeader[36:40])[0]
            self.peoptDict['13_majorop'] = struct.unpack('h', peOptionalHeader[40:42])[0]
            self.peoptDict['14_minorop'] = struct.unpack('h', peOptionalHeader[42:44])[0]
            self.peoptDict['15_majorimage'] = struct.unpack('h', peOptionalHeader[44:46])[0]
            self.peoptDict['16_minorimage'] = struct.unpack('h', peOptionalHeader[46:48])[0]
            self.peoptDict['17_majorsubver'] = struct.unpack('h', peOptionalHeader[48:50])[0]
            self.peoptDict['18_minorsubver'] = struct.unpack('h', peOptionalHeader[50:52])[0]
            self.peoptDict['19_win32verval'] = struct.unpack('i', peOptionalHeader[52:56])[0]
            self.peoptDict['20_sizeofimage'] = struct.unpack('i', peOptionalHeader[56:60])[0]
            self.peoptDict['21_sizeofheaders'] = struct.unpack('i', peOptionalHeader[60:64])[0]
            self.peoptDict['22_checksum'] = struct.unpack('i', peOptionalHeader[64:68])[0]
            self.peoptDict['23_subsystem'] = struct.unpack('h', peOptionalHeader[68:70])[0]
            self.peoptDict['24_DllCharacteristics'] = bin(int(hex(struct.unpack('h', peOptionalHeader[70:72])[0]), 16))[2:]
            self.peoptDict['25_SizeOfStackReserve'] = struct.unpack('q', peOptionalHeader[72:80])[0]
            self.peoptDict['26_SizeOfStackCommit'] = struct.unpack('q', peOptionalHeader[80:88])[0]
            self.peoptDict['27_SizeOfHeapReserve'] = struct.unpack('q', peOptionalHeader[88:96])[0]
            self.peoptDict['28_SizeOfHeapCommit'] = struct.unpack('q', peOptionalHeader[96:104])[0]
            self.peoptDict['29_loaderflags'] = struct.unpack('I', peOptionalHeader[104:108])[0]
            self.peoptDict['30_NumberOfRvaAndSizes'] = struct.unpack('I', peOptionalHeader[108:112])[0]
            last_index = 112
            return last_index

    def readPEOptHeader(self, peOptionalHeader):
        self.peoptDict['01_optionalHeaderMagic'] = peOptionalHeader[0:2].decode('ascii')
        if self.peoptDict['01_optionalHeaderMagic']=='\x0b\x01':
            self.peoptDict['01_optionalHeaderMagic']='PE32'
            self.is32bit = True
        elif self.peoptDict['01_optionalHeaderMagic']=='\x0b\x02':
            self.peoptDict['01_optionalHeaderMagic']='PE32+'
            self.is32bit = False # 64bit binary
        else:
            print('Missing optional header magic!')
            sys.exit(1)

        self.last_index = self.fillOptHeaderFields(peOptionalHeader)
        self.peoptDict['31_imageDataDirectory'] = {}
        init1 = self.last_index
        init2 = self.last_index + 4
        #for i in range(0,  self.peoptDict['NumberOfRvaAndSizes']):
        for i in range(0, 16):
            try:
                rva = struct.unpack('I', peOptionalHeader[init1:init2])[0]
                size = struct.unpack('I', peOptionalHeader[init2:init2+4])[0]
                self.peoptDict['31_imageDataDirectory'][self.datadirNames[i]] = (rva, size)
                if self.datadirNames[i] == 'Resource table':
                    self.rsrc_rva = rva
            except:
                pass
            init1 += 8
            init2 += 8

        #print self.peoptDict['imageDataDirectory']
        #print [peOptionalHeader[96:]], len(peOptionalHeader[96:])

    def readPEHeader(self, peHeader):
        self.peDict['01_machine'] = hexlify(peHeader[0:2]).decode('ascii')
        if self.peDict['01_machine'] == '4c01':
            self.peDict['01_machine'] = "i386 32Bit (0x014c)"
        elif self.peDict['01_machine'] == '6486':
            self.peDict['01_machine'] = "i386 64Bit (0x8664)"
        else:
            print('No machine type found!')
            sys.exit(1)

        self.peDict['02_numberofsections'] = struct.unpack('h', peHeader[2:4])[0]
        self.peDict['03_timedatestamp'] = struct.unpack('i', peHeader[4:8])[0]
        self.peDict['04_pSymbolTable'] = struct.unpack('I', peHeader[8:12])[0]
        self.peDict['05_numSymbols'] = struct.unpack('I', peHeader[12:16])[0]
        self.peDict['06_sizeoptheader'] = struct.unpack('h', peHeader[16:18])[0]
        self.peDict['07_chars'] = bin(int(hex(struct.unpack('H', peHeader[18:20])[0]), 16))

    def readMSDOSHeader(self, msdosHeader):
        self.msdosDict['01_magicnumber'] = struct.unpack('H', msdosHeader[0:2])[0]
        self.msdosDict['02_bytesLastPage'] = struct.unpack('H', msdosHeader[2:4])[0]
        self.msdosDict['03_pagesInFile'] = struct.unpack('H', msdosHeader[4:6])[0]
        self.msdosDict['04_numRelocs'] = struct.unpack('H', msdosHeader[6:8])[0]
        self.msdosDict['05_paragraphs'] = struct.unpack('H', msdosHeader[8:10])[0]
        self.msdosDict['06_minpara'] = struct.unpack('H', msdosHeader[10:12])[0]
        self.msdosDict['07_maxpara'] = struct.unpack('H', msdosHeader[12:14])[0]
        self.msdosDict['08_stackmod'] = struct.unpack('H', msdosHeader[14:16])[0]
        self.msdosDict['09_spregister'] = struct.unpack('H', msdosHeader[16:18])[0]
        self.msdosDict['10_chksum'] = struct.unpack('H', msdosHeader[18:20])[0]
        self.msdosDict['11_ipregister'] = struct.unpack('H', msdosHeader[20:22])[0]
        self.msdosDict['12_codemod'] = struct.unpack('H', msdosHeader[22:24])[0]
        self.msdosDict['13_offsetfirstreloc'] = struct.unpack('H', msdosHeader[24:26])[0]
        self.msdosDict['14_overlaynum'] = struct.unpack('H', msdosHeader[26:28])[0]
        self.msdosDict['15_pPEHeader'] = struct.unpack('I', msdosHeader[60:64])[0]


path = os.path.dirname(__file__)
tool_path = os.path.join(path, 'bin', 'Dia2Dump.exe')

DataDirectories = {
    'ExportDir' : 0, 
    'ExceptionDir' : 3,
    '_tls_used' : 9,
    '_load_config_used' : 10
}
DataDirectoryRva = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
DataDirectorySize = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
rsrc_old_rva = 0

pe_path = sys.argv[1]
pdb_path = pe_path[:pe_path.rfind('.')] + '.pdb'
print('Parsing pdb:%s'%pdb_path)
parse_result = subprocess.check_output([tool_path, '-sym', 'ExportDir', '-sym', 'ExceptionDir', '-sym', '_tls_used', '-sym', '_load_config_used', pdb_path]).decode('utf-8')
print(parse_result)
for line in parse_result.split('\r\n'):
    sp = line.split(':\t')
    key = sp[0].strip()
    if key == 'Name':
        value = sp[1].strip()
        index = DataDirectories[value]
    elif key == 'RelativeVirtualAddress':
        value = sp[1].strip()
        DataDirectoryRva[index] = int(value, 16)

with open(os.path.join(os.path.dirname(pe_path), 'hint.txt'), 'r') as r:
    for line in r.readlines():
        sp = line.strip().split(':')
        if sp[0] == 'ExportDirSize':
            DataDirectorySize[0] = int(sp[1], 16)
        elif sp[0] == 'ExceptionDirSize':
            DataDirectorySize[3] = int(sp[1], 16)
        elif sp[0] == '_tls_used_size':
            DataDirectorySize[9] = int(sp[1], 16)
        elif sp[0] == '_load_config_used_size':
            DataDirectorySize[10] = int(sp[1], 16)
        elif sp[0] == 'rsrc_rva':
            rsrc_old_rva = int(sp[1], 16)


pe = PEFile(pe_path)
with open(pe_path, 'rb+') as rw:
    if pe.rsrc_sec_index:
        rsrc_raw_base = pe.sectionDict[pe.rsrc_sec_index]['ptorawdata']
        rsrc_slide = pe.rsrc_rva - rsrc_old_rva
        print('Patching rsrc (raw base=0x%x) data entry rva with slide=0x%x (0x%x - 0x%x)'%(rsrc_raw_base, rsrc_slide, pe.rsrc_rva, rsrc_old_rva))
        for k in pe.rsrc_patchpoints:
            pos = rsrc_raw_base+k
            newValue = pe.rsrc_patchpoints[k] + rsrc_slide
            print('Patching to 0x%x at raw pos: 0x%x'%(newValue, pos))
            rw.seek(pos)
            rw.write(newValue.to_bytes(4, 'little', signed=False))
    
    dataDirOffset = pe.msdosDict['15_pPEHeader']+4+20+pe.last_index
    for i in range(1, 15):  # skip export directory, we have defined it manually from .def file
        rva = DataDirectoryRva[i]
        size = DataDirectorySize[i]
        if rva != 0 and size != 0:
            offset = dataDirOffset + i*8
            print('Patching DataDirectory[%d](offset=0x%x), rva:0x%x, size:0x%x'%(i, offset, rva, size))
            rw.seek(offset)
            rw.write(rva.to_bytes(4, 'little', signed=False))
            rw.write(size.to_bytes(4, 'little', signed=False))

print('[*] done.')
