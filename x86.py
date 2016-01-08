from structur import *
from capstone import *


def GETx86(par):
	#par=x
	#return par
#par=heks
	chk=0
	disassembled=b''
	md = Cs(CS_ARCH_X86, CS_MODE_32)
	Dos_Header = DosHeader()
	PE_Header = PeHeader()
	Section_Table = [IMAGE_SECTION_HEADER(),IMAGE_SECTION_HEADER(),IMAGE_SECTION_HEADER(),IMAGE_SECTION_HEADER(),IMAGE_SECTION_HEADER(),IMAGE_SECTION_HEADER(),IMAGE_SECTION_HEADER(),IMAGE_SECTION_HEADER(),IMAGE_SECTION_HEADER(),IMAGE_SECTION_HEADER(),IMAGE_SECTION_HEADER(),IMAGE_SECTION_HEADER(),IMAGE_SECTION_HEADER(),IMAGE_SECTION_HEADER(),IMAGE_SECTION_HEADER()]
	Import_Directory = [IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS(),IMAGE_IMPORT_DESCRIPTORS()]
	DLL = [DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS(),DLLS()]
	pointer_to_imptable = 0
	pointer_to_func_name = 0
	RA = 0
	pointer_to_import_directory = 0

	Dos_Header.e_magic = par[:2]
	Dos_Header.e_lfanew = hex(signed_dword(par[60:63]))
	PE_Header.signature = par[int(Dos_Header.e_lfanew,16):int(Dos_Header.e_lfanew,16)+4]
	PE_Header.file_header.machine                   = hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+4:int(Dos_Header.e_lfanew,16)+6]))
	PE_Header.file_header.number_of_sections        =signed_dword(par[int(Dos_Header.e_lfanew,16)+6:int(Dos_Header.e_lfanew,16)+8])
	PE_Header.file_header.size_of_optional_header   =signed_dword(par[int(Dos_Header.e_lfanew,16)+20:int(Dos_Header.e_lfanew,16)+22])
	PE_Header.file_header.characteristics           =signed_dword(par[int(Dos_Header.e_lfanew,16)+22:int(Dos_Header.e_lfanew,16)+24])
	PE_Header.optional_header.address_of_entry_point=signed_dword(par[int(Dos_Header.e_lfanew,16)+40:int(Dos_Header.e_lfanew,16)+44])
	PE_Header.optional_header.base_of_code          =signed_dword(par[int(Dos_Header.e_lfanew,16)+44:int(Dos_Header.e_lfanew,16)+48])
	PE_Header.optional_header.base_of_data          =signed_dword(par[int(Dos_Header.e_lfanew,16)+48:int(Dos_Header.e_lfanew,16)+52])
	PE_Header.optional_header.image_base            =signed_dword(par[int(Dos_Header.e_lfanew,16)+52:int(Dos_Header.e_lfanew,16)+56])

	PE_Header.optional_header.data_directory.export.virt_adr   =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+120:int(Dos_Header.e_lfanew,16)+124]))
	PE_Header.optional_header.data_directory.export.isize      =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+124:int(Dos_Header.e_lfanew,16)+128]))
	PE_Header.optional_header.data_directory.imports.virt_adr  =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+128:int(Dos_Header.e_lfanew,16)+132]))
	PE_Header.optional_header.data_directory.imports.isize     =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+132:int(Dos_Header.e_lfanew,16)+136]))
	PE_Header.optional_header.data_directory.resources.virt_adr=hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+136:int(Dos_Header.e_lfanew,16)+140]))
	PE_Header.optional_header.data_directory.resources.isize   =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+140:int(Dos_Header.e_lfanew,16)+144]))
	PE_Header.optional_header.data_directory.excep.virt_adr    =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+144:int(Dos_Header.e_lfanew,16)+148]))
	PE_Header.optional_header.data_directory.excep.isize       =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+148:int(Dos_Header.e_lfanew,16)+152]))
	PE_Header.optional_header.data_directory.security.virt_adr =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+152:int(Dos_Header.e_lfanew,16)+156]))
	PE_Header.optional_header.data_directory.security.isize    =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+156:int(Dos_Header.e_lfanew,16)+160]))
	PE_Header.optional_header.data_directory.basereloc.virt_adr=hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+160:int(Dos_Header.e_lfanew,16)+164]))
	PE_Header.optional_header.data_directory.basereloc.isize   =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+164:int(Dos_Header.e_lfanew,16)+168]))
	PE_Header.optional_header.data_directory.debug.virt_adr    =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+168:int(Dos_Header.e_lfanew,16)+172]))
	PE_Header.optional_header.data_directory.debug.isize       =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+172:int(Dos_Header.e_lfanew,16)+176]))
	PE_Header.optional_header.data_directory.copyright.virt_adr=hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+176:int(Dos_Header.e_lfanew,16)+180]))
	PE_Header.optional_header.data_directory.copyright.isize   =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+180:int(Dos_Header.e_lfanew,16)+184]))
	PE_Header.optional_header.data_directory.globalptr.virt_adr=hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+184:int(Dos_Header.e_lfanew,16)+188]))
	PE_Header.optional_header.data_directory.globalptr.isize   =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+188:int(Dos_Header.e_lfanew,16)+192]))
	PE_Header.optional_header.data_directory.tls.virt_adr      =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+192:int(Dos_Header.e_lfanew,16)+196]))
	PE_Header.optional_header.data_directory.tls.isize         =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+196:int(Dos_Header.e_lfanew,16)+200]))
	PE_Header.optional_header.data_directory.load_config.virt_adr=hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+200:int(Dos_Header.e_lfanew,16)+204]))
	PE_Header.optional_header.data_directory.load_config.isize   =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+204:int(Dos_Header.e_lfanew,16)+208]))
	PE_Header.optional_header.data_directory.bound_import.virt_adr=hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+208:int(Dos_Header.e_lfanew,16)+212]))
	PE_Header.optional_header.data_directory.bound_import.isize   =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+212:int(Dos_Header.e_lfanew,16)+216]))
	PE_Header.optional_header.data_directory.iat.virt_adr         =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+216:int(Dos_Header.e_lfanew,16)+220]))
	PE_Header.optional_header.data_directory.iat.isize            =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+220:int(Dos_Header.e_lfanew,16)+224]))
	PE_Header.optional_header.data_directory.delay_import.virt_adr=hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+224:int(Dos_Header.e_lfanew,16)+228]))
	PE_Header.optional_header.data_directory.delay_import.isize   =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+228:int(Dos_Header.e_lfanew,16)+232]))
	PE_Header.optional_header.data_directory.com_descriptor.virt_adr=hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+232:int(Dos_Header.e_lfanew,16)+236]))
	PE_Header.optional_header.data_directory.com_descriptor.isize   =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+236:int(Dos_Header.e_lfanew,16)+240]))
	PE_Header.optional_header.data_directory.directory_entries.virt_adr=hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+240:int(Dos_Header.e_lfanew,16)+244]))
	PE_Header.optional_header.data_directory.directory_entries.isize   =hex(signed_dword(par[int(Dos_Header.e_lfanew,16)+244:int(Dos_Header.e_lfanew,16)+228]))
	
	pointer_to_section_table = 248 + int(Dos_Header.e_lfanew, 16)
	block=40
	i=0
	ptcs=pointer_to_section_table
	while i<PE_Header.file_header.number_of_sections:
		bufer=par[ptcs:ptcs+block]
		Section_Table[i].name1 = bufer[:8]
		Section_Table[i].virtual_size = hex(signed_dword(bufer[8:12]))
		Section_Table[i].virtual_address = hex(signed_dword(bufer[12:16]))
		Section_Table[i].size_of_raw_data = hex(signed_dword(bufer[16:20]))
		Section_Table[i].pointer_to_raw_data = hex(signed_dword(bufer[20:24]))
		Section_Table[i].pointer_to_relocations = hex(signed_dword(bufer[24:28]))
		Section_Table[i].pointer_to_linenumbers = hex(signed_dword(bufer[28:32]))
		Section_Table[i].number_of_relocations = hex(signed_dword(bufer[32:36]))
		Section_Table[i].number_of_linenumbers = hex(signed_dword(bufer[36:40]))
		Section_Table[i].characteristics = hex(signed_dword(bufer[40:44]))
		Section_Table[i].section_hex = par[int(Section_Table[i].pointer_to_raw_data,16):int(Section_Table[i].pointer_to_raw_data,16)+int(Section_Table[i].size_of_raw_data,16)]
		ptcs+=block
		i+=1
	i = 0
	while i < PE_Header.file_header.number_of_sections:
		if PE_Header.optional_header.data_directory.imports.virt_adr==Section_Table[i].virtual_address:
			pointer_to_imptable = i
		elif PE_Header.optional_header.data_directory.iat.virt_adr==Section_Table[i].virtual_address:
			pointer_to_imptable = i
		i+=1

	if PE_Header.optional_header.data_directory.iat.virt_adr != b'0x0':
		RA = int(PE_Header.optional_header.data_directory.iat.virt_adr,16) - int(Section_Table[pointer_to_imptable].pointer_to_raw_data,16)
	else:
		RA = int(PE_Header.optional_header.data_directory.imports.virt_adr,16) - int(Section_Table[pointer_to_imptable].pointer_to_raw_data,16)

	pointer_to_import_directory = int(PE_Header.optional_header.data_directory.imports.virt_adr,16) - RA
	t=True
	j=pointer_to_import_directory
	i=0
	while t == True:
		block = par[j:j+20]
		if block == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
			t=False
			Import_Directory[0].number=i
			break
		Import_Directory[i].ft          = hex(signed_dword(block[:4]))
		Import_Directory[i].time_date   = hex(signed_dword(block[4:8]))
		Import_Directory[i].fc          = hex(signed_dword(block[8:12]))
		Import_Directory[i].name1       = hex(signed_dword(block[12:16]))
		Import_Directory[i].first_thunk = hex(signed_dword(block[16:20]))
		i+=1
		j+=20
	i=0
	while i < Import_Directory[0].number:
		for j in par[int(Import_Directory[i].name1,16)-RA:]:
			if j == b'\x00':
				break
			DLL[i].name+=j
		i+=1

	
	f2 = open('import.txt','w+')
	i=0
	adres = int(Section_Table[pointer_to_imptable].virtual_address,16)+int(hex(PE_Header.optional_header.image_base),16)
	while i < Import_Directory[0].number:
		t=True
		y=0
		fts = int(Import_Directory[i].first_thunk,16)-RA
		while t==True:
			buf=b''
			pointer_to_func_name = signed_dword(par[fts:fts+4])-RA+2
			if par[fts] == b'\x00':
				t=False
				DLL[i].kol=y
				break
			for k in par[pointer_to_func_name:]:
				if k == b'\x00':
					break
				buf+=k
			DLL[i].func[y].name=buf
			DLL[i].func[y].address= hex(adres)
			print(DLL[i].name,DLL[i].func[y].name,DLL[i].func[y].address)
			f2.write(DLL[i].func[y].address+DLL[i].func[y].name+' '+DLL[i].name+'\n')
			adres+=len(buf)
			fts+=4
			y+=1
		i+=1
		
	local=PE_Header.optional_header.address_of_entry_point + PE_Header.optional_header.image_base
	n=0
	i=0
	while i< PE_Header.file_header.number_of_sections:
		if format("%s" %(Section_Table[i].name1))==b'\x2E\x63\x6F\x64\x65\x00\x00\x00':
			n=i
		if format("%s" %(Section_Table[i].name1))==b'\x2E\x74\x65\x78\x74\x00\x00\x00':
			n=i
		i+=1
	print(n)
	for i in md.disasm(Section_Table[n].section_hex, local):
		disassembled+=format("0x%x:  %s  %s" %(i.address, i.mnemonic, i.op_str)+'\n')
	f = open('code.txt','w+')
	f1 = open('data.txt','w+')
	
	f.write(disassembled)
	


	f.close()	
	f2.close()
	f1.close()
	return PE_Header