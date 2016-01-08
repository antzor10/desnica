from structur import *
from x86 import *

heks=b''
disassembled=b''
Dos_Header = DosHeader()
PE_Header = PeHeader()

program=open('TinyAsm.exe','r+b')
heks=program.read()

Dos_Header.e_lfanew = hex(signed_dword(heks[60:63]))
PE_Header.file_header.machine = hex(signed_dword(heks[int(Dos_Header.e_lfanew,16)+4:int(Dos_Header.e_lfanew,16)+6]))
if PE_Header.file_header.machine==b'0x14c':
	print('This file PE32')
	GETx86(heks)
elif PE_Header.file_header.machine==b'0x200':
	print('This file PE64 (IA64)')
elif PE_Header.file_header.machine==b'0x8664':
	print('This file PE64 (AMD64)')
#print(Dos_Header.e_magic,Dos_Header.e_lfanew,PE_Header.signature,PE_Header.file_header.machine)
program.close()