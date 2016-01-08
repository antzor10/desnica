class DosHeader:
	def __init__(self, e_magic='', e_lfanew=''):
		self.e_magic=e_magic
		self.e_lfanew=e_lfanew

class IMAGE_FILE_HEADER:
	def __init__(self, machine='', number_of_sections=0, time_date_stamp='', pointer_to_symboltable='', number_of_symbols='',size_of_optional_header='', characteristics=''):
		self.machine=machine
		self.number_of_sections=number_of_sections
		self.time_date_stamp=time_date_stamp
		self.pointer_to_symboltable=pointer_to_symboltable
		self.number_of_symbols=number_of_symbols
		self.size_of_optional_header=size_of_optional_header
		self.characteristics=characteristics
class IMAGE_DATA:
	def __init__(self, virt_adr='', isize=''):
		self.virt_adr=virt_adr
		self.isize=isize
class IMAGE_DATA_DIRECTORY:
	def __init__(self, export=IMAGE_DATA(), imports=IMAGE_DATA(), resources=IMAGE_DATA(), excep=IMAGE_DATA(), security=IMAGE_DATA(), basereloc=IMAGE_DATA(), debug=IMAGE_DATA(), copyright=IMAGE_DATA(), globalptr=IMAGE_DATA(), tls=IMAGE_DATA(), load_config=IMAGE_DATA(), bound_import=IMAGE_DATA(), iat=IMAGE_DATA(), delay_import=IMAGE_DATA(), com_descriptor=IMAGE_DATA(), directory_entries=IMAGE_DATA()):
		self.export=export
		self.imports=imports
		self.resources=resources
		self.excep=excep
		self.security=security
		self.basereloc=basereloc
		self.debug=debug
		self.copyright=copyright
		self.globalptr=globalptr
		self.tls=tls
		self.load_config=load_config
		self.bound_import=bound_import
		self.iat=iat
		self.delay_import=delay_import
		self.com_descriptor=com_descriptor
		self.directory_entries=directory_entries
class IMAGE_OPTIONAL_HEADER:
	def __init__(self, address_of_entry_point='', base_of_code='', base_of_data='', image_base='', data_directory=IMAGE_DATA_DIRECTORY()):
		self.address_of_entry_point=address_of_entry_point
		self.base_of_code=base_of_code
		self.base_of_data=base_of_data
		self.image_base=image_base
		self.data_directory=data_directory
class PeHeader:
	def __init__(self, signature='', file_header=IMAGE_FILE_HEADER(), optional_header=IMAGE_OPTIONAL_HEADER()):
		self.signature=signature
		self.file_header=file_header
		self.optional_header=optional_header
class IMAGE_SECTION_HEADER:
	def __init__(self,section_hex='', name1='', virtual_size='', virtual_address='', size_of_raw_data='', pointer_to_raw_data='', pointer_to_relocations='', pointer_to_linenumbers='', number_of_relocations='', number_of_linenumbers='', characteristics=''):
		self.name1=name1
		self.virtual_size=virtual_size
		self.virtual_address=virtual_address
		self.size_of_raw_data=size_of_raw_data
		self.pointer_to_raw_data=pointer_to_raw_data
		self.pointer_to_relocations=pointer_to_relocations
		self.pointer_to_linenumbers=pointer_to_linenumbers
		self.number_of_relocations=number_of_relocations
		self.number_of_linenumbers=number_of_linenumbers
		self.characteristics=characteristics
		self.section_hex=section_hex
class IMAGE_IMPORT_DESCRIPTORS:
	def __init__(self, ft='', time_date='', fc='', name1='', first_thunk='', number=0):
		self.ft=ft
		self.time_date=time_date
		self.fc=fc
		self.name1=name1
		self.first_thunk=first_thunk
		self.number=number
class FUNCTION_NAME:
	def __init__(self, address='', name=''):
		self.address=address
		self.name=name
class DLLS:
	def __init__(self, name='',kol=0, func=[FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME(),FUNCTION_NAME()]):
		self.name=name
		self.func=func
		self.kol=kol

def signed_byte(b):
   if hex(ord(b))=='0x80':
     return -(256 - b)
   return b
def signed_dword(d):
   val = unsigned_dword(d)
   if val & 0x80000000:
      return -(0x100000000 - val)
   return val

def unsigned_dword(d):
   val = 0
   shift = 0
   for b in d:
      val = val + (ord(b) << shift)
      shift += 8
   return val