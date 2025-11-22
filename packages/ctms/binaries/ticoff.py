import struct
from pathlib import Path
from typing import Any, Self, Type, Iterator
from ctms.utils import pathutils

class TiCoffSection:
	""" Provides read only access to a section within a ti coff image"""

	ENT_SIZE = 48
	""" The size of a section entry within the image in bytes """

	_idx   : int
	_laddr : int
	_eaddr : int
	_name  : str
	_data  : memoryview

	def __init__(self, name: str, idx: int, ent: tuple[Any], data: memoryview, blen: int):
		self._name  = name
		self._idx   = idx
		self._eaddr = ent[2]
		self._laddr = ent[3]
		self._data  = self._get_data(data, ent, blen)

	def _get_data(self, data: memoryview, ent: tuple[Any], blen: int) -> memoryview:
		offset = ent[5]
		dlen   = ent[4] * blen
		return data[offset:offset+dlen]

	@property
	def laddr(self) -> int:
		""" Gets the load address of the section """
		return self._laddr
	
	@property
	def eaddr(self) -> int:
		""" Gets the execution address of the section """
		return self._eaddr

	@property
	def name(self) -> str:
		""" Gets the name of the section """
		return self._name
	
	@property
	def data(self) -> memoryview:
		""" Gets a view of the data that comprises the section within the image """
		return self._data

class TiCoffSymbol:
	""" Provides read only access to a symbol within a ti coff image"""

	ENT_SIZE = 18
	""" The size of a symbol entry within the image in bytes """

	STC_EXT = 2
	""" The storage class value for external symbols """

	ABS = -1
	""" The type of an absolute symbol """

	_value : int
	_sect  : int
	_name  : str

	def __init__(self, name: str, ent: tuple[Any]):
		self._name  = name
		self._value = ent[2]
		self._sect  = ent[3]

	@property
	def is_abs(self) -> bool:
		""" Gets a value that indicates if the symbol is an absolute symbol """
		return self._sect == self.ABS

	@property
	def value(self) -> int:
		""" Gets the value of the symbol """
		return self._value

	@property
	def sect(self) -> int:
		""" Gets the index of the section that the symbol resides in"""
		return self._sect

	@property
	def name(self) -> str:
		""" Gets the name of the symbol """
		return self._name

class TiCoffSectionTable:
	""" Provides read only access to the section table of a ti coff image """

	_sects : list[TiCoffSection]
	_tab   : dict[str, TiCoffSection]

	def __init__(self, sects: list[TiCoffSection]):
		self._sects = sects
		self._tab   = { sect.name: sect for sect in sects }

	def _load_tab(self, sects: list[TiCoffSection]) -> dict[str, TiCoffSection]:
		tab = { }
		for sect in sects:
			if sect.name in tab:
				raise KeyError(f"A duplicate section: '{sect.name}' exists within the image.")
			tab[sect.name] = sect
		return tab

	def __len__(self) -> int:
		return len(self._sects)
	
	def __iter__(self) -> Iterator[TiCoffSection]:
		return iter(self._sects)

class TiCoffSymbolTable:
	""" Provides read only access to the symbol table of a ti coff image"""

	_syms : list[TiCoffSymbol]
	_tab  : dict[str, TiCoffSymbol]

	def __init__(self, syms: list[TiCoffSymbol]):
		self._syms = syms
		self._tab  = self._load_tab(syms)

	def _load_tab(self, syms: list[TiCoffSymbol]) -> dict[str, TiCoffSymbol]:
		tab = { }
		for sym in syms:
			if sym.name in tab:
				raise KeyError(f"A duplicate external sym: '{sym.name}' exists within the image.")
			tab[sym.name] = sym
		return tab

	def __len__(self) -> int:
		return len(self._syms)
	
	def __iter__(self) -> Iterator[TiCoffSymbol]:
		return iter(self._syms)

class TiCoffImage:
	""" Provides read only access to the information within a ti coff image """

	MAGIC : int = 0x0108
	""" The value required to be at offset 22 within the header enter of the image """

	HDR_ENT_SIZE : int = 50
	""" The size of a header entry within the image in bytes """

	NAME_ENT_SIZE : int = 8
	""" The size of a name entry within the image in bytes """

	_tid     : int
	_entry   : int
	_nsects  : int
	_nsyms   : int
	_symtaba : int
	_strtaba : int
	_blen    : int
	_data    : memoryview
	_sectab  : TiCoffSectionTable
	_symtab  : TiCoffSymbolTable

	# Table of target architecture byte lengths
	_wtids = { 0x9D }

	def __init__(self, data: bytes | bytearray | memoryview):
		"""
		Constructs a new coff image using the data from a buffer

		Args:
			data: The data comprising image

		Raises:
			MemoryError: If the data does not comprise a valid image
		"""
		self._load(data if isinstance(data, memoryview) else memoryview(data))

	def to_bin(self, laddr: int, len: int, fill: int = 0xFF) -> bytearray:
		bin = bytearray([fill] * len)
		self.bin_cpy(bin, laddr)
		return bin

	def bin_cpy(self, dst: memoryview, laddr: int):
		lend = laddr + len(dst)
		for sect in self.sectab:
			data   = sect.data
			dlen   = len(data)
			sladdr = sect.laddr
			if (sladdr >= laddr) and ((sladdr + dlen) <= lend):
				print(sect.name)
				dst[sladdr-laddr:sladdr-laddr+dlen] = data

	@classmethod
	def from_file(cls: Type[Self], fpath: str | Path) -> Self:
		"""
		Creates a new image by loading the contents of a file

		Args:
			fpath: The path of the file to load

		Returns:
			The loaded image
		"""
		return TiCoffImage(pathutils.str2path(fpath).read_bytes())

	def _load(self, data: memoryview) -> None:
		dlen = len(data)

		# Make sure there is enough data within the buffer
		if (dlen < self.HDR_ENT_SIZE):
			raise MemoryError("The data does not comprise a valid image.")
		
		# Unpack the header
		hdr = struct.unpack("<2H3I5H6I", data[:self.HDR_ENT_SIZE])

		# Load the header
		nsects  = hdr[1]
		symtaba = hdr[3]
		nsyms   = hdr[4]
		tid     = hdr[7]
		magic   = hdr[8]
		entry   = hdr[13]

		# Resolve some info
		sectabe = nsects * TiCoffSection.ENT_SIZE + self.HDR_ENT_SIZE
		symtabl = nsyms * TiCoffSymbol.ENT_SIZE
		symtabe = symtaba + symtabl
		strtaba = symtabl + symtaba
		strtabl = dlen - strtaba

		# Make sure the magic value is valid
		if (magic != self.MAGIC):
			raise MemoryError(f"Expected magic: {self.MAGIC} but read {magic}.")
		
		# Make sure the target id is valid
		elif (tid == 0):
			raise MemoryError("The target for the image is not valid")
		
		# Make sure the section table is valid
		elif (sectabe >= dlen):
			raise MemoryError("The image does not contain a valid section table.")
		
		# Make sure the symbol table is valid
		if (symtabe >= dlen):
			raise MemoryError("The image does not contain a valid symbol table.")
		
		# Make sure the string table is valid
		if (strtabl <= 0):
			raise MemoryError("The image does not contain a valid string table.")
		
		# Initialize the image
		self._data    = data
		self._tid     = tid
		self._blen    = 2 if tid in self._wtids else 1
		self._nsects  = nsects
		self._nsyms   = nsyms
		self._symtaba = symtaba
		self._strtaba = strtaba
		self._entry   = entry
		self._sectab  = self._load_sectab()
		self._symtab  = self._load_symtab()

	def _load_sectab(self) -> TiCoffSectionTable:
		offset = self.HDR_ENT_SIZE
		sects  = []
		for idx in range(0, self._nsects):
			ent  = struct.unpack("12I", self._data[offset:offset+TiCoffSection.ENT_SIZE])
			name = self._get_ent_name(offset, ent)
			sects.append(TiCoffSection(name, idx, ent, self._data, self._blen))
			offset += TiCoffSection.ENT_SIZE
		return TiCoffSectionTable(sects)

	def _load_symtab(self) -> TiCoffSymbolTable:
		offset  = self._symtaba
		symbols = []
		for idx in range(0, self._nsyms):
			ent = struct.unpack("3I2h2B", self._data[offset:offset+TiCoffSymbol.ENT_SIZE])
			if(ent[5] == TiCoffSymbol.STC_EXT):
				name = self._get_ent_name(offset, ent)
				symbols.append(TiCoffSymbol(name, ent))
			offset += TiCoffSymbol.ENT_SIZE
		return TiCoffSymbolTable(symbols)
	
	def _get_ent_name(self, offset: int, ent: tuple[Any]):
		if (ent[0] == 0):
			return self._get_str(ent[1])
		return self._dec_str(self._data[offset:offset+self.NAME_ENT_SIZE])

	def _get_str(self, offset: int):
		return self._dec_str(self._data[self._strtaba + offset:])

	def _dec_str(self, data: memoryview) -> str:
		slen = 0
		dlen = len(data)
		while ((slen < dlen) and (data[slen] != 0)):
			slen += 1
		return data[:slen].tobytes().decode()
	
	@property
	def symtab(self) -> TiCoffSymbolTable:
		""" Gets the symbol table within the image. The symbol table only contains external
			symbols residing within the image. """
		return self._symtab
	
	@property
	def sectab(self) -> TiCoffSectionTable:
		""" Gets the section table within the image """
		return self._sectab