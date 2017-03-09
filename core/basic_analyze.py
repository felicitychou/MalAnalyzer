#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1
# author = felicitychou

import os
import time
import hashlib
import binascii
import subprocess

import magic
import pefile
import peutils
import ssdeep
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import (
    describe_ei_class, describe_ei_data, describe_ei_version,
    describe_ei_osabi, describe_e_type, describe_e_machine,
    describe_e_version_numeric, describe_p_type, describe_p_flags,
    describe_sh_type, describe_sh_flags,
    describe_symbol_type, describe_symbol_bind, describe_symbol_visibility,
    describe_symbol_shndx, describe_reloc_type, describe_dyn_tag,
    describe_ver_flags, describe_note)
from elftools.elf.constants import E_FLAGS
from elftools.elf.sections import SymbolTableSection

from conf import basic_conf

# filename filetype filesize md5 sha1
class BasicAnalyzer(object):

    def __init__(self,filepath,logger):

        self.filepath = filepath
        self.logger = logger
        self.run()

    def run(self):
        '''
        return {filename,filetype,filesize(Byte)}
        '''
        try:
            self.filename = os.path.basename(self.filepath)
            self.filetype = magic.from_file(self.filepath)
            self.filesize = int(os.path.getsize(self.filepath))
            self.hash = {"md5":self.hash_file('md5'),
                        "sha256":self.hash_file('sha256'),
                        "crc32":self.get_crc32(),
                        "ssdeep":self.get_ssdeep()}
            # get strings
            self.get_strings()
            self.strings = {"ascii":self.ascii_strings,"unicode":self.unicode_strings}

            # get info (include packer info)
            #if self.filetype.startswith('PE32'):
            #    self.get_pe_info()
            #elif self.filetype.startswith('ELF'):
            #    self.get_elf_info()

        except Exception as e:
            self.logger.exception('%s: %s' % (Exception, e))
            
    
    # get packer info:
    def get_packer_info_pe(self,pe):
        # PE (PEid)
        # pe = pefile.PE(self.filepath)
        signatures = peutils.SignatureDatabase(basic_conf["PEidSign_path"])
        # matches is list()
        self.packer = signatures.match_all(pe, ep_only = True)

    def get_packer_info_elf(self):
        # ELF (UPX)
        cmd = [basic_conf["UPX_path"],"-q", "-t",self.filepath]
        output = subprocess.check_output(cmd)
        if -1!=output.find("[OK]"):
            self.packer = "upx"
        else:
            self.packer = None

    # get pe info
    def get_pe_info(self):

        # https://github.com/erocarrera/pefile/blob/wiki/UsageExamples.md#introduction
        # load pe
        pe = pefile.PE(self.filepath)
        self.get_packer_info_pe(pe = pe)
        #self.pe_info = pe.dump_info()

        self.pe_info = {}
        # Machine
        if hasattr(pe.FILE_HEADER,'Machine'):
            self.pe_info['Machine'] = hex(pe.FILE_HEADER.Machine)

        # TimeDateStamp
        if hasattr(pe.FILE_HEADER,'TimeDateStamp'):
            self.pe_info['TimeDataStamp'] = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(pe.FILE_HEADER.TimeDateStamp))

        # AddressOfEntryPoint
        if hasattr(pe.OPTIONAL_HEADER,'AddressOfEntryPoint'):
            self.pe_info['AddressOfEntryPoint'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        
        # Iterating through the sections
        if hasattr(pe,'sections'):
            self.pe_info['sections'] = [(section.Name, hex(section.VirtualAddress),hex(section.Misc_VirtualSize), hex(section.PointerToRawData), hex(section.SizeOfRawData)) for section in pe.sections]
        
        # Listing the imported symbols
        if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
            import_info = {}
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                import_info[entry.dll] = [(hex(imp.address), imp.name) for imp in entry.imports]
        self.pe_info['DIRECTORY_ENTRY_IMPORT'] = import_info
        
        # Listing the exported symbols
        if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):
            self.pe_info['DIRECTORY_ENTRY_EXPORT']  = [(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal) for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols]

    '''
    # get elf info ？？？
    def get_elf_info(self):
        self.get_packer_info_elf()
        with open(self.filepath,'rb') as f:
            elffile = ELFFile(f)
        self._parse_elf_info(elffile=elffile)


    def decode_flags(self, flags):
        description = ""
        if self.elffile['e_machine'] == "EM_ARM":
            if flags & E_FLAGS.EF_ARM_HASENTRY:
                description += ", has entry point"

            version = flags & E_FLAGS.EF_ARM_EABIMASK
            if version == E_FLAGS.EF_ARM_EABI_VER5:
                description += ", Version5 EABI"
        elif self.elffile['e_machine'] == "EM_MIPS":
            if flags & E_FLAGS.EF_MIPS_NOREORDER:
                description += ", noreorder"
            if flags & E_FLAGS.EF_MIPS_CPIC:
                description += ", cpic"
            if not (flags & E_FLAGS.EF_MIPS_ABI2) and not (flags & E_FLAGS.EF_MIPS_ABI_ON32):
                description += ", o32"
            if (flags & E_FLAGS.EF_MIPS_ARCH) == E_FLAGS.EF_MIPS_ARCH_1:
                description += ", mips1"

        return description

    
    def _format_hex(self, addr, fieldsize=None, fullhex=False, lead0x=True,alternate=False):
            """ Format an address into a hexadecimal string.
            fieldsize:
                Size of the hexadecimal field (with leading zeros to fit the
                address into. For example with fieldsize=8, the format will
                be %08x
                If None, the minimal required field size will be used.
            fullhex:
                If True, override fieldsize to set it to the maximal size
                needed for the elfclass
            lead0x:
                If True, leading 0x is added
            alternate:
                If True, override lead0x to emulate the alternate
                hexadecimal form specified in format string with the #
                character: only non-zero values are prefixed with 0x.
                This form is used by readelf.
            """
        if alternate:
            if addr == 0:
                lead0x = False
            else:
                lead0x = True
                fieldsize -= 2
    
        s = '0x' if lead0x else ''
        if fullhex:
           fieldsize = 8 if self.elffile.elfclass == 32 else 16
        if fieldsize is None:
            field = '%x'
        else:
            field = '%' + '0%sx' % fieldsize
        return s + field % addr


    def _parse_elf_info(self,elffile):
        # https://github.com/eliben/pyelftools/blob/master/scripts/readelf.py

        header = {}
        e_ident = elffile.header['e_ident']
        header['Magic'] = ' '.join('%2.2x' % byte2int(b) for b in elffile.e_ident_raw)
        header['Class'] = '%s' % describe_ei_class(e_ident['e_ident']['EI_CLASS'])
        header['Data'] = '%s' % describe_ei_data(e_ident['e_ident']['EI_DATA'])        
        header['Version'] = '%s' % describe_ei_version(e_ident['EI_VERSION'])
        header['OS_ABI'] = '%s' %describe_ei_osabi(e_ident['EI_OSABI'])
        header['ABI_Version'] = '%d' % e_ident['EI_ABIVERSION']
        header['Type'] = '%s' % describe_e_type(header['e_type'])
        header['Machine'] = '%s' % describe_e_machine(header['e_machine'])
        header['Version'] = '%s' % describe_e_version_numeric(header['e_version'])
        header['Entry'] = '%s' % self._format_hex(header['e_entry'])
        header['Phoff'] = '%s' % header['e_phoff']
        header['shoff'] = '%s' % header['e_shoff']
        header['flags'] = '%s%s' % (self._format_hex(header['e_flags']),self.decode_flags(header['e_flags']))
        header['ehsize'] = '%s (bytes)' % header['e_ehsize']
        header['phentsize'] = '%s (bytes)' % header['e_phentsize']
        header['phnum'] = '%s' % header['e_phnum']
        header['shentsize'] = '%s (bytes)' % header['e_shentsize']
        header['shnum'] = '%s' % header['e_shnum']
        header['shstrndx'] = '%s' % header['e_shstrndx']

        sections = []
        for nsec, section in enumerate(elffile.iter_sections()):
            section_info = {}
            section_info['nsec'] = '%2u' % nsec
            section_info['section.name'] = '%-17.17s' % section.name
            section_info['sh_type'] = '%-15.15s' % describe_sh_type(section['sh_type'])                
            if self.elffile.elfclass == 32:
                section_info['sh_addr'] = '%s' % self._format_hex(section['sh_addr'], fieldsize=8, lead0x=False)
                section_info['sh_offset'] = '%s' % self._format_hex(section['sh_offset'], fieldsize=6, lead0x=False)
                section_info['sh_size'] = '%s' % self._format_hex(section['sh_size'], fieldsize=6, lead0x=False)
                section_info['sh_entsize'] = '%s' % self._format_hex(section['sh_entsize'], fieldsize=2, lead0x=False)
                section_info['sh_flags'] = '%3s' % describe_sh_flags(section['sh_flags'])
                section_info['sh_link'] = '%2s' % section['sh_link']
                section_info['sh_info'] = '%3s' % section['sh_info']
                section_info['sh_addralign'] = '%2s' % section['sh_addralign']
            else: # 64
                section_info['sh_addr'] = '%s' % self._format_hex(section['sh_addr'], fullhex=True, lead0x=False)
                section_info['sh_offset']  = '%s' % self._format_hex(section['sh_offset'],fieldsize=16 if section['sh_offset'] > 0xffffffff else 8,lead0x=False)
                section_info['sh_size'] = '%s' % self._format_hex(section['sh_size'], fullhex=True, lead0x=False)
                section_info['sh_entsize'] = '%s' % self._format_hex(section['sh_entsize'], fullhex=True, lead0x=False)
                section_info['sh_flags'] = '%3s' % describe_sh_flags(section['sh_flags'])
                section_info['sh_link'] = '%2s' % section['sh_link'],
                section_info['sh_info'] = '%3s' % section['sh_info']
                section_info['sh_addralign'] = '%s' % section['sh_addralign']
            sections.append(section_info)

        segments = []
        if elffile.num_segments() == 0:
            return
        else:
            for segment in elffile.iter_segments():
                segment_info = {}
                segment_info['p_type'] = '%-14s' % describe_p_type(segment['p_type'])
                if elffile.elfclass == 32:
                    segment_info['p_offset'] = '%s' % self._format_hex(segment['p_offset'], fieldsize=6)
                    segment_info['p_vaddr'] = '%s' % self._format_hex(segment['p_vaddr'], fullhex=True)
                    segment_info['p_paddr'] = '%s' % self._format_hex(segment['p_paddr'], fullhex=True)
                    segment_info['p_filesz'] = '%s' % self._format_hex(segment['p_filesz'], fieldsize=5)
                    segment_info['p_memsz'] = '%s' % self._format_hex(segment['p_memsz'], fieldsize=5)
                    segment_info['p_flags'] = '%s' % describe_p_flags(segment['p_flags'])
                    segment_info['p_align'] = '%-3s' % self._format_hex(segment['p_align'])
                else: # 64
                    segment_info['p_offset'] = '%s' % self._format_hex(segment['p_offset'], fullhex=True)
                    segment_info['p_vaddr'] = '%s' % self._format_hex(segment['p_vaddr'], fullhex=True)
                    segment_info['p_paddr'] = '%s' % self._format_hex(segment['p_paddr'], fullhex=True)
                    segment_info['p_filesz'] = '%s' % self._format_hex(segment['p_filesz'], fullhex=True)
                    segment_info['p_memsz'] = '%s' % self._format_hex(segment['p_memsz'], fullhex=True)
                    segment_info['p_flags'] = '%-3s' % describe_p_flags(segment['p_flags'])
                    segment_info['p_align'] = '%s' % self._format_hex(segment['p_align'], lead0x=False)
                segments.append(segment_info)

        symbols = []

            for section in self.elffile.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue

                if section['sh_entsize'] == 0:
                    continue

                for nsym, symbol in enumerate(section.iter_symbols()):
                    symbol_info[''] = '%6d' % nsym
                    symbol_info[''] = '%s' % self._format_hex(symbol['st_value'], fullhex=True, lead0x=False)
                    symbol_info[''] = '%5d' % symbol['st_size']
                    symbol_info[''] = '%-7s' % describe_symbol_type(symbol['st_info']['type'])
                    symbol_info[''] = '%-6s' % describe_symbol_bind(symbol['st_info']['bind'])
                    symbol_info[''] = '%-7s' % describe_symbol_visibility(symbol['st_other']['visibility'])
                    symbol_info[''] = '%4s' % describe_symbol_shndx(symbol['st_shndx'])
                    symbol_info[''] = '%.25s' % symbol.name
        symbols.append(symbol_info)        
    ''' 
    # get strings unicode and ascii 
    def get_strings(self):
        # windows
        # strings.exe https://technet.microsoft.com/en-us/sysinternals/bb897439.aspx

        # linux return string list
        try:
            self.ascii_strings = subprocess.check_output(["strings", "-a", self.filepath]).split('\n')
            self.unicode_strings = subprocess.check_output(["strings", "-a", "-el", self.filepath]).split('\n')
        except Exception as e:
            self.logger.exception('%s: %s' % (Exception, e))


    # get hash ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')
    def hash_file(self, hash_type):
        try:
            hash_handle = getattr(hashlib, hash_type)()
            with open(self.filepath, 'rb') as file:
                hash_handle.update(file.read())
            return hash_handle.hexdigest()
        except Exception as e:
            self.logger.exception('%s: %s' % (Exception, e))
        
    # get crc32
    def get_crc32(self):
        try:
            with open(self.filepath, 'rb') as file:
                return '%x' % (binascii.crc32(file.read()) & 0xffffffff)
        except Exception as e:
            self.logger.exception('%s: %s' % (Exception, e))

    # get ssdeep
    def get_ssdeep(self):
        try:
            return ssdeep.hash_from_file(self.filepath)
        except Exception as e:
            self.logger.exception('%s: %s' % (Exception, e))
        
    # output
    def output(self):
        try:
            result = {}
            for item in ('filename','filetype','filesize'):
                result[item] = getattr(self,item)
            result.update(self.hash)
            return result
        except Exception as e:
            self.logger.exception('%s: %s' % (Exception, e))


    # output json
