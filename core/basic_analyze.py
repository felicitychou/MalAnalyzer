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
import ssdeep
import pefile



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

            # get packer_info
            self.getpacker_info()

            # get info
            if self.filetype.startswith('PE32'):
                self.get_pe_info()
            elif self.filetype.startswith('ELF'):
                self.get_elf_info()

        except Exception as e:
            self.logger.exception('%s: %s' % (Exception, e))
            raise e

    # get packer info:
    def get_packer_info(self):
        # PE (PEid)

        # ELF (UPX)
        cmd = ["/usr/bin/upx","-q", "-t",file_path]
        output = self.check_output_safe(cmd)
        if -1!=output.find("[OK]"):
            return "upx"
        else:
            return None

    # get pe info ？
    def get_pe_info(self):
        # https://github.com/erocarrera/pefile/blob/wiki/UsageExamples.md#introduction
        # load pe
        pe = pefile.PE(self.filepath)
        self.pe_info = pe.dump_info()
        '''
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
        if hasattr(pe,DIRECTORY_ENTRY_EXPORT):
            self.pe_info['DIRECTORY_ENTRY_EXPORT']  = [(hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal) for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols]
        '''

    # get elf info ？？？
    def get_elf_info(self):
        pass

    # get strings unicode and ascii 
    def get_strings(self):
        # windows
        # strings.exe https://technet.microsoft.com/en-us/sysinternals/bb897439.aspx

        # linux
        self.ascii_strings = subprocess.check_output(["strings", "-a", self.filepath])
        self.unicode_strings = subprocess.check_output(["strings", "-a", "-el", self.filepath])
        #return ascii_strings, unicode_strings

    # get hash ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')
    def hash_file(self, hash_type):
        try:
            hash_handle = getattr(hashlib, hash_type)()
            with open(self.filepath, 'rb') as file:
                hash_handle.update(file.read())
            return hash_handle.hexdigest()
        except Exception as e:
            raise e
        
    # get crc32
    def get_crc32(self):
        try:
            with open(self.filepath, 'rb') as file:
                return '%x' % (binascii.crc32(file.read()) & 0xffffffff)
        except Exception as e:
            raise e

    # get ssdeep
    def get_ssdeep(self):
        try:
            return ssdeep.hash_from_file(self.filepath)
        except Exception as e:
            raise e
        
    # output
    def output(self):
        try:
            result = {}
            for item in ('filename','filetype','filesize')
                result[item] = getattr(self,item)
            result.update(self.hash)
            return result
        except Exception as e:
            raise e


if __name__ == '__main__':
    from logger import logger
    filepath = ''
    ba = BasicAnalyzer(filepath = filepath,logger = logger)
    print(ba.output())

