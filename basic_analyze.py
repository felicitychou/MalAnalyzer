#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1
# author = felicitychou

import os
import magic
import subprocess
import hashlib
import binascii

import pefile


# filename filetype filesize md5 sha1
class BasicAnalyzer(object):

    def __init__(self,filepath):

        self.filepath = filepath
        self.get_file_basic_info()

    def get_file_basic_info(self):
        '''
        return {filename,filetype,filesize(Byte)}
        '''
        self.filename = os.path.basename(self.filepath)
        self.filetype = magic.from_file(self.filepath)
        self.filesize = int(os.path.getsize(self.filepath))
        self.md5 = self.hash_file('md5')
        self.sha1 = self.hash_file('sha1')

    # get pe info
    def get_pe_info(self):
        pe = pefile.PE(self.filepath)

        # section
        for section in pe.sections:
            print (section.Name, hex(section.VirtualAddress),hex(section.Misc_VirtualSize), section.SizeOfRawData)
        # import
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print entry.dll
            for imp in entry.imports:
                print '\t', hex(imp.address), imp.name
        pass

    # get elf info
    def get_elf_info(self):
        pass


    # get strings unicode and ascii
    def get_strings(self):
        # windows
        # strings.exe https://technet.microsoft.com/en-us/sysinternals/bb897439.aspx

        # linux
        ascii_strings = subprocess.check_output(["strings", "-a", self.filepath])
        unicode_strings = subprocess.check_output(["strings", "-a", "-el", self.filepath])
        return ascii_strings, unicode_strings

    # hash
    def hash_file(self, hash_type):
        # file hash cal hash_type('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')
        hash_handle = getattr(hashlib, hash_type)()
        with open(self.filepath, 'rb') as file:
            hash_handle.update(file.read())
        return hash_handle.hexdigest()

    # get crc32
    def get_crc32(self):
        with open(self.filepath, 'rb') as file:
            return '%x' % (binascii.crc32(file.read()) & 0xffffffff)
