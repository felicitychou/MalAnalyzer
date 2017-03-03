#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1
# author = felicitychou

from container import Container
from logger import logger

class DynamicAnalyzer(object):

    def __init__(self,**kw)

        self.logger = logger

        # init filepath,filetype,md5,timeout,result_path,code_path
        for key in ("filepath","filetype","md5","timeout","result_path","code_path")
            if kw.haskey(key):
                setattr(self,key,kw[key])
            else:
                self.logger.error("DynamicAnalyzer: Init but lose %s value." % (key,))
        # init platform
        self.get_platform(self.filetype)

        
    def get_platform(self):
        '''
        select platform

        Example:
        >>> get_platform('PE32 executable (GUI) Intel 80386, for MS Windows')
        'win'
        >>> get_platform('PE32 executable (DLL) (GUI) Intel 80386, for MS Windows')
    
        >>> get_platform('ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, stripped')
        
        >>> get_platform('ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.18, BuildID[sha1]=1e1c12b3c8c09b17ad2fe1a03c24cef5fbb8eac9, not stripped')
        'linux'
        >>> get_platform('ELF 32-bit MSB executable, PowerPC or cisco 4500, version 1 (SYSV), statically linked, stripped')
    
        '''
        
        # PE32 executable Not Dll
        if self.filetype.startswith('PE32 executable'):
            self.platform = ('win' if self.filetype.find("DLL")==-1 else None)
        # ELF Intel 80386/x86-64    
        elif self.filetype.startswith('ELF') and self.filetype.find('executable')!=-1:
            self.platform = ('linux' if (self.filetype.find("Intel 80386")!=-1 or self.filetype.find("x86-64")!=-1) else None)
        else:
            self.platform = None

        self.logger.debug("DynamicAnalyzer: %s Get Platform %s." % (self.filrtype,self.platform))

    def run(self):

        if self.platform:
            container = Container()
            self.logger.debug("DynamicAnalyzer: Init container.")
            self.logger.debug("DynamicAnalyzer: analyze conf %s" )
            container.analyze(name=self.md5,mal_path=self.filepath,timeout=self.timeout,
                            result_path=self.result_path,platform=self.platform,code_path=self.code_path)
        else:
            self.logger.error("DynamicAnalyzer: platform is %s." % (self.platform,))


if __name__=='__main__':
    pass