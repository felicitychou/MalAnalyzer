#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1

from container import Container
from conf import dynamic_conf



class DynamicAnalyzer(object):

    def __init__(self,fileinfo):
        self.filepath = fileinfo['filepath']
        self.filetype = fileinfo['filetype']
        self.md5hash = fileinfo['md5']


    def get_platform(self):
        '''
        select platform

        Example:

        >>> get_platform('PE32 executable (GUI) Intel 80386, for MS Windows')
        'win'
        >>> get_platform('PE32 executable (DLL) (GUI) Intel 80386, for MS Windows')
    
        >>> get_platform('ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, stripped')
        'linux'
        >>> get_platform('ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.18, BuildID[sha1]=1e1c12b3c8c09b17ad2fe1a03c24cef5fbb8eac9, not stripped')
        'linux'
        >>> get_platform('ELF 32-bit MSB executable, PowerPC or cisco 4500, version 1 (SYSV), statically linked, stripped')
    
        '''
        if filetype.startswith('PE32'):
            # PE32 Not Dll
            return ('win' if filetype.find("DLL")==-1 else None)
        elif filetype.startswith('ELF'):
            # ELF Intel 80386/x86-64
            return ('linux' if (filetype.find("Intel 80386")!=-1 or filetype.find("x86-64")!=-1) else None)
        else:
            return None

def dynamic_analyze(filepath,filetype,md5hash):

    platform = get_platform(filetype)
    timeout = dynamic_conf['timeout']
    result_path = '%s.tar' % md5hash
    if platform:
        container = Container()
        container.analyze(name=md5hash,mal_path=filepath,timeout=timeout,
                            result_path=result_path,platform=platform,code_path='container_code/')
    else:
        #logger.info("Can't handle type: %s" % task['type'])
        print "not support"


if __name__=='__main__':
    import doctest
    doctest.testmod()