#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1
# author: felicitychou

import os,stat
import subprocess
import shutil
import time
import sys,getopt
import logging

###
class Logger(object):
    
    def __init__(self, logname = "log.txt", loglevel = logging.DEBUG, loggername = "logger"):
        
        self.logger = logging.getLogger(loggername)
        self.logger.setLevel(loglevel)
        
        format = '%(asctime)s %(filename)s: %(levelname)s %(message)s'
        datefmt='%Y/%m/%d %H:%M:%S'
        formatter = logging.Formatter(format,datefmt)       
        
        fh = logging.FileHandler(logname)
        fh.setLevel(loglevel)
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

        ch = logging.StreamHandler()
        ch.setLevel(loglevel)
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

###

def download_mal(mal_url,download_path,logger,extension=''):
    import urllib2
    try:
        f = urllib2.urlopen(mal_url)
        if not os.path.exists(download_path):
            os.mkdir(download_path)
        # PE32 need exe extension
        mal_name = os.path.basename(mal_url)
        mal_path = os.path.join(download_path,mal_name) + extension
        with open(mal_path,"wb") as code:
            code.write(f.read())
        logger.info('Download %s to %s successfully.' % (mal_url,mal_path))
        return mal_path
    except urllib2.HTTPError, e:
        logger.exception('urllib2.HTTPError')
        sys.exit()
    except Exception,e:
        logger.exception('%s: %s' % (Exception,e))
        sys.exit()

###

def start_tcpdump(result_path,logger):
    try:
        pcap_path = os.path.join(result_path,'pcap') 
        child = subprocess.Popen(["tcpdump","-C","100","-i","eth0","-w",pcap_path,"-U"])
        if child.poll() is None:
            logger.info("Start tcpdump(pid=%s) successfully." % (child.pid))
            return child
        else:
            logger.error("Start tcpdump failed.")
            sys.exit()
    except Exception,e:
        logger.exception('%s: %s' % (Exception,e))
        sys.exit()

###

def start_wine(mal_path,result_path,logger):
    try:
        filepath, ext = os.path.splitext(mal_path)
        # add .exe 
        if not ext:
            mal_path = '%s.exe' % filepath
            os.renames(filepath, mal_path)

        wine_path = os.path.join(result_path,'wine.txt')
        with open(wine_path,'w') as f:
            child = subprocess.Popen(["wine",mal_path],stdout=f,stderr=f,env={'WINEDEBUG':'+relay'})
            logger.debug("WINEDEBUG:+relay wine %s" % (mal_path,))
        if child.poll() is None:
            logger.info("Start wine(pid=%s) successfully." % (child.pid))
            return child
        else:
            logger.error("Start wine failed.")
            sys.exit()
    except Exception,e:
        logger.exception('%s: %s' % (Exception,e))
        sys.exit()

###

def start_strace(mal_path,result_path,logger):
    try:
        os.chmod(mal_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH) # mode:744
        logger.debug('Chmod %s to %s successfully.' % (mal_path,'744'))
        strace_path = os.path.join(result_path,'strace.txt')
        child = subprocess.Popen(["strace","-ttt","-x","-y","-yy","-s","32","-o",strace_path,"-f",mal_path])
	logger.debug("strace -ttt -x -y -yy -s 32 -o %s -f %s" % (strace_path,mal_path))
        if child.poll() is None:
            logger.info("Start strace(pid=%s) successfully." % (child.pid))
            return child
        else:
            logger.error("Start strace failed.")
            sys.exit()
    except Exception,e:
        logger.exception('%s: %s' % (Exception,e))
        sys.exit()

###

def check(children,logger):
    check_result = True
    for childname,child in children.items():
        if child.poll() is None:
            logger.error("Stop %s(pid=%s) fail." % (childname,child.pid))
            check_result = check_result and False
        else:
            logger.info("Stop %s(pid=%s) successfully." % (childname,child.pid))
            check_result = check_result and True
    return check_result

###

def stop(children,timeout,logger):
    try:
	logger.debug(children)
        if children.has_key('wine'):
            progrunner = children.get("wine")
            logger.info("Progrunner wine.")
        elif children.has_key('strace'):
            progrunner = children.get("strace")
            logger.info("Progrunner strace.")
        else:
            pass
        
        tcpdump = children.get("tcpdump",None)
        # wait timeout
        wait = 0
        while (wait < timeout and progrunner.poll() is None):
            time.sleep(5)
            wait += 5
            logger.info("Wait %d" % wait)


        # timeout 
        if progrunner.poll() is None:
            progrunner.kill()
            progrunner.wait()

        if tcpdump.poll() is None:
            tcpdump.terminate()
            tcpdump.wait()

        #if check(childname="wine",child=progrunner,logger=logger) and check(childname="tcpdump",child=tcpdump,logger=logger):
        if check(children=children,logger=logger):
            logger.info("Analyze finished.")
        else:
            logger.error("Error.")

    except Exception,e:
        logger.exception('Exception')
        sys.exit()


###

def main(mal_url,mal_path,result_path,timeout,mode):

    # check result save path
    if not os.path.exists(result_path):
        os.mkdir(result_path)

    # init logger
    logger = Logger(logname = os.path.join(result_path,"log.txt")).logger

    # check mode
    if mode not in ['win','linux']:
        logger.error("Unknown mode %s." % (mode,))
        return 
    
    if mal_url:
        mal_path = download_mal(mal_url=mal_url,download_path=os.path.join('/tmp','sample'),logger=logger)
    
    if mal_path:
        new_mal_path = os.path.join("/home","sample")
        shutil.copyfile(mal_path, new_mal_path)
    mal_path = new_mal_path

    # check mal exists
    if not os.path.exists(mal_path):
        logger.error("Mal does not exist.")
        return

    # start analyze
    logger.info("Start Analyze Mal:%s Mode:%s" % (mal_path,mode))
    tcpdump = start_tcpdump(result_path=result_path,logger=logger)
    if mode == 'win':
        wine = start_wine(mal_path=mal_path,result_path=result_path,logger=logger)
        children = {"wine":wine,"tcpdump":tcpdump}
        stop(children=children,timeout=timeout,logger=logger)
    elif mode == 'linux':
        strace = start_strace(mal_path=mal_path,result_path=result_path,logger=logger)
        children = {"strace":strace,"tcpdump":tcpdump}
        stop(children=children,timeout=timeout,logger=logger)
    else:
        return

###

def usage():
    print readme
    return

readme = '''
usage:
        analyze.py -u mal_url
        analyze.py -f mal_path
        analyze.py -u mal_url -f mal_path == analyze.py -f mal_path
param:
        -u/--malurl  analyze malware url
        -f/--malpath analyze malware file
        -t/--timeout analyze time
        -m/--mode    analyze mode win/linux
        -h/--help    help
'''

if __name__ == '__main__':
    opts, args = getopt.getopt(sys.argv[1:], "hu:f:t:m:",["help","malurl","malpath","timeout","mode"])

    mal_url = None
    mal_path = None
    mode = None
    timeout = 60
    result_path = os.path.join('/tmp','result')

    for op, value in opts:
        if op == "-u" or op == "--malurl":
            mal_url = value
        elif op == "-f" or op == "--malpath":
            mal_path = value
        elif op == "-t" or op == "--timeout":
            timeout = int(value)
        elif op == '-m' or op == "--mode":
            mode = value
        elif op == "-h" or op == "--help":
            usage()
            sys.exit()
        else:
            usage()
            sys.exit()  

    if mal_url or mal_path:
        main(mal_url=mal_url,mal_path=mal_path,result_path=result_path,timeout=timeout,mode=mode)
    else:
        usage()
        sys.exit() 
