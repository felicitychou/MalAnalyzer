#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Malcode Analysis System
# version = 0.1
# author: felicitychou

import os, stat
import subprocess
import shutil
import time
import sys
import getopt
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

class Analyzer(object):

    def __init__(self, mal_url, mal_path, result_path, timeout, mode, tracemode):

        # check result save path
        self.result_path = result_path
        if not os.path.exists(self.result_path):
            os.mkdir(self.result_path)
        self.logger = Logger(logname = os.path.join(self.result_path, "log.txt")).logger
        # analyze config
        self.mal_path = mal_path
        self.mal_url = mal_url
        self.timeout = timeout
        self.mode = mode
        self.tracemode = tracemode
        # start analyze
        self.start()


    def download_mal(self, download_path):
        import urllib2
        try:
             # check download exists or not
            if not os.path.exists(download_path):
                os.mkdir(download_path)

            self.mal_path = os.path.join(download_path, 'sample')
            f = urllib2.urlopen(self.mal_url)
            with open(mal_path, "wb") as code:
                code.write(f.read())
            self.logger.info('Download %s to %s successfully.' % (self.mal_url, self.mal_path))
        except urllib2.HTTPError, e:
            self.logger.exception('urllib2.HTTPError')
            sys.exit()
        except Exception, e:
            self.logger.exception('%s: %s' % (Exception, e))
            sys.exit()

    ###

    def start_tcpdump(self):
        try:
            pcap_path = os.path.join(self.result_path, 'pcap')
            child = subprocess.Popen(["tcpdump", "-C", "100", "-i", "eth0", "-w", pcap_path, "-U"])
            if child.poll() is None:
                self.logger.info("Start tcpdump(pid=%s) successfully." % (child.pid))
                self.tcpdump = child
            else:
                self.logger.error("Start tcpdump failed.")
                sys.exit()
        except Exception, e:
            self.logger.exception('%s: %s' % (Exception, e))
            sys.exit()

    ###
    def start_wine(self):
        try:
            filepath, ext = os.path.splitext(self.mal_path)
            # add .exe ext
            self.mal_path = filepath if ext else '%s.exe' % filepath
            os.renames(filepath, self.mal_path)

            wine_path = os.path.join(self.result_path, 'wine.txt')
            with open(wine_path, 'w') as f:
                child = subprocess.Popen(["wine", self.mal_path], stdout = f, stderr = f, env = {'WINEDEBUG': '+relay'})
                self.logger.debug("WINEDEBUG:+relay wine %s" % (self.mal_path,))
            if child.poll() is None:
                self.logger.info("Start wine(pid=%s) successfully." % (child.pid))
                self.progrunner = 'wine'
                self.wine = child
            else:
                self.logger.error("Start wine failed.")
                sys.exit()
        except Exception, e:
            self.logger.exception('%s: %s' % (Exception, e))
            sys.exit()

    ###

    def start_trace(self):
        try:
            os.chmod(self.mal_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH)  # mode:744
            self.logger.debug('Chmod %s to %s successfully.' % (self.mal_path, '744'))

            trace_path = os.path.join(self.result_path, '%s.txt' % self.tracemode)

            ltrace_cmd = ['ltrace', '-f', '-ttt', '-S', '-o', trace_path, self.mal_path]
            strace_cmd = ["strace", "-ttt", "-x", "-y", "-yy", "-s", "32", "-o", trace_path, "-f", self.mal_path]

            trace_cmd = ltrace_cmd if self.tracemode == 'ltrace' else strace_cmd
            child = subprocess.Popen(trace_cmd)
            self.logger.debug(trace_cmd)
            if child.poll() is None:
                self.logger.info("Start %s(pid=%s) successfully." % (self.tracemode, child.pid))
                self.progrunner = self.tracemode
                setattr(self,self.tracemode,child)
            else:
                self.logger.error("Start %s failed." % self.tracemode)
                sys.exit()
        except Exception, e:
            self.logger.exception('%s: %s' % (Exception, e))
            sys.exit()

    ###

    def check(self):
        check_result = True
        for progname in (self.progrunner,"tcpdump"):
            child = getattr(self,progname)
            if child.poll() is None:
                self.logger.error("Stop %s(pid=%s) fail." % (progname, child.pid))
                check_result = check_result and False
            else:
                self.logger.info("Stop %s(pid=%s) successfully." % (progname, child.pid))
                check_result = check_result and True
        return check_result

    ###

    def stop(self):
        try:

            self.logger.info("Progrunner %s." % (self.progrunner,))
            progrunner = getattr(self,self.progrunner)
            self.logger.debug("Get Progrunner %s." % (progrunner,))

            wait = 0
            while (wait < self.timeout and progrunner.poll() is None):
                time.sleep(5)
                wait += 5
                self.logger.info("Wait %d" % wait)

            # timeout
            if progrunner.poll() is None:
                progrunner.kill()
                progrunner.wait()

            if self.tcpdump.poll() is None:
                self.tcpdump.terminate()
                self.tcpdump.wait()

            if self.check():
                self.logger.info("Analyze finished.")
            else:
                self.logger.error("Error.")

        except Exception, e:
            self.logger.exception('%s: %s' % (Exception, e))
            sys.exit()

    ###

    def start(self):

        # check mode
        if self.mode not in ['win', 'linux']:
            self.logger.error("Unknown mode %s." % (self.mode,))
            return

        if self.mal_url:
            self.download_mal(download_path = '/tmp')

        if self.mal_path:
            new_mal_path = os.path.join("/home", "sample")
            shutil.copyfile(self.mal_path, new_mal_path)
        self.mal_path = new_mal_path

        # check mal exists
        if not os.path.exists(self.mal_path):
            self.logger.error("Mal does not exist.")
            return

        # start analyze
        self.logger.info("Start Analyze Mal:%s Mode:%s" % (self.mal_path, self.mode))

        # start tcpdump
        self.start_tcpdump()

        if self.mode == 'win':
            self.start_wine()
            self.stop()
        elif self.mode == 'linux':
            self.start_trace()
            self.stop()
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
        --trace      analyze  strace/ltrace
        -h/--help    help
'''

if __name__ == '__main__':
    opts, args = getopt.getopt(sys.argv[1:], "hu:f:t:m:",["help","malurl=","malpath=","timeout=","mode=","tracemode="])

    mal_url = None
    mal_path = None
    mode = None
    timeout = 60
    result_path = os.path.join('/tmp','result')

    for op, value in opts:
        if op in ("-u","--malurl"):
            mal_url = value
        elif op in ("-f","--malpath"):
            mal_path = value
        elif op in ("-t","--timeout"):
            timeout = int(value)
        elif op in ('-m',"--mode"):
            mode = value
        elif op in ('--tracemode'):
            tracemode = value
        elif op in ("-h","--help"):
            usage()
            sys.exit()
        else:
            usage()
            sys.exit()  

    if mal_url or mal_path:
        Analyzer(mal_url=mal_url,mal_path=mal_path,result_path=result_path,timeout=timeout,mode=mode,tracemode=tracemode)

    else:
        usage()
        sys.exit() 
