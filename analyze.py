#!/usr/bin/env Python
# -*- coding:utf-8 -*-

import os,stat
import subprocess
import time
import sys,getopt


def download_mal(mal_url,result_path):
    import urllib2
    try:
        f = urllib2.urlopen(mal_url)
        mal_name = os.path.basename(mal_url)
        mal_path = os.path.join(result_path,mal_name)
        with open(mal_path,"wb")as code:
            code.write(f.read())
        os.chmod(mal_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH) # mode:744
        return mal_path
    except urllib2.HTTPError, e:
        return None
    except Exception,e:
        return None

def start_tcpdump(result_path):
    try:
        pcap_path = os.path.join(result_path,'pacp') 
        print pcap_path
        child = subprocess.Popen(["tcpdump","-C","10","-i","eth0","-w",pcap_path,"-U"])
        if child.poll() is None:
            return child
        else:
            return None
    except Exception,e:
        return None

def start_strace(mal_path,result_path):
    try:
        strace_path = cap_path = os.path.join(result_path,'strace.txt')
        print strace_path
        child = subprocess.Popen(["strace","-o",strace_path,"-f",mal_path])
        if child.poll() is None:
            return child
        else:
            return None
    except Exception,e:
        return None    


def main(mal_url,result_path,timeout):
    # check result save path
    if not os.path.exists(result_path):
        os.mkdir(result_path)
    #create log
    log = open(os.path.join(result_path,"log.txt"),"wb")
    log.write("create result dir %s and log file %s \r\n" % (result_path, "log.txt"))
    print "create result dir %s and log file %s." % (result_path, "log.txt")
    #download mal
    mal_path = download_mal(mal_url=mal_url,result_path=result_path)
    if mal_path is not None:
        log.write("Download mal_url %s successfully \r\n" % (mal_url))
        print "Download mal_url %s successfully." % (mal_url)
        #start tcpdump
        tcpdump = start_tcpdump(result_path=result_path)
        if tcpdump is not None:
            log.write("Start tcpdump %s successfully \r\n" % (tcpdump.pid))
            print "Start tcpdump %s successfully." % (tcpdump.pid)
            #start strace
            strace = start_strace(mal_path=mal_path,result_path=result_path)
            if strace is not None:
                log.write("Start strace %s successfully \r\n" % (strace.pid))
                print "Start strace %s successfully." % (strace.pid)
                time.sleep(timeout)
                strace.kill()#terminate() don't work.
                tcpdump.terminate()
                #wait for subpross end
                strace.wait()
                tcpdump.wait()
                if strace.poll() is None or tcpdump.poll() is None:
                    log.write("Stop strace and tcpdump %s fail \r\n")
                    print "Stop strace and tcpdump fail."
                else:
                    log.write("Stop strace and tcpdump %s successfully \r\n")
                    print "Stop strace and tcpdump successfully "
                    log.write("Analyze finished.")
                    print "Analyze finished."
            else:
                log.write("Start strace fail \r\n")
                print "Start strace fail."
        else:
            log.write("Start tcpdump fail \r\n")
            print "Start tcpdump fail." 
    else:
        log.write("Download mal_url %s fail \r\n" % (mal_url))
        print "Download mal_url %s fail." % (mal_url)
    log.close()

def usage():
    print readme
    return


      
readme = '''
usage:
        analyze -u mal_url
param:
        -u to analyze malware url
        -h help
'''



if __name__ == '__main__':
    opts, args = getopt.getopt(sys.argv[1:], "hu:t:",["help","malurl","timeout"])

    mal_url = ''
    timeout = 300
    result_path = 'result'

    for op, value in opts:
        if op == "-u" or op == "--malurl":
            mal_url = value
        elif op == "-t" or op == "--timeout":
            timeout = int(value)
        elif op == "-h" or op == "--help":
            usage()
            sys.exit()
        else:
            usage()
            sys.exit()

    if len(mal_url) == 0:
        usage()
        sys.exit()

    main(mal_url=mal_url,result_path=result_path,timeout=timeout)
    