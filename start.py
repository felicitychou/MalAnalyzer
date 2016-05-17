

import os
import subprocess
import time


def download_mal(mal_url):
    mal_path = '/log/' + os.path.basename(mal_url)
    import urllib2
    try:
        f = urllib2.urlopen(mal_url)
        with open(mal_path,"wb")as code:
            code.write(f.read())
        return True,mal_path
    except urllib2.HTTPError, e:
        return False
    except Exception,e:
        return False

def start_tcpdump():
    child = subprocess.Popen(["tcpdump","-C","10","-i","esn33","-w","/log/pcap.pcap","-U"])
    if child.poll() == None:
        return True,child

def start_strace(malpath):
    child = subprocess.Popen(["strace","-o","/log/strace.txt","-f",malpath])
    if child.poll() == None:
        return True,child


def main(mal_path):
    #result,mal_path = download_mal(mal_url=mal_url)
    result = True
    if result:
        print "Download successfully"
        result,tcpdump = start_tcpdump()
        if result:
            print "Start Tcpdump"
            result,strace = start_strace(mal_path=mal_path)
            if result:
                print "Start Strace"
    time.sleep(300)
    strace.terminate()
    tcpdump.terminate()
    print "Analyze finished.Log in /log"



if __name__ == '__main__':
    main("/log/")