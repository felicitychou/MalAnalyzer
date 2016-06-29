import docker
import subprocess
import time


class dockermanager(object):

    def __init__(self):
        self.client = docker.Client(base_url ="unix://var/run/docker.sock")
        self.total = 0
        self.containers = []

    def list(self):
        return self.client.containers()

    
    def create_container(self,malurl):
        #container = self.client.create_container(image = 'analyzer:latest',command = 'python start.py malurl',mem_limit = '256m')
        container  = self.client.create_container(image = 'ubuntu:14.04_minimal' , command = ['/bin/echo','Hello world'])
        self.containers.append(container)
        self.total += 1
        return container.get('Id')

    def start_container(self,malurl=None):
        container = self.create_container(malurl=malurl)
        self.client.logs(container=container, stdout=True, stderr=True, timestamps=True)
        if self.client.start(container = container) == None:
            return container,True
        else:
            return container,False

    def stop_container(self,container):
        return self.client.stop(container = container,timeout = 10)

    def containers(self):
        return self.client.containers()



if __name__ == '__main__':
    Manager = dockermanager()
    container,result= Manager.start_container()
    print "start"
    print Manager.containers
    print Manager.client.containers()
    time.sleep(10)
    Manager.stop_container(container)
    print "stop"
    print Manager.containers
    print Manager.client.containers()

