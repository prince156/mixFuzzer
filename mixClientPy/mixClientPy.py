# -*- coding: utf-8 -*-
import conf
import os
import utils
import time
import datetime
import urllib
import hashlib
import shutil
import re
from pydbg import *
from pydbg.defines import *

class moniter():
    """moniter"""
    def __init__(self):
        self.dbg = pydbg()
        self.dbg.start_time = time.time()
        self.cf = conf.conf()
        #self.crasher = fuzzutil.crasher(self.cf)
        self.InitPage = 'http://'+self.cf.host+':'+self.cf.port+'/'
        print '[maim] Server: ' + self.cf.host+':'+self.cf.port
        print '[main] Taregt: ' + self.cf.target
        print '[main] Image: ' + self.cf.image
        os.system('mkdir logs 2> null')
        print '[main] LogPath: ./logs/'

    def tellme(self, message):
        t = str(datetime.datetime.now())
        t = t[:t.rfind('.')]
        print '['+t+'] ' + message

    def deal_accessv(self,dbg):
        print "[fuzz] find crash !!"

        name = hashlib.md5(str(datetime.datetime.now())).hexdigest()

        print "[fuzz] retrieve html file ..."
        pocfile = self.cf.logspath + '//poc-' + name + '.html'
        pocurl = 'http://'+self.cf.host + ':' + self.cf.port + '/current.html'
        urllib.urlretrieve(pocurl, pocfile)

        #print "[fuzz] get crash info ..."
        #crash_bin = utils.crash_binning.crash_binning()
        #crash_bin.record_crash(dbg)

        #print "[fuzz] write to log file ..."
        #crashfile = self.cf.logspath + '//crash-'+name+'.txt'
        #f = open(crashfile, 'w')
        #f.write(crash_bin.crash_synopsis())
        #f.close()

        print "[main] detach dbg ..."
        os.system('killall Safari 2> null')
        self.dbg.detach()
        return DBG_EXCEPTION_NOT_HANDLED

    def time_out(self,dbg):
        if time.time()-dbg.start_time > 60.0:
            print "[main] fuzz timeout !"
            print "[main] detach dbg ..."
            os.system('killall Safari 2> null')
            dbg.detach()
            dbg.start_time = time.time()

    def run(self):
        pattern=r'\s*([0-9]*)\s*'
        while 1:
            print ' '
            t = str(datetime.datetime.now())
            t = t[:t.rfind('.')]
            print '['+t+']'

            print "[main] kill processes ..."
            os.system('killall Safari 2> null')
            os.system('killall Preview 2> null')
            os.system('killall ReportCrash 2> null')

            print "[main] delete download files ..."
            shutil.rmtree(os.path.expanduser("~/Downloads"))
            os.mkdir(os.path.expanduser("~/Downloads"))

            print "[main] start safari ..."
            self.cmdline = 'open -a '+self.cf.targetpath+' '+self.InitPage
            os.system(self.cmdline)
            time.sleep(1)
            pbuf = os.popen("echo $(ps auxc | grep 'WebContent' | awk '{print $2}')")
            pids = re.findall(pattern,pbuf.read())
            for pid in pids:
                if pid != '':
                    print '[main] attach dbg to '+ str(pid)
                    self.dbg.attach(int(pid))
                    time.sleep(1)

            print '[main] fuzz ... '+ str(pid)
            self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.deal_accessv)
            self.dbg.set_callback(USER_CALLBACK_DEBUG_EVENT, self.time_out)
            self.dbg.run()

            self.dbg = pydbg()
            self.dbg.start_time = time.time()


if __name__=='__main__':
    print '************** wellcome to mixClientPy v1.0 **************'
    moniter().run()