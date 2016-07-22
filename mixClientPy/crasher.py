# -*- coding: utf-8 -*-

from pydbg import *
from pydbg.defines import *
import utils
import re
import os
import urllib
import datetime
import time
import hashlib
import shutil

def deal_accessv(dbg):
    #if dbg.dbg.u.Exception.dwFirstChance:
    #    return DBG_EXCEPTION_NOT_HANDLED
    print "[fuzz] find crash !!"

    print "[fuzz] generate log file ..."
    crash_bin = utils.crash_binning.crash_binning()
    crash_bin.record_crash(dbg)
    name = hashlib.md5(str(datetime.datetime.now())).hexdigest()
    crashfile = dbg.cf.logspath + '//crash-'+name+'.txt'
    f = open(crashfile, 'w')
    f.write(crash_bin.crash_synopsis())
    f.close()

    print "[fuzz] retrieve html file ..."
    pocfile = dbg.cf.logspath + '//poc-' + name + '.html'
    pocurl = 'http://'+dbg.cf.host + ':' + dbg.cf.port + '/current.html'
    urllib.urlretrieve(pocurl, pocfile)

    print "[fuzz] terminate safari ..."
    dbg.terminate_process()
    return DBG_EXCEPTION_NOT_HANDLED


def time_out(dbg):
    if time.time()-dbg.start_time > 100.0:
        print "[fuzz] fuzz timeout !"
        print "[fuzz] detach dbg ..."
        dbg.detach()
        dbg.start_time = time.time()

        print "[fuzz] kill processes ..."
        os.system('killall Safari')
        os.system('killall Preview')

        print "[fuzz] delete download files ..."
        shutil.rmtree('/Users/test/Downloads/')
        os.mkdir('/Users/test/Downloads')

class crasher():
    """docstring for crasher"""
    def __init__(self, cf):
        self.cf = cf
        self.cases = 1

    def hook(self, pid):
        #loadpid = dbg.pid

        print "[fuzz] init dbg ..."
        dbg = pydbg()
        dbg.cf = self.cf

        print "[fuzz] first process PID = %d"%pid
        pattern=r'\s*([0-9]*)\s*'
        count = 0
        while count<=1:
            pbuf = os.popen("ps auxc | grep WebContent | awk '{print $2}'")
            pids = re.findall(pattern,pbuf.read())
            count = len(pids)
            print "[fuzz] find "+str(count-1)+" Safari pids:" + str(pids)
        for pid in pids:
            if pid != 0:
                try:
                    print "[fuzz] attach dbg to %s ..."%(pid)
                    dbg.attach(int(pid))
                    dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, deal_accessv)
                    dbg.set_callback(USER_CALLBACK_DEBUG_EVENT,time_out)
                    dbg.start_time = time.time()
                    return dbg
                except Exception, e:
                    print '[fuzz] attach dbg to %s failed!'%(pid)
                    print e
                    return None


