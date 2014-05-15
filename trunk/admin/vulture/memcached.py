#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys,os

# set django environment for standalone daemon
try:
    sys.path.append("/opt/vulture")
    sys.path.append("/opt/vulture/admin")
    sys.path.append("/opt/vulture/lib/Python/modules")
    os.environ["DJANGO_SETTINGS_MODULE"] = "admin.settings"
    from vulture.models import Intf, App, Conf
except:
    sys.path.append("/var/www/vulture")
    sys.path.append("/var/www/vulture/admin")
    sys.path.append("/opt/vulture/lib/Python/modules")
    os.environ["DJANGO_SETTINGS_MODULE"] = "admin.settings"
    from vulture.models import Intf, App, Conf

# import sqlite driver
try:
    import sqlite3
except:
    from pysqlite2 import dbapi2 as sqlite3

try:
    import cPickle as pickle
except:
    import pickle

import logging
import time
import signal
import memcache

from storable import thaw
from django.conf import settings
from django.db import connection

class StorablePickler:
    def __init__(self,fd, protocol=None):
        self.fd = fd
    def dump(self, obj):
        raise NotImplementError()
    def dumps(self, obj):
        raise NotImplementError()
    def load(self):
        return thaw(self.fd.read())
    def loads(self, obj):
        return thaw(obj)

class NopPickler:
    def __init__(self,fd, protocol=None):
        self.fd = fd
    def dump(self, obj):
        return obj
    def dumps(self, obj):
        self.fd.write(obj)
    def load(self):
        return self.fd.read()
    def loads(self, obj):
        return obj

class KeyList:
    def __init__(self, keys):
        self.keys = keys

    def get_keys(self):
        return self.keys

# Class MC, override some functions of python memcache

class MC:
    LOCKNAME = "vulture_lock"
    MAX_VALUE_LEN = 1000000
    def __init__(self,perl_storable=False):
        self.mc_servers = [x.strip() for x in Conf.objects.get(
            var="memcached").value.split(",")]
        if perl_storable:
            self.client = memcache.Client(self.mc_servers,
                    pickler=StorablePickler, unpickler=StorablePickler)
        else:
            self.client = memcache.Client(self.mc_servers,
                    pickler=NopPickler, unpickler=NopPickler)

    def split_put(self, key, value, func):
        """
        split_put pickle the value, and return a list of objects to add/set, 
        of length < MAX_VALUE_LEN
        """
        pickled = pickle.dumps(value)
        if len(pickled) <= MC.MAX_VALUE_LEN:
            return func(key, pickled)
        else:
            keys = []
            i=0
            while len(pickled):
                sval = pickled[:MC.MAX_VALUE_LEN]
                pickled = pickled[MC.MAX_VALUE_LEN:]
                k = "%s__sub%s"%(key,i)
                if not func(k,sval):
                    return False
                keys += [k]
                i += 1
            return func(key, pickle.dumps(KeyList(keys)))

    def unsplit_get(self,key,func):
        """
        get a value from the memcache, eventually unsplit it if needed
        """
        try:
            val = pickle.loads(func(key))
        except:
            return None
        try:
            keys = val.get_keys()
        except:
            return val
        try:
            val = ''
            for k in keys:
                val += func(k)
            return pickle.loads(val)
        except:
            return None

    def get(self, key):
        try:
            return self.unsplit_get( str(key), self.client.get)
        except:
            pass

    def set(self,key,value):
        try:
            return self.split_put(str(key),value,self.client.set)
        except:
            pass

    def add(self,key,value):
        try:
            return self.split_put(str(key),value,self.client.add)
        except:
            pass

    def delete(self,key):
        try:
            k1 = str(key)
            keys = [k1]
            v = self.client.get(k1)
            try:
                val = pickle.loads(v)
                keys += val.get_keys()
            except:
                pass
            for k in keys:
                self.client.delete(k)
        except:
            pass

    def lock(self):
        while not self.add(self.LOCKNAME,1):
            time.sleep(1)

    def unlock(self):
        self.delete(self.LOCKNAME)

# Class SynchroDaemon
# CheckConf of memecache & local conf
# push or pop conf

class SynchroDaemon:
    LOCKFILE = "%s/vulture-daemon.lock"%settings.CONF_PATH
    VERSIONKEY = "vulture_version"
    KEYSTORE = "vulture_instances"
    INTERVAL = 60
    def __init__(self):
        self.db = sqlite3.connect(settings.DATABASES['default']['NAME'])
        self.db.row_factory=sqlite3.Row
        self.mc = MC()

    def getConf(self, key):    
        val=Conf.objects.get(var=key)
        return val and val.value or None

    # check if cluster is activated in conf vulture.
    def cluster_activated(self):
        try:
            useMe = self.getConf("use_cluster")
            if useMe == "1" :
                return True
        except:
            return False
 
    # check if daemon already Started
    def started(self):
        try:
            f = open(self.LOCKFILE,"rb")
            pid = int(f.read())
            f.close()
            os.kill(pid,0)
            return pid
        except:
            return False

    # Start Daemon of memcache
    # Refresh Daemon every 30s.
    def start(self):
        if self.started():
            logger.info("[-] Already started")
            self.stop()
            if self.started():
                logger.info("[-] Unable to stop daemon")
                return False
        if not self.cluster_activated():
            logger.info("[-] Cluster not activated in conf")
            return True
        logger.info("[+] Cluster sync daemon starting .. ")
        # creating lock file
        f = open(self.LOCKFILE,"wb")
        f.write(str(os.getpid()))
        f.close()
        # set interrupt handler
        signal.signal(signal.SIGINT, self.stop)
        try:
            os.mkdir("%s/security-rules"%settings.CONF_PATH)
        except:
            pass
        while True:
            # check if the cluster was deactivated in conf
            if not self.cluster_activated():
                self.stop()
            # check if conf is up to date, eventually update
            self.refresh()
            # wait x seconds
            time.sleep(self.INTERVAL)

    # Stop Daemon
    def stop(self,sig=2, v=0):
        name = self.getConf("name")
        pid = self.started()
        if not pid:
        # daemon is already stopped
            logger.info("[-] Daemon not started...")
            return True
        if pid != os.getpid():
        # stopping external process
            logger.info("[+] Stopping external daemon [%s]"%pid)
            os.kill(pid,2)
            return True
        # stopping this process
        logger.info("[+] Stopping daemon [%s]"%pid)
        # remove this cluster from memcache
        old = self.mc.get(self.KEYSTORE) or []
        if old:
            self.mc.set(self.KEYSTORE,[f for f in old if f!=name])
        self.mc.delete("%s:infos"%name)
        # remove lock file
        os.remove(self.LOCKFILE)
        sys.exit(0)
   
    # Check_Config of memcache
    def refresh(self):
        self.mc.lock()
        try:
            self.check_config()
        except:
            self.mc.unlock()
            raise
        self.mc.unlock()
    
    # check if local version is sup, inf or equal to memcache Version.
    # Pop or Push conf.

    def check_config(self):
        # get database conf vars
        myversion = int(self.getConf("version_conf"))
        name = self.getConf('name')
        # get memcache conf version
        mcversion = self.mc.get(self.VERSIONKEY)
        mcversion = mcversion == None and -1 or int(mcversion)
        if myversion == mcversion:
            logger.info("[-] Conf is up to date, nothing to do")
            pass
        elif myversion > mcversion:
        # push my conf in memcache 
            logger.info("[+] Pushing my conf into memcache...")
            self.push_conf()
            self.mc.set(self.VERSIONKEY, myversion)
            logger.info("[+] Push done")
        else:
        # new config available, update
            logger.info("[+] Updating conf...")
            myversion = mcversion
            # update my version number in database
            Conf.objects.filter(var="version_conf").update(value=str(myversion)) 
            self.pop_conf()
            logger.info("[+] Update done")
        # put this server name in memcache if not already there
        all_srv = self.mc.get(self.KEYSTORE) or []
        if not name in all_srv:
            self.mc.set(self.KEYSTORE,all_srv+[name])
        # put infos of this server in memcache for monitoring purpose
        infos = {"version":myversion,"last":time.time()}
        self.mc.set("%s:infos"%name,infos)
    
    # monitoring func, return list of servers and infos
    def list_servers(self):
        ret = []
        all_srv = self.mc.get(self.KEYSTORE)
        if not all_srv:
            return ret
        for name in all_srv:
            info = self.mc.get("%s:infos"%name)
            # if we failed to get infos, return err value
            if not info:
                info = {"name":name,"version":-1,"last":0,"up":False}
            else:
            # else return memcache value with this server's name
                info.update({"name":name})
                # check if server is up, give it 3 seconds to update its conf
                if (info['last'] + self.INTERVAL+3) >= time.time() :
                    info['up'] = True
                else:
                    info['up'] = False
            ret += [info]
        return ret
        
    def reload_intfs(self):
        intfs= Intf.objects.all()
        for intf in intfs :
            if intf.need_restart():
                fail = intf.maybeWrite()
                if not fail:
                    # conf is valid : reload
                    intf.k('graceful')
                    apps = App.objects.filter(intf=intf).all()
                    for app in apps:
                        self.mc.delete('%s:app'%app.name)

    def reset_mc(self):
        # delete sql conf
        for t in self.list_tables():
            self.mc.delete("conf:%s"%t)
        # delete servers infos
        srv = self.mc.get(self.KEYSTORE) or []
        for s in srv:
            self.mc.delete("%s:infos"%s)
        self.mc.delete(self.KEYSTORE)
        # delete conf version
        self.mc.delete(self.VERSIONKEY)
        # eventually delete lock
        self.mc.unlock()

    # push conf of this server in memcache
    def push_conf(self):
        self.push_sql_conf()
 
    def push_sql_conf(self):
        for table in self.list_tables():
            self.mc.set('conf:%s'%table,self.get_SQL_table(table))

    def pop_conf(self):
        try:
            self.pop_sql_conf()
        except sqlite3.IntegrityError, e:
            if (len(e.args)==1 and 
                e.args[0]=='columns app_id, intf_id are not unique'):
                logger.info("Warning: integrity error, cleaning..")
                self.db.execute("DELETE from app_intf");
                return self.pop_conf()
            raise
        # eventually reload interfaces with changes
        if self.getConf("auto_restart")=='1':
            self.reload_intfs()

    # pop conf if local conf is lower than version memcache
    # update table in db with some conf of Versio memcache 
    def pop_sql_conf(self):
        for table in self.list_tables():
            logger.info("[?] checking  %s ...",table)
            db_conf = self.get_SQL_table(table)
            mc_conf = self.mc.get("conf:%s"%table)
            db_ids,mc_ids = {},{}
            if db_conf:
                for row in db_conf:
                    db_ids[row['id']]=row
            if mc_conf:
                for row in mc_conf:
                    mc_ids[row['id']]=row
            # Eventually delete some lines
            dels=[str(f) for f in db_ids if not f in mc_ids]
            if dels:
                q = "DELETE FROM `%s` WHERE id IN (%s)"%(
                    table,",".join(dels))
                logger.info("%s" % q)
                self.db.execute(q)
            # for all keys in memcache conf, 
            # check if it's present in the db
            for mc_k in mc_ids:
                mc_e=mc_ids[mc_k]
                # line present, eventually update
                if mc_k in db_ids:
                
                    db_e = db_ids[mc_k]
                    # get keys to update
                    keys,vals=[],[]
                    for k in mc_e:  
                        if mc_e[k] != db_e[k]:
                            keys += [k]
                            vals += [mc_e[k]]
                    if vals:
                        q = "UPDATE `%s` SET %s WHERE id=?"%(table,
                            ",".join(["`%s`=?"%k for k in keys])
                            )
                        logger.info("UPDATE TABLE %s" % table)
                        self.db.execute(q,vals+[mc_k])
                elif mc_e: 
                    vals = [mc_e[k] for k in mc_e]
                    q = "INSERT INTO `%s` (%s) VALUES (%s)"%(table,
                        ",".join(["`%s`"%k for k in mc_e]),
                        ",".join(['?']*len(vals))
                        )
                    logger.info("INSERT INTO %s" % table)
                    self.db.execute(q,vals)
        self.db.commit()
        self.check_config()

    # convert sqlite to dictionnary
    def convert_sqliteRow_to_dict(self,rows):
        #for easy work, we convert sqliteRow object (return by the query)
        #to table of dictionnary
        tab=[]
        for row in rows:
            dico={}
            for key in row.keys():
                dico[key]=row[key]
            tab += [dico]
        return tab

    #get data from database
    def get_SQL_table(self,table):
        sth = self.db.execute("SELECT * from `%s`"%table)
        rows = sth.fetchall();
        di = self.convert_sqliteRow_to_dict(rows)
        return di
    
    #list all table in db
    def list_tables(self):
        return [table for table in connection.introspection.table_names()
            # avoid server specific tables
            if not ( table in ('conf','vintf','event_logger') 
            # avoid django tables
                    or table.startswith("django_")) ]

# add log from Daemon to */log/Vulture-memcachedDaemon.log
logger = logging.getLogger("DaemonLog")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s %(message)s",
        "[%a %b %d %H:%M:%S %Y] [info]")

if (os.path.exists("/var/www/vulture/log/") == True):
    location = "/var/www/vulture/log/Vulture-memcachedDaemon.log"
else:
    location = "/opt/vulture/log/Vulture-memcachedDaemon.log"
handler = logging.FileHandler(location)
handler.setFormatter(formatter)

logger.addHandler(handler)
handler.close()
