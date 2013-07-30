#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys,os
# set django environment for standalone daemon
try:
    sys.path.append("/opt/vulture")
    sys.path.append("/opt/vulture/admin")
    os.environ["DJANGO_SETTINGS_MODULE"] = "admin.settings"
    from vulture.models import Intf, App, Conf
except:
    sys.path.append("/var/www/vulture")
    sys.path.append("/var/www/vulture/admin")
    os.environ["DJANGO_SETTINGS_MODULE"] = "admin.settings"
    from vulture.models import Intf, App, Conf
from django.conf import settings
from django.db import connection
# import sqlite driver
try:
    import sqlite3
except:
    from pysqlite2 import dbapi2 as sqlite3
import time
import signal
import memcache
from storable import thaw

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

class MC:
    LOCKNAME = "vulture_lock"
    def __init__(self,perl_storable=False):
        self.mc_servers = [x.strip() for x in Conf.objects.get(var="memcached").value.split(",")]
        if perl_storable:
            self.client = memcache.Client(self.mc_servers,
                    pickler=StorablePickler, unpickler=StorablePickler)
        else:
            self.client = memcache.Client(self.mc_servers)
        
    def get(self, key):
        try:
            return self.client.get(str(key))
        except:
            pass

    def set(self,key,value):
        return self.client.set(str(key),value)

    def add(self,key,value):
        return self.client.add(str(key),value)

    def append(self,key,value):
        return self.client.append(str(key),value)

    def prepend(self,key,value):
        return self.client.prepend(str(key),value)

    def delete(self,key):
        return self.client.delete(str(key))
    
    def lock(self):
        while not self.add(self.LOCKNAME,1):
            time.sleep(1)

    def unlock(self):
        self.delete(self.LOCKNAME)

class SynchroDaemon:
    LOCKFILE = "%s/vulture-daemon.lock"%settings.CONF_PATH
    VERSIONKEY = "vulture_version"
    KEYSTORE = "vulture_instances"
    MSCONFKEY = "conf:ms_files"
    INTERVAL = 30
    def __init__(self):
        self.db = sqlite3.connect(settings.DATABASES['default']['NAME'])
        self.db.row_factory=sqlite3.Row
        self.mc = MC()

    def getConf(self, key):    
        val=Conf.objects.get(var=key)
        return val and val.value or None

    def cluster_activated(self):
        try:
            useMe = self.getConf("use_cluster")
            if useMe == "1" :
                return True
        except:
            return False
 
    def started(self):
        try:
            f = open(self.LOCKFILE,"rb")
            pid = int(f.read())
            f.close()
            os.kill(pid,0)
            return pid
        except:
            return False

    def start(self):
        if self.started():
            print ("[-] %s: Already started"%time.ctime())
            self.stop()
            if self.started():
                print ("[-] %s: Unable to stop daemon"%time.ctime())
                return False
        if not self.cluster_activated():
            print ("[-] %s: Cluster not activated in conf"%time.ctime())
            return True
        print ("[+] %s: Cluster sync daemon starting .. "%time.ctime())
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

    def stop(self,sig=2, v=0):
        name = self.getConf("name")
        pid = self.started()
        if not pid:
        # daemon is already stopped
            print ("[-] %s: Daemon not started..."%time.ctime())
            return True
        if pid != os.getpid():
        # stopping external process
            print ("[+] %s: Stopping external daemon [%s]"%(time.ctime(),pid))
            os.kill(pid,2)
            return True
        # stopping this process
        print ("[+] %s: Stopping daemon [%s]"%(time.ctime(),pid))
        # remove this cluster from memcache
        old = self.mc.get(self.KEYSTORE) or []
        if old:
            self.mc.set(self.KEYSTORE,[f for f in old if f!=name])
        self.mc.delete("%s:infos"%name)
        # remove lock file
        os.remove(self.LOCKFILE)
        sys.exit(0)
    
    def refresh(self):
        self.mc.lock()
        try:
            self.check_config()
        except:
            self.mc.unlock()
            raise
        self.mc.unlock()
    
    def check_config(self):
        # get database conf vars
        myversion = int(self.getConf("version_conf"))
        name = self.getConf('name')
        # get memcache conf version
        mcversion = self.mc.get(self.VERSIONKEY)
        mcversion = mcversion == None and -1 or int(mcversion)
        if myversion == mcversion:
            pass
        elif myversion > mcversion:
        # push my conf in memcache 
            print ("[+] %s: Pushing my conf into memcache..."%time.ctime())
            self.push_conf()
            self.mc.set(self.VERSIONKEY, myversion)
            print ("[+] %s: Push done"%time.ctime())
        else:
        # new config available, update
            print ("[+] %s: Updating conf..."%time.ctime())
            self.pop_conf()
            myversion = mcversion
            # update my version number in database
            Conf.objects.filter(var="version_conf").update(value=str(myversion))
            print ("[+] %s: Update done"%time.ctime())
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
            if intf.need_restart:
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
        # delete ms conf
        self.mc.delete(self.MSCONFKEY)
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
        self.push_ms_conf()
       
    def push_ms_conf(self):
        sec_dir = "%s/security-rules"%(settings.CONF_PATH)
        ms_files = []
        for type_ in ('activated','CUSTOM'):
            dir_type = "%s/%s"%(sec_dir,type_)
            if not os.path.exists(dir_type):
                continue
            for dir_app in os.listdir(dir_type):
                subdir = "%s/%s"%(type_,dir_app)
                for file_ in os.listdir("%s/%s"%(sec_dir,subdir)):
                    f_path = "%s/%s"%(subdir,file_)
                    f = open("%s/%s"%(sec_dir,f_path),'rb')
                    fcont = f.read()
                    f.close()
                    ms_files.append(f_path)
                    self.mc.set("%s:%s"%(self.MSCONFKEY,f_path),fcont)
        self.mc.set(self.MSCONFKEY,ms_files)
 
    def push_sql_conf(self):
        for table in self.list_tables():
            self.mc.set('conf:%s'%table,self.get_SQL_table(table))

    def pop_conf(self):
        try:
            self.pop_sql_conf()
        except sqlite3.IntegrityError, e:
            if (len(e.args)==1 and 
                e.args[0]=='columns app_id, intf_id are not unique'):
                print ("Warning: integrity error, cleaning..")
                self.db.execute("DELETE from app_intf");
                return self.pop_conf()
            raise
        self.pop_ms_conf()
        # eventually reload interfaces with changes
        if self.getConf("auto_restart")=='1':
            self.reload_intfs()

    def pop_ms_conf(self):
        sec_dir = os.path.realpath(
                "%s/security-rules"%(settings.CONF_PATH))
        # remove old conf 
        for type_ in ('activated','CUSTOM'):
            sec_dir1 = "%s/%s"%(sec_dir,type_)
            if not os.path.exists(sec_dir1):
                continue
            for app in os.listdir(sec_dir1):
                sec_dir2 = "%s/%s"%(sec_dir1,app)
                for file_ in os.listdir(sec_dir2):
                    os.remove("%s/%s"%(sec_dir2,file_))
                os.rmdir(sec_dir2)
            os.rmdir(sec_dir1)
        # get files from memcache
        list_files = self.mc.get(self.MSCONFKEY)
	
        if list_files:
            for relpath in list_files:
                # check if file is in right folder
                if not os.path.realpath("%s/%s"%(sec_dir,relpath)
                        ).startswith(sec_dir):
                    continue
                print ("[?] %s: pop ms file : %s"%(time.ctime(),relpath))
                dirs = relpath.split("/")
                filename = dirs[len(dirs)-1]
                dirs = dirs[:len(dirs)-1]
                d = sec_dir
                # eventually create dir
                for di in dirs:
                    d += "/%s"%di
                    if not os.path.exists(d):
                        os.mkdir(d)
                # write file in its right place
                f = open("%s/%s"%(sec_dir,relpath),"wb")
                file=self.mc.get("%s:%s"%(self.MSCONFKEY,relpath))
                f.write(file)
                f.close()

    def pop_sql_conf(self):
        for table in self.list_tables():
#todo therse
            print("[?] %s: checking  %s ..."%(time.ctime(),table))
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
                print("%s: %s"%(time.ctime(),q))
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
                        if mc_e[k]!=db_e[k]:
                            keys +=[k]
                            vals+=[mc_e[k]]
                    if vals:
                        q = "UPDATE `%s` SET %s WHERE id=?"%(table,
                            ",".join(["`%s`=?"%k for k in keys])
                            )
                        print("%s: UPDATE TABLE %s"%(time.ctime(),table))
                        self.db.execute(q,vals+[mc_k])
                elif mc_e: 
                    vals = [mc_e[k] for k in mc_e]
                    q = "INSERT INTO `%s` (%s) VALUES (%s)"%(table,
                        ",".join(["`%s`"%k for k in mc_e]),
                        ",".join(['?']*len(vals))
                        )
                    print("%s: INSERT INTO %s"%(time.ctime(),table))
                    self.db.execute(q,vals)
        self.db.commit()
   
    def convert_sqliteRow_to_dict(self,rows):
        #for easy work, we convert sqliteRow object (return by the query) to table of dictionnary
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
    
    def list_tables(self):
        return [table for table in connection.introspection.table_names()
            # avoid server specific tables
            if not ( table in ('conf','vintf','event_logger') 
            # avoid django tables
                    or table.startswith("django_")) ]

def usage():
    sys.stderr.write("usage : vulture-daemon.py {start/stop/status}\n")
    sys.exit(1)

if __name__ == '__main__':
    daemon = SynchroDaemon()
    func = {
            'start':daemon.start,
            'stop':daemon.stop,
            'status':daemon.started,
        }
    try:
        f = func[sys.argv[1]]
    except:
        usage()
    sys.exit(not f() and 1 or 0)

