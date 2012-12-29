#!/usr/bin/env python
# -*- coding: utf-8 -*-
try:
    import sqlite3
except:
    from pysqlite2 import dbapi2 as sqlite3
import socket as S
from django.utils import simplejson
import time
import signal
from django.conf import settings
import sys,os
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

class MC:
    lockname = "vulture_lock"
    lockfile = "%s/vulture-daemon.lock"%settings.CONF_PATH
    versionkey = "vulture_version"
    keystore = "vulture_inst"
    tmpfile = "vulture_tmp"
    itv = 30
    mc_servers = [x.strip() for x in Conf.objects.get(var="memcached").value.split(",")]
    mc_client = None
    try:
        import memcache
        mc_client = memcache.Client(mc_servers);
    except:
        pass
    if not mc_client:
        raise Exception("no memcached driver available")

    db = sqlite3.connect(settings.DATABASES['default']['NAME'])
    db.row_factory=sqlite3.Row

    @staticmethod
    def getConf(key):    
        val=Conf.objects.get(var=key)
        return val and val.value or None

    @staticmethod
    def get(key):
        return MC.mc_client.get(str(key))
            
    @staticmethod
    def set(key,value):
        return MC.mc_client.set(str(key),value)

    @staticmethod
    def add(key,value):
        return MC.mc_client.add(str(key),value)

    @staticmethod
    def append(key,value):
        return MC.mc_client.append(str(key),value)

    @staticmethod
    def prepend(key,value):
        return MC.mc_client.prepend(str(key),value)

    @staticmethod
    def delete(key):
        return MC.mc_client.delete(str(key))
    
    @staticmethod
    def lock():
        while not MC.add(MC.lockname,1):
            time.sleep(1)

    @staticmethod
    def unlock():
        MC.delete(MC.lockname)

    @staticmethod
    def clusterActivated():
        try:
            useMe = MC.getConf("use_cluster")
            if useMe == "1" :
                return True
        except:
            return False
 
    @staticmethod
    def daemonStarted():
        try:
            f = open(MC.lockfile,"rb")
            pid = f.read()
            f.close()
            pid=int(pid)
            os.kill(pid,0)
            return pid
        except:
            return False

    @staticmethod
    def startDaemon():
        if MC.daemonStarted():
            print ("[-] Already started")
            MC.stopDaemon()
            if MC.daemonStarted():
                print ("[-] Unable to stop daemon")
                return False
        if not MC.clusterActivated():
            print ("[-] Cluster not activated in conf")
            return False
        print ("[+] Cluster sync daemon starting .. ")
        # creating lock file
        f = open(MC.lockfile,"wb")
        f.write(str(os.getpid()))
        f.close()
        # set interrupt handler
        signal.signal(signal.SIGINT, MC.stopDaemon)
        try:
            os.mkdir(settings.CONF_PATH+"security-rules")
        except:
            pass
        while True:
            # check if the cluster was deactivated in conf
            if not MC.clusterActivated():
                MC.stopDaemon()
            # check if conf is up to date, eventually update
            MC.refresh()
            # wait x seconds
            time.sleep(MC.itv)

    @staticmethod
    def stopDaemon(sig=2, v=0):
        name = MC.getConf("name")
        pid = MC.daemonStarted()
        # daemon is already stopped
        if not pid:
            print ("[-] Daemon not started, exiting..")
            return False
        # stopping external process
        if pid != os.getpid():
            print ("[+] Stopping external daemon [%s]"%pid)
            os.kill(pid,2)
            return True
        # stopping this process
        print ("[+] Stopping daemon [%s]"%pid)
        # remove this cluster from memcache
        old = MC.get(MC.keystore) or []
        if old:
            MC.set(MC.keystore,[f for f in old if f!=name])
        MC.delete("%s:infos"%name)
        # remove lockfile
        os.remove(MC.lockfile)
        sys.exit(0)
    
    @staticmethod
    def refresh():
        MC.lock()
        try:
            MC.check_config()
        except:
            MC.unlock()
            raise
        MC.unlock()
    
    @staticmethod
    def check_config():
        # get database conf vars
        myversion = int(MC.getConf("version_conf"))
        name = MC.getConf('name')
        # get memcache conf version
        mcversion = MC.get(MC.versionkey)
        mcversion = mcversion == None and -1 or int(mcversion)
        print ("[*] Refreshing conf, current: %s , last: %s"%(myversion,mcversion))
        if myversion == mcversion:
            print "[*] Already to last version"
            pass
        elif myversion > mcversion:
        # push my conf in memcache 
            print ("[+] Pushing my conf into memcache...")
            MC.push_conf()
            MC.set(MC.versionkey, myversion)
            print ("[+] Done")
        else:
        # new config available, update
            print ("[+] Updating conf...")
            MC.update_from_mc()
            myversion = mcversion
            # update my version number in database
            Conf.objects.filter(var="version_conf").update(value=str(myversion))
            # eventually reload interfaces with changes
            if MC.getConf("auto_restart")=='1':
                MC.reload_intfs()
            print ("[+] Done")
        # put this server name in memcache if not already there
        all_srv = MC.get(MC.keystore) or []
        if not name in all_srv:
            MC.set(MC.keystore,all_srv+[name])
        # put infos of this server in memcache for monitoring purpose
        infos = {"version":myversion,"last":time.time()}
        MC.set("%s:infos",infos)
    
    # monitoring func, return list of servers and infos
    @staticmethod
    def all_elements():
        ret = []
        all_srv = MC.get(MC.keystore)
        if not all_srv:
            return ret
        for name in all_srv:
            info = MC.get("%s:infos")
            # if we failed to get infos, return err value
            if not info:
                info = {"name":name,"version":-1,"last":0}
            else:
            # else return memcache value with this server's name
                info.update({"name":name})
            ret += [info]
        return ret
        
    @staticmethod
    def reload_intfs():
        intfs= Intf.objects.all()
        for intf in intfs :
            if intf.need_restart:
                fail = intf.maybeWrite()
                if not fail:
                    # conf is valid : reload
                    intf.k('graceful')
                    apps = App.objects.filter(intf=intf).all()
                    for app in apps:
                        MC.delete('%s:app'%app.name)

    @staticmethod
    def get_all_tables_name():
        #Here we get all config tables name except django specific tables
        sth = MC.db.execute("SELECT name FROM (SELECT * FROM sqlite_master UNION ALL SELECT * FROM sqlite_temp_master) WHERE type='table' AND name not like 'django%' and name NOT IN ('conf','vintf','event_logger') ORDER BY name;")
        tables = sth.fetchall()
        return [t[0] for t in tables]

    @staticmethod
    def reset_mc():
        # delete sql conf
        tables = MC.get_all_tables_name()
        for t in tables:
            MC.delete("conf:%s"%t)
        # delete ms conf
        MC.delete("conf:mod_secu")
        # delete servers infos
        srv = MC.get(MC.keystore) or []
        for s in srv:
            MC.delete("%s:infos"%s)
        MC.delete(MC.keystore)
        # delete conf version
        MC.delete(MC.versionkey)
        # delete lock
        MC.unlock()

    # push conf of this server in memcache
    @staticmethod
    def push_conf():
        tables = MC.get_all_tables_name()
        # push sql conf
        for table in tables:
            MC.set('conf:%s'%table,MC.get_SQL_table(table))
        # push mod_secu conf
        cmd = "cd %s/security-rules ; tar hczf %s *"%(
            settings.CONF_PATH,MC.tmpfile)
        os.popen(cmd).read()
        tmp_path = "%s/security-rules/%s"%(settings.CONF_PATH,MC.tmpfile)
        fcont = open(tmp_path,"rb").read()
        MC.set("conf:mod_secu",fcont)
        os.remove(tmp_path)
        
    @staticmethod
    def convert_sqliteRow_to_dict(rows):
        #for easy work, we convert sqliteRow object (return by the query) to table of dictionnary
        tab=[]
        for row in rows:
            dico={}
            for key in row.keys():
                dico[key]=row[key]
            tab += [dico]
        return tab

    #get data from database
    @staticmethod
    def get_SQL_table(table):
        sth = MC.db.execute("SELECT * from `%s`"%table)
        rows = sth.fetchall();
        di = MC.convert_sqliteRow_to_dict(rows)
        return di
    
    @staticmethod
    def update_from_mc():
        tables = MC.get_all_tables_name()
        for table in tables:
            print("checking  %s ..."%table)
            db_conf = MC.get_SQL_table(table)
            mc_conf = MC.get("conf:%s"%table)
            db_ids,mc_ids = {},{}
            for row in db_conf:
                db_ids[row['id']]=row
            for row in mc_conf:
                mc_ids[row['id']]=row
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
                        q="UPDATE `%s` SET %s WHERE id=?"%(
                            table,",".join(["`%s`=?"%k for k in keys]))
                        print(q)
                        MC.db.execute(q,vals+[mc_k])
                elif mc_e: 
                    vals = [mc_e[k] for k in mc_e]
                    q = "INSERT INTO `%s` (%s) VALUES (%s)"%(table,
                        ",".join(["`%s`"%k for k in mc_e]),
                        ",".join(['?']*len(vals))
                        )
                    print(q)
                    MC.db.execute(q,vals)
            # Eventually delete some lines
            dels=[str(f) for f in db_ids if not f in mc_ids]
            if dels:
                q = "DELETE FROM `%s` WHERE id IN (%s)"%(
                    table,",".join(dels))
                print (q)
                MC.db.execute(q)
        MC.db.commit()
        # pop mod secu conf
        tmp_path = "%s/security-rules/%s"%(settings.CONF_PATH,MC.tmpfile)
        os.popen("rm -rf %s/security-rules/*"%settings.CONF_PATH)
        open(tmp_path,"wb").write(MC.get("conf:mod_secu"))
        os.popen("tar-C %s/security-rules -zxf %s"%settings.CONF_PATH)
        os.remove(tmp_path)
    
    @staticmethod
    def usage():
        sys.stderr.write("usage : vulture-daemon.py {start/stop/status}\n")
        sys.exit(1)

if __name__ == '__main__':
    func = {
            'start':MC.startDaemon,
            'stop':MC.stopDaemon,
            'status':MC.daemonStarted,
        }
    try:
        f = func[sys.argv[1]]
    except:
        MC.usage()
    sys.exit(f() and 0 or 1)
