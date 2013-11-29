# -*- coding: utf-8 -*-
from django.template.loader import get_template
from django.template import Context
from django.conf import settings
from django.db import models
from django.contrib import admin
from time import sleep
import time
try:
	import sqlite3
except:
	from pysqlite2 import dbapi2 as sqlite3
from datetime import date
import ldap
import operator
import os, time
import os
import subprocess
import re
from django.contrib.auth.models import User as DjangoUser, UserManager as DjangoUserManager
from django.db.models.signals import post_save
from django import forms
import base64
import ifconfig
import tarfile,zipfile
import urllib2
import tempfile
import shutil

class Groupe(models.Model):
    name = models.CharField(max_length = 255,blank=False,null=True)
    date = models.DateField(auto_now_add=True,editable=False)
    version = models.IntegerField(default=0)
    url= models.URLField(null=True)

    def copy(self):
        groupe=Groupe(name=self.name,version=self.version+1,url=self.url)
        groupe.save()
        try:
            if groupe.url:
                fd = groupe.get_file(url = self.url)
                groupe.extract_archive(fd)
        except:
            groupe.delete()
            raise Exception('error testing rule set updates')
        return groupe

    def is_uptodate(self):
        """check if a group is uptodate and create one if not"""
        copy=self.copy()
        if len(copy.fichier_set.all()) != len(self.fichier_set.all()):
            return False
        for c in copy.fichier_set.all():
            r=False
            for f in self.fichier_set.all():
                if f.content == c.content:
                    r=True
            if not r:
                return False
        copy.delete()
        return True

    def delete(self,*args,**kwargs):
        if self.is_ondisk():
            shutil.rmtree(self.get_dir_path())
        super(Groupe,self).delete(*args,**kwargs)
        
    def deploy_ondisk(self):
        """put group files on disk to be used by apache"""
        
        #creer un dossier "gpe_version" dans security rules en utilisant settings.conf
        if self.is_ondisk():
            return False

        #pour chaque fichier ratache au groupe dans la DB
        for file_ in self.fichier_set.all():                    
            #Deployer le fichier:
            # -creer le dossier racine du fichier  
            file_subdir = file_.get_full_dir_path()
            if not os.path.exists(file_subdir):
                os.makedirs(file_subdir)
            file_path = file_.get_full_file_path()
            # -creer le fichier
            if not os.path.exists(file_path):
                f=open(file_path,'w')
                f.write(file_.content.encode('utf-8'))
                f.close()
        return True

    def get_file(self, url='', filecontent=''):#,path="http://vulture.googlecode.com/files/mod_secu_rules.tgz"):
        """retourne file descriptor sur l'archive de regles mod security"""
        t = tempfile.NamedTemporaryFile()
        if url: 
            try:
                proxy_url= Conf.objects.get(var="proxy").value 
                proxy_handler = urllib2.ProxyHandler({'http': proxy_url, 'https': proxy_url, 'ftp':proxy_url })
                opener = urllib2.build_opener(proxy_handler)
            except:
                opener = urllib2.build_opener()
            t.write(opener.open(url).read())
        else:
            t.write(filecontent)
        t.seek(0,0)
        return t

    def extract_archive(self,fd):
        """extrait une archive"""
        destination_path = tempfile.mkdtemp()
        if zipfile.is_zipfile(fd.name):
            archive = zipfile.ZipFile(fd.name)
        elif tarfile.is_tarfile(fd.name):
            archive = tarfile.open(fd.name)
        else:
            raise Exception("%s is no a tarfile or zipfile"%fd.name ) 
        archive.extractall(destination_path)
        fd.close()
        archive.close()
        self.walk_dir(destination_path)
        shutil.rmtree(destination_path)
        return True
    
    def walk_dir(self, tempdir):
        """parcoure recursivement le path et lance la fonction d'ajout pour tous les fichiers"""
        reg = re.compile('.*\.(conf|data|lua|js|c|pl|tests)$')
        for root, dirs, files in os.walk(tempdir):
            for each_file in files:
                if not reg.match(each_file):
                    continue
                path_file="%s/%s"%(root,each_file)
                f=open(path_file, "rb")
                content = f.read().decode('utf-8','replace')
                self.fichier_set.create(
                    name=each_file,
                    content=content,
                    groupe=self,
                    path_name="/".join(root.split("/")[3:]))
                f.close()
        return True

    def get_dir_path(self):
        return "%ssecurity-rules/%s_%s"%(settings.CONF_PATH,self.name, self.version)

    def is_ondisk(self):
        """check if groups files of the group exists on the disk"""
        return os.path.exists(self.get_dir_path())

    def __unicode__(self):
        return self.name+"-"+str(self.version)

    class Meta:
        db_table = 'groupe'

class Fichier(models.Model):
    name    = models.CharField(max_length = 255)
    content = models.TextField()
    path_name = models.CharField(max_length = 255)
    groupe  = models.ForeignKey(Groupe)

    def get_full_dir_path(self):
        return "%s/%s"%(self.groupe.get_dir_path(), self.path_name)

    def get_full_file_path(self):
        return "%s/%s"%(self.get_full_dir_path(), self.name)

    def get_rule_list(self):
        content=self.content.replace("\\\n"," ")
        return [d for d in filter(None,[ x.strip() for x in content.split("\n")]) if not d.startswith("#")]

    def get_rule_components(self):
        rule_list=self.get_rule_list()
        reg = re.compile('(?P<sec>Sec[a-zA-Z]+)(\s+(?P<variables>.*?))?(\s+\"(?P<operator>.?@.*?)\")?\s+\"(?P<actions>.*?)\"\s*')
        t=[]
        for rule in rule_list:
            m=reg.search(rule)
            if m:
                t+=[m.groupdict()]
        return t 

    def get_actions_rules_components(self):
        """ transform rules actions form string to array of actions"""
        reg1 = re.compile("id\s*:\s*'?(\d+)'?")
        try:
            t=self.get_rule_components()
            for k in t:
                if k['actions']:
                    k['actions']=k['actions'].split(",")
                    j=0
                    while j < len(k['actions']):
                        splited = k['actions'][j].split(":")
                        if splited[0]=='id':
                            k['id']= int(splited[1].strip("'"))
                            del(k['actions'][j])
                        else:
                            k['actions'][j]= splited
                            j+=1
        except:
            t=[]
        return t

    def __unicode__(self):
        return self.name

    class Meta:
        db_table = "file"

class Politique(models.Model):
    name = models.CharField(max_length = 255)
    custom_rule = models.ManyToManyField('CustomRule',null=True,blank=True)

    def deploy(self):
        #deploiement du fichier de conf par politique
        if self.is_uptodate():
            return
        f=open(self.get_custom_rule_path(),"w")
        f.write(self.to_file().encode('utf-8'))
        f.close()
        #deploiement du groupe de conf
        for fp in self.fichierpolitique_set.all():
            fp.fichier.groupe.deploy_ondisk()   
        return True 
    
    def to_file(self):
        t = get_template("custom_rule.conf")
        return t.render(Context({'policy':self}))
    
    def custom_rules_are_uptodate(self):
        if self.custom_rule.all():
            if os.path.exists(self.get_custom_rule_path()):
                f=open(self.get_custom_rule_path(),"r")
                content=f.read()
                f.close()
                if content == self.to_file():
                    return True
            return False
        return True

    def policy_group_is_uptodate(self):
        for fp in self.fichierpolitique_set.all():
            if not fp.fichier.groupe.is_ondisk():
                return False
        return True 
    
    def is_uptodate(self):
        return self.custom_rules_are_uptodate() and self.policy_group_is_uptodate()

    def has_strange_ignore(self):
        for fp in self.fichierpolitique_set.all():
            if fp.has_strange_ignore():
                return True

    def get_custom_rule_path(self):
        return "%ssecurity-rules/%s_custom_rules.conf"%(settings.CONF_PATH, self.name.replace(" ","_").lower())

    def __unicode__(self):
        return self.name

    class Meta:
        db_table = "policy"

class FichierPolitique(models.Model):
    politique = models.ForeignKey(Politique)
    fichier = models.ForeignKey(Fichier)

    def has_strange_ignore(self):
        for i in self.ignorerules_set.all():
            if i.is_strange():
                return True

    def all_ignores(self):
        return [i.rules_number for i in self.ignorerules_set.all()]

    def update(self,post):
        """update fp with adding/removing ignoreRules depeding on post"""
        #delete all ignores
        self.ignorerules_set.all().delete() 

        #creation des ignores rules en base
        reg = re.compile('ignore_rule_(\d+)')
        
        #recense les rule_id du fichier
        t=[]
        for i in self.fichier.get_actions_rules_components():
            if 'id' in i:
                t.append(i['id'])            
        #pour chaque rule_id trouvé dans le post, on l'enleve de tableau d'id
        for data,activated in post:
            n = reg.search(data)
            if n:
                idr=int(n.group(1))
                if idr in t:
                    t.remove(idr)
        #pour chaque rule_id restant, on cree un ignorerule associe au fichier politique
        for i in t:
            self.ignorerules_set.create(rules_number=i)
       

    def __unicode__(self):
        return self.fichier.name

    class Meta:
        db_table = "policy_file"

class IgnoreRules(models.Model):
    rules_number = models.IntegerField()
    fichier_politique = models.ForeignKey(FichierPolitique)

    def is_strange(self):
        reg2 = re.compile("id\s*:\s*'(\d+)'",re.MULTILINE)
        ids = [ int(i) for i in reg2.findall(self.fichier_politique.fichier.content)]
        return self.rules_number not in ids
        
    def __unicode__(self):
        return str(self.rules_number)

    class Meta:
        db_table = "ignore_rules"


class CustomRule(models.Model):
    name = models.CharField(max_length=128,unique=1)
    rule = models.TextField()
    def __unicode__(self):
        return self.name
    class Meta:
        db_table = 'custom_rule'

class PluginCAS(models.Model):
    auth = models.ForeignKey('Auth',null=1,blank=1)
    field = models.CharField(max_length=128,null=1,blank=1)
    class Meta:
        db_table='plugin_cas';

class VINTF(models.Model): 
    name = models.CharField(max_length=128,unique=1,null=0)
    intf = models.CharField(max_length=128,unique=1,null=0)
    ip = models.CharField(max_length=128, unique=1, null=0)
    netmask = models.CharField(max_length=128,unique=0, null=0)
    broadcast = models.CharField(max_length=128,unique=0,null=1)
   
    def isStarted(self):
	started = ifconfig.getIntfs()
	return self.intf in started and started[self.intf] == self.ip

    def start(self):
        ifconfig.startIntf(self.intf, self.ip, self.netmask, self.broadcast)
    
    def stop(self):
        ifconfig.stopIntf(self.intf)
    
    def reload(self):
        self.stop()
        self.start()

    class Meta:
	db_table = 'vintf'
	
class Log(models.Model):
    LOG_LEVELS = (
        ('emerg', 'emerg'),
        ('alert', 'alert'),
        ('crit',  'crit'),
        ('error', 'error'),
        ('warn',  'warn'),
        ('notice','notice'),
        ('info',  'info'),
        ('debug', 'debug'),
        )
    name = models.CharField(max_length=128, unique=1)
    level = models.CharField(max_length=10, blank=1,choices=LOG_LEVELS)
    format = models.CharField(max_length=500, blank=1)
    dir = models.CharField(max_length=200)
    script = models.CharField(max_length=200, blank=1, null=1)
    def __str__(self):
        return self.name
        
    class Meta:
        db_table = 'log'

class Intf(models.Model):
    SSL_ENGINES = (
        ('cswift',   'CryptoSwift'),
        ('chil',     'nCipher'),
        ('atalla',   'Atalla'),
        ('nuron',    'Nuron'),
        ('ubsec',    'UBSEC'),
        ('aep',      'Aep'),
        ('sureware', 'SureWare'),
        ('4758cca',  'IBM 4758 CCA'),
        )

        #Actions to be used to handle login problems
    ACTIONS = (
        ('nothing', 'nothing'),
        ('template', 'template'),
        ('log', 'log'),
        ('message', 'message'),
        ('redirect', 'redirect'),
        ('script', 'script'),
        )
    RESTRICTED_ACTIONS = (
        ('message', 'message'),
        ('redirect', 'redirect'),
        ('script', 'script'),
        )
    REMOVAL_ALGORITHM = (
        ('LRU','LRU'),
        ('GDSF','GDSF'),
        )
    name = models.CharField(max_length=128, unique=1)
    ip = models.IPAddressField()
    port = models.IntegerField()
    log = models.ForeignKey('Log')
    default_url = models.CharField(max_length=256,blank=1,null=1)
    appearance = models.ForeignKey('Appearance', blank=1, null=1)
    # sso portal
    sso_portal = models.CharField(max_length=256,blank=1,null=1)
    sso_timeout = models.IntegerField(blank=1,null=1)
    sso_update_access_time = models.BooleanField(default=0)
    check_csrf = models.BooleanField(default=True);
    # cas portal
    cas_portal = models.CharField(max_length=256,blank=1,null=1)
    cas_auth = models.ForeignKey('Auth',null=1,blank=1)
    cas_auth_basic = models.BooleanField(default=0)
    cas_st_timeout = models.IntegerField(blank=1,null=1)
    cas_redirect = models.CharField(max_length=256,blank=1,null=1)
    cas_display_portal = models.BooleanField(default=0);
    # login triggers
    auth_server_failure_action = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    auth_server_failure_options = models.CharField(max_length=128, blank=1, null=1)
    account_locked_action = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    account_locked_options = models.CharField(max_length=128, blank=1, null=1)
    login_failed_action = models.CharField(max_length=128, blank=1, null=1, choices=RESTRICTED_ACTIONS, default='template')
    login_failed_options = models.CharField(max_length=128, blank=1, null=1)
    need_change_pass_action = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    need_change_pass_options = models.CharField(max_length=128, blank=1, null=1)
    # ssl fields	
    cert = models.TextField(blank=1,null=1)
    key = models.TextField(blank=1,null=1)
    ca = models.TextField(blank=1,null=1)
    cacert = models.TextField(blank=1,null=1)
    ssl_engine = models.CharField(max_length=10,blank=1,choices=SSL_ENGINES)
    # apache server setting
    srv_timeout = models.IntegerField(blank=0,default=300)
    srv_startsrv = models.IntegerField(blank=0,default=5)
    srv_min_spare_srv = models.IntegerField(blank=0,default=5)
    srv_max_spare_srv = models.IntegerField(blank=0,default=10)
    srv_max_clients = models.IntegerField(blank=0,default=150)
    srv_max_req_per_child = models.IntegerField(blank=0,default=0)
    srv_ka = models.BooleanField(default=True)
    srv_ka_max_req = models.IntegerField(blank=1,null=1,default=100)
    srv_ka_timeout = models.IntegerField(blank=1,null=1,default=15)
    srv_apache_user = models.CharField(blank=1,null=1,max_length=50)
    srv_apache_group = models.CharField(blank=1,null=1,max_length=50)
    cache_root = models.CharField(blank=1,null=1,max_length=128)
    cache_dir_level = models.IntegerField(default=3)
    cache_dir_length = models.IntegerField(default=2)
    cache_max_file_size = models.IntegerField(default=1000000)
    cache_min_file_size = models.IntegerField(default=1)
    mcache_max_object_count = models.IntegerField(default=1009)
    mcache_max_object_size = models.IntegerField(default=10000)
    mcache_max_streaming_buffer = models.IntegerField(blank=1,null=1)
    mcache_min_object_size = models.IntegerField(default=1)
    mcache_removal_algorithm = models.CharField(choices=REMOVAL_ALGORITHM, default='GDSF',max_length=128)
    mcache_size = models.IntegerField(default=100)
    virtualhost_directives = models.TextField(blank=1,null=1)

    def conf(self):
        t = get_template("vulture_httpd.conf")
        dirapp = {}
        allapp = App.objects.filter(intf=self.id).order_by('name', '-alias')
        for app in allapp:
            split=app.name.split("/",1)
            host=split[0]
            dir=app
            if not dirapp.has_key(host):
                dirapp[host]=[dir]
            else:
                dirapp[host]+=[dir]
        MS_path=Conf.objects.filter(var='mod_security_path')
        if len(MS_path):
            MS_path = MS_path[0];
        else:
            MS_path = ""
        uname = os.uname()
        c = Context({"VultureConfPath" : settings.CONF_PATH,
                     "VultureStaticPath" : settings.MEDIA_ROOT,
                     "VultureBinPath" : settings.BIN_PATH,
                     "PerlSwitches" : settings.PERL_SWITCHES,
                     "dbname" : settings.DATABASES['default']['NAME'],
                     "serverroot" : settings.SERVERROOT,
                     "www_user" : settings.WWW_USER,
                     "www_group" : settings.WWW_GROUP,
                     "httpd_custom" : settings.HTTPD_CUSTOM,
                     "app_list" : dirapp,
                     "intf" : self,
                     "MS_path" : MS_path,
                     "arch64" : (uname[4] == 'x86_64')
                     })
        return t.render(c)


    def has_deflate(self):
        return App.objects.filter(intf=self.id,
                deflate_activated=True).count()>0
    
    def has_mod_secu(self):
        return App.objects.filter(intf=self.id,
                security__isnull=False).count()>0
    
    def has_balancer(self):
        return App.objects.filter(intf=self.id,
                Balancer_Activated=True).count()>0

    def has_ftp(self):
        return (
                App.objects.filter(intf=self.id,
                    Balancer_Activated=True,
                    Balancer_Node__istartswith='ftp://').count()>0
                or App.objects.filter(intf=self.id,
                    Balancer_Activated=False,
                url__istartswith='ftp://').count()>0)

    def has_cache(self):
        return (App.objects.filter(intf=self.id, cache_activated=True).count()>0)

    def has_disk_cache(self):
        return (App.objects.filter(intf=self.id, cache_activated=True, cache_type="disk").count()>0)

    def has_mem_cache(self):
        return (App.objects.filter(intf=self.id, cache_activated=True, cache_type="mem").count()>0)

    def hasJK(self):
        for a in App.objects.filter(intf=self.id):
            if a.getJKDirective():
                return True
        return False

    def is_ssl(self):
        return self.cert and True or False

    def backupConf(self):
        backpath="%s%s_backup/"%(settings.CONF_PATH,self.id)
        if not os.path.exists(backpath):
            os.mkdir(backpath,0770)
        for ext in ("cert","conf","key","chain","cacrt","ca"):
            fnam="%s.%s"%(self.id,ext)
            bpath="%s%s"%(backpath,fnam)
            cpath="%s%s"%(settings.CONF_PATH,fnam)
            try: 
                open(bpath,"w").write(open(cpath).read())
            except:
                pass
        return backpath

    def restoreConf(self,backpath):
        for ext in ("cert","conf","key","chain","cacrt","ca"):
            fnam="%s.%s"%(self.id,ext)
            bpath="%s%s"%(backpath,fnam)
            cpath="%s%s"%(settings.CONF_PATH,fnam)
            try: 
                open(cpath,"w").write(open(bpath).read())
            except:
                pass
         
    def tryConf(self):
        cfile="%s%s.conf"%(settings.CONF_PATH,self.id)
        proc = subprocess.Popen(settings.HTTPD_PATH.split()+["-t","-f",cfile],0,"/usr/bin/sudo",None,subprocess.PIPE,subprocess.PIPE)
        if not proc:
            raise "Unable to execute apache!"
        if proc.wait():
            return "Bad Apache Conf > "+proc.stderr.read()
        
    def maybeWrite(self):
        bpath = self.backupConf()
        self.write()
        fail_msg = self.tryConf()
        if fail_msg:
            self.restoreConf(bpath)
            return fail_msg

    def delete(self,*args,**kwargs):
        for ext in ("conf","crt","key","chain","cacrt"):
            fname = "%s%s.%s"%(settings.CONF_PATH,self.pk,ext)
            if os.path.exists(fname):
                os.remove(fname)
        super(Intf,self).delete(*args,**kwargs)
        
            
    def write(self):
        self.deploy_all()
        f=open("%s%s.conf" % (settings.CONF_PATH, self.id), 'wb')
        f.write(str(self.conf()))
        f.close()
        todos = (
                    ("crt",self.cert),
                    ("key",self.key),
                    ("chain",self.ca),
                    ("cacrt",self.cacert),
                )
        for (ext,file_) in todos:
            fname = "%s%s.%s" % (settings.CONF_PATH, self.id,ext)
            if file_:
                f=open(fname, 'wb')
                f.write(str(file_))
                f.close()
            else:
                if os.path.exists(fname):
                    os.remove(fname)
        for app in App.objects.filter(intf=self.id).all():
            auth = app.auth
            if auth and auth.is_ssl():
                f=open("%s%s.ca" % (settings.CONF_PATH, str(self.id)+'-'+app.name.split("/")[0]), 'wb')
                f.write(str(auth.get_crt()))
                f.close()

    def deploy_all(self):
        """ si mod_secu est active, deployer groupe et modsecuconf"""
        for app in App.objects.filter(intf=self).all():
            if app.security:
                app.security.deploy()
                if app.policy:
                    app.policy.deploy()
        
    def checkIfEqual(self):
        try:
            f=open("%s%s.conf" % (settings.CONF_PATH, self.id), 'rb')
            content=f.read()
            content2 = self.conf()
            f.close()
        except:
            return False
        return (content == content2)
            
    def pid(self):
        regproc = re.compile("^(\d+)$")
        regstat = re.compile("\d+\s+\(.*(httpd|apache)/*\)\s+\w\s+(\d+)\s+.*")
        try:
                f = open("%s%s.pid" % (settings.CONF_PATH, self.id), "rb")
                pid = f.read().strip()
                f.close()
        except:
                return None
        pidof = str(os.popen("pidof %s" % settings.HTTPD_PATH).read()).split()
        parents = [f.group(1) for f in [regstat.match(m) for m in [open("/proc/%s/stat"%(g)).read() for g in pidof]] if f]
        if pid in pidof or pid in parents:
                return pid


    def need_restart(self):
        apps = self.app_set.all()
        for app in apps:
            if app.security and not app.security.is_uptodate():
                return True
            if app.policy and not app.policy.is_uptodate():
                return True
        try:
            f=open("%s%s.conf" % (settings.CONF_PATH, self.id), 'r')
            content = f.read()
            f.close()
            if content != self.conf(): 
                return True
        except:
            return True

        if self.ca:
            try:
                f=open("%s%s.chain" % (settings.CONF_PATH, self.id), 'r')
                content = f.read()
                f.close()
                if content != self.ca :
                    return True
            except:
                return True

        if self.cert:
            try:
                f=open("%s%s.crt" % (settings.CONF_PATH, self.id), 'r')
                content = f.read()
                f.close()
                if content != self.cert :
                    return True
            except:
                return True

        if self.key:
            try:
                f=open("%s%s.key" % (settings.CONF_PATH, self.id), 'r')
                content = f.read()
                f.close()
                if content != self.key :
                    return True
            except:
                return True

        if self.cacert:
            try:
                f=open("%s%s.cacrt" % (settings.CONF_PATH, self.id), 'r')
                content = f.read()
                f.close()
                if content != self.cacert :
                    return True
            except:
                return True

        for app in App.objects.filter(intf=self.id).all():
            auth = app.auth
            if auth and auth.is_ssl():
                try:
                    f=open("%s%s.ca" % (settings.CONF_PATH, str(self.id)+'-'+app.name.split("/")[0]), 'r')
                    content = f.read()
                    f.close()
                    if content != auth.get_crt() :
                        return True
                except:
                    return True
          
# send command "cmd" to apache (using httpd.conf of interface 
    def k(self, cmd):
	confFile=settings.CONF_PATH+str(self.id)+".conf"
	proc = subprocess.Popen(settings.HTTPD_PATH.split()+["-f",confFile,"-k",cmd],0,"/usr/bin/sudo",None,subprocess.PIPE,subprocess.PIPE)
	if proc:
		return proc.stdout.read()+proc.stderr.read()
	return "unable to execute "+settings.HTTPD_PATH
 
    def hasBlackIp (self):
        return BlackIP.objects.filter(app__isnull = True)
    
    def __str__(self):
        return self.name
        
    class Meta:
        db_table = 'intf'
        permissions = (
            ("reload_intf", "Can stop/start interface"),
        )
        
class Profile(models.Model):
    app = models.ForeignKey('App')
    user = models.TextField()
    login = models.CharField(max_length=256,null=1)
    password = models.CharField(max_length=256,null=1, blank=1)
    class Meta:
        db_table = 'profile'

class ACL(models.Model):
    name = models.CharField(max_length=128, unique=1)
    auth = models.ForeignKey('Auth')
    users_ok = models.ManyToManyField('UserOK',null=1,blank=1,db_table='acl_userok')
    groups_ok = models.ManyToManyField('GroupOK',null=1,blank=1,db_table='acl_groupok') 
    def __unicode__(self):
        return self.name    
    def get_absolute_url(self):
        return "/acl/"
    class Meta:
        db_table = 'acl'

class UserOK(models.Model):
    user = models.CharField(max_length=20,unique=1)
    def __str__(self):
        return self.user
    class Meta:
        db_table = 'userok'

class GroupOK(models.Model):
    group = models.CharField(max_length=20,unique=1)
    def __str__(self):
        return self.group
    class Meta:
        db_table = 'groupok'

class Conf(models.Model):
    var = models.CharField(unique=1, max_length=128)
    value = models.CharField(null=1, max_length=128)
    def __str__(self):
        return self.var
    class Meta:
        db_table = 'conf'

class EventLogger(models.Model):
    EVENT_TYPE = (
        ('connection', 'connection'),
        ('connection_failed', 'connection_failed'),
        ('deconnection', 'deconnection'),
        ('active_sessions', 'active_sessions'),
    )
    app = models.ForeignKey('App', blank=1, null=1)
    user = models.CharField(max_length = 256, null=1, blank=1)
    event_type = models.CharField(max_length=64,choices=EVENT_TYPE)
    timestamp = models.DateTimeField(auto_now_add=True, null=1, blank=1)
    info = models.CharField(max_length = 256, null=1, blank=1)
    class Meta:
        db_table = 'event_logger'
   
# Authentification classes
class SQL(models.Model):
    SQL_DRIVERS = (
        ('SQLite', 'SQLite'),
        ('Pg', 'PostgreSQL'),
        ('mysql', 'MySQL'),
        ('Oracle','Oracle'),
        )
    SQL_ALGOS = (
        ('plain', 'plain'),
        ('md5', 'md5'),
        ('sha1', 'sha1'),
        )
    name = models.CharField(max_length=128, unique=1)
    driver = models.CharField(max_length=10,choices=SQL_DRIVERS)
    database = models.CharField(max_length=128)
    user = models.CharField(max_length=128, blank=1)
    password = models.CharField(max_length=128, blank=1)
    host = models.CharField(max_length=128, blank=1)
    port = models.IntegerField(null=1, blank=1)
    table = models.CharField(max_length=128)
    user_column = models.CharField(max_length=64)
    pass_column = models.CharField(max_length=64)
    pass_algo = models.CharField(max_length=10,choices=SQL_ALGOS)
    changepass_column = models.CharField(max_length=64,null=1, blank=1)
    def user_ko(self, user_ok):
        user_ko = []
        if self.driver == 'SQLite':
            con = sqlite3.connect(self.database)
            cur = con.cursor()
            query = "SELECT %s from %s WHERE %s NOT IN (%s)" % (
                self.user_column, self.table,self.user_column,
                ",".join(["'%s'"%user.user for user in user_ok]))
            cur.execute(query)
            for user in cur:
                user_ko.append(('%s' % user, '%s' % user))
        return user_ko

    def delete(self,*args,**kwargs):
        auth = Auth.objects.get(id_method=self.pk,auth_type='sql')
        auth.delete()
        super(SQL,self).delete(*args,**kwargs)

    def __str__(self):
        return "%s [SQL]"%(self.name)
    class Meta:
        db_table = 'sql'

class Kerberos(models.Model):
    name = models.CharField(max_length=128,unique=1)
    realm = models.CharField(max_length=256)

    def delete(self,*args,**kwargs):
        auth = Auth.objects.get(id_method=self.pk,auth_type='kerberos')
        auth.delete()
        super(Kerberos,self).delete(*args,**kwargs)

    def __str__(self):
        return "%s [KERBEROS]"%self.name
    class Meta:
        db_table = 'kerberos'
        
class CAS(models.Model):
    name = models.CharField(max_length=128,unique=1)
    url_login = models.CharField(max_length=256)
    url_validate = models.CharField(max_length=256)
    cas_attribute = models.CharField(max_length=256)

    def delete(self,*args,**kwargs):
        auth = Auth.objects.get(id_method=self.pk,auth_type='cas')
        auth.delete()
        super(CAS,self).delete(*args,**kwargs)

    def __str__(self):
        return "%s [CAS]"%self.name
    class Meta:
        db_table = 'cas'

class SSL(models.Model):
    SSL_REQUIRE = (
        ('none', 'none'), 
        ('optional','optional'),
        ('require', 'require'),
        )
    name = models.CharField(max_length=128,unique=1)
    require = models.CharField(max_length=20, choices=SSL_REQUIRE)
    crt = models.TextField()
    constraint = models.TextField()

    def get_require(self):
        return self.require

    def get_crt(self):
        return self.crt

    def get_constraint(self):
        return self.constraint

    def delete(self,*args,**kwargs):
        auth = Auth.objects.get(id_method=self.pk,auth_type='ssl')
        auth.delete()
        super(SSL,self).delete(*args,**kwargs)

    def __str__(self):
        return "%s [SSL]"%self.name
    class Meta:
        db_table = 'ssl'

class NTLM(models.Model):
    name = models.CharField(max_length=128,unique=1)
    domain = models.CharField(max_length=128)
    primary_dc = models.CharField(max_length=128)
    secondary_dc = models.CharField(max_length=128, blank=1, null=1)

    def delete(self,*args,**kwargs):
        auth = Auth.objects.get(id_method=self.pk,auth_type='ntlm')
        auth.delete()
        super(NTLM,self).delete(*args,**kwargs)

    def __str__(self):
        return "%s [NTLM]"%self.name
    class Meta:
        db_table = 'ntlm'

class RADIUS(models.Model):
    name = models.CharField(max_length=128,unique=1)
    host = models.CharField(max_length=128)
    port = models.IntegerField()
    secret = models.CharField(max_length=64)
    timeout = models.IntegerField()
    url_attr = models.CharField(max_length=32, blank=1)

    def delete(self,*args,**kwargs):
        auth = Auth.objects.get(id_method=self.pk,auth_type='radius')
        auth.delete()
        super(RADIUS,self).delete(*args,**kwargs)

    def __str__(self):
        return "%s [RADIUS]"%self.name
    class Meta:
        db_table = 'radius'

class LDAP(models.Model):
    LDAP_ENC_SCHEMES = (
            ('none','none (usual port: 389)'),
            ('ldaps','ldaps (usual port: 636)'),
            ('start-tls','start-tls (usual port: 389)'),
            )
    LDAP_SCOPE = (
            (ldap.SCOPE_SUBTREE,'subtree (all levels under suffix)'),
            (ldap.SCOPE_ONELEVEL,'one (one level under suffix)'),
            (ldap.SCOPE_BASE,'base (the suffix entry only)'),
            )
    LDAP_VERSIONS = (
            ('2','LDAP v2'),
            ('3','LDAP v3'),
            )
    name = models.CharField(max_length=255, unique=1)
    host = models.CharField(max_length=255)
    port = models.IntegerField()
    protocol = models.CharField(max_length=1,choices=LDAP_VERSIONS, default="3")
    scheme = models.CharField(max_length=255,choices=LDAP_ENC_SCHEMES, default="none")
    cacert_path = models.CharField(max_length=1024, blank=1, null=1)
    base_dn = models.CharField(max_length=255)
    dn = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    user_ou = models.CharField(max_length=255, blank=1, null=1)
    user_attr = models.CharField(max_length=255)
    user_scope = models.IntegerField(choices=LDAP_SCOPE)
    user_filter = models.CharField(max_length=255, blank=1, null=1)
    user_account_locked_attr = models.CharField(max_length=255, blank=1, null=1)
    user_mobile = models.CharField(max_length=15,blank=1)
    group_ou = models.CharField(max_length=255, blank=1, null=1)
    group_attr = models.CharField(max_length=255)
    group_scope = models.IntegerField(choices=LDAP_SCOPE)
    group_filter = models.CharField(max_length=255, blank=1, null=1)
    group_member = models.CharField(max_length=255, blank=1, null=1)
    are_members_dn = models.BooleanField()
    url_attr = models.CharField(max_length=255, blank=1)
    chpass_attr = models.CharField(max_length=255, blank=1)

    def delete(self,*args,**kwargs):
        auth = Auth.objects.get(id_method=self.pk,auth_type='ldap')
        auth.delete()
        super(LDAP,self).delete(*args,**kwargs)

    def search(self, base_dn, scope, filter, attr):
        result_set = []
        try:
            l = ldap.open(self.host)
            l.simple_bind_s(self.dn, self.password)
            result_id = l.search(base_dn, scope, filter.encode('utf-8'), attr)
            while 1:
                result_type, result_data = l.result(result_id, 0)
                if not result_data:
                    break
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
        except ldap.LDAPError, error_message:
            print error_message
        if len(result_set) == 0:
            return
        result_set_cleaned = []
        for i in range(len(result_set)):
            for entry in result_set[i]:
                    dic = (entry[1])
                    search_attr = attr[0]
                    try:
                        result_set_cleaned.append( (dic[search_attr][0],dic[search_attr][0]) )
                    except:
                        pass
        return sorted(result_set_cleaned, key=operator.itemgetter(1))

    def user_ko(self, user_ok):
        user_filter = "(&"
        user_filter += self.user_filter or "(|(objectclass=posixAccount)(objectclass=inetOrgPerson)(objectclass=person))"
        for user in user_ok:
            name = user.user
            user_filter += "(!("+self.user_attr+"="+name.decode('utf-8')+"))"
        user_filter += ")"
        ret = self.search(self.user_ou or self.base_dn, self.user_scope, user_filter, [ str(self.user_attr) ])
        return ret

    def all_groups(self):
        ret = self.search(self.group_ou or self.base_dn, self.group_scope, self.group_filter, [ str(self.group_attr) ])
        return ret

    def group_ko(self, group_ok):
        group_filter = "(&"
        group_filter += self.group_filter or "(|(objectclass=posixGroup)(objectclass=group)(objectclass=groupofuniquenames))"
        for group in group_ok:
            name = group.group
            group_filter += "(!("+self.group_attr+"="+name.decode('utf-8')+"))"
        group_filter += ")"
        ret = self.search(self.group_ou or self.base_dn, self.group_scope, group_filter, [ str(self.group_attr) ])
        return ret

    def modify(self, dn, attrs):
        try:
            l = ldap.open(self.host)
            l.simple_bind_s(self.dn, self.password)
            l.modify_s(dn.encode('utf-8'), attrs)
        except ldap.LDAPError, error_message:
            raise error_message

    def add(self, dn, attrs):
        try:
            l = ldap.open(self.host)
            l.simple_bind_s(self.dn, self.password)
            l.add_s(dn.encode('latin-1'), attrs)
            print "ADD %s" % dn
            print attrs
        except ldap.LDAPError, error_message:
            print error_message

    def member(self, mod_type, group_cn, user_dn):
        try:
            l = ldap.open(self.host)
            l.simple_bind_s(self.dn, self.password)
            dn = self.group_attr + "=" + group_cn + ",ou=" + self.group_ou + "," + self.base_dn
            l.modify_s(dn.encode('utf-8'), [(mod_type, "member", user_dn.encode('utf-8'))])
        except ldap.LDAPError, error_message:
            print error_message

    def delete_user(self, uid):
        try:
            l = ldap.open(self.host)
            l.simple_bind_s(self.dn, self.password)
            l.delete_s("uid="+uid+",ou="+self.user_ou+","+self.base_dn)
        except ldap.LDAPError, error_message:
            print error_message

    def delete_group(self, cn):
        try:
            l = ldap.open(self.host)
            l.simple_bind_s(self.dn, self.password)
            l.delete_s("cn="+cn+",ou="+self.group_ou+","+self.base_dn)
        except ldap.LDAPError, error_message:
            print error_message

    class Meta:
        db_table = 'ldap'
    
    def __str__(self):
        return "%s [LDAP]"%self.host

    def __unicode__(self):
        return str(self)

    def get_absolute_url(self):
        return "/ldap/"

class Logic(models.Model):
    OPERATORS = (
        ('OR','OR'),
        ('AND','AND'),
        )
    name = models.CharField(max_length=128, unique=1)
    op = models.CharField(max_length=3,choices=OPERATORS)
    auths = models.ManyToManyField('Auth',null=False)
    login_auth = models.ForeignKey('Auth',null=False, related_name="login_logic_auth")

    def delete(self,*args,**kwargs):
        auth = Auth.objects.get(id_method=self.pk,auth_type='logic')
        auth.delete()
        super(Logic,self).delete(*args,**kwargs)

    class Meta:
        db_table = 'logic'

    def __str__(self):
        return ("( %s )"%(" %s "%self.op).join(
            [str(a) for a in self.auths.all()]
            ))

    def ssl_auth(self):
        for a in self.auths.all():
            sa = a.ssl_auth()
            if sa:
                return sa
    def get_constraint(self):
        return self.ssl_auth().get_constraint()
    def get_require(self):
        return self.ssl_auth().get_require()
    def get_crt(self):
        return self.ssl_auth().get_crt()

class OTP(models.Model):
    name = models.CharField(max_length=128)
    auth = models.ForeignKey('Auth')
    contact_field = models.CharField(max_length=128)
    script = models.TextField(
            default="/bin/echo __MESSAGE__ | /usr/bin/mail -s 'otp' __CONTACT__"
        )
    passlen = models.IntegerField(default=8)
    template = models.TextField(
        default="OTP pass for __USER__ : __PASS__",
        )
    timeout = models.IntegerField(default=300)

    def delete(self,*args,**kwargs):
        auth = Auth.objects.get(id_method=self.pk,auth_type='otp')
        auth.delete()
        super(OTP,self).delete(*args,**kwargs)

    def __str__(self):
        return "%s [OTP]"%self.name
    class Meta:
        db_table='otp'

class Auth(models.Model):
    TYPES = {
        'sql':SQL,
        'ldap':LDAP,
        'ssl':SSL,
        'ntlm':NTLM,
        'kerberos':Kerberos,
        'cas':CAS,
        'logic':Logic,
        'otp':OTP,
        'radius':RADIUS,
        }
    name = models.CharField(max_length=128)
    auth_type = models.CharField(max_length=20,
        choices=[(k,k) for k in TYPES])
    id_method = models.IntegerField()
    def getAuth(self):
        return Auth.TYPES[self.auth_type].objects.get(pk=self.id_method)

    def ssl_auth(self):
        if self.auth_type == 'ssl':
            return self.getAuth()
        elif self.auth_type =='logic':
            return self.getAuth().ssl_auth()

    def is_ssl(self):
        return self.ssl_auth() and True

    def get_constraint(self):
        return self.ssl_auth().get_constraint()

    def get_require(self):
        return self.ssl_auth().get_require()

    def get_crt(self):
        return self.ssl_auth().get_crt()

    def __str__(self):
        return str(self.getAuth())

    def delete(self,*args,**kwargs):
        for l in Logic.objects.all():
            if l.login_auth.pk==self.pk:
                l.delete()
            else:
                if self in l.auths.all():
                    l.auths.remove(self)
                l.save()
        App.objects.filter(auth=self.pk).update(auth=None)
        Intf.objects.filter(cas_auth=self.pk).update(cas_auth=None)
        super(Auth,self).delete(*args,**kwargs)

    class Meta:
        db_table = 'auth'

class SSO(models.Model):
    SSO_TYPES = (
        ('sso_forward_htaccess', 'sso_forward_htaccess'),
        ('sso_forward', 'sso_forward'),
        )
    ACTIONS = (
        ('nothing', 'nothing'),
        ('log', 'log'),
        ('message', 'message'),
        ('redirect', 'redirect'),
		('relearning' , 'relearning'),
        ('nofollowredirect','nofollowredirect'),
        )
    name = models.CharField(max_length=128, unique=1)
    type = models.CharField(max_length=20, choices=SSO_TYPES, blank=1)
    auth = models.ForeignKey('Auth', null=1, blank=1)
    table_mapped = models.CharField(max_length=128, blank=1, null=1)
    base_dn_mapped = models.CharField(max_length=128, blank=1, null=1)
    user_mapped = models.CharField(max_length=128, blank=1, null=1)
    app_mapped = models.CharField(max_length=128, blank=1, null=1)
    follow_get_redirect = models.BooleanField(default=1)
    is_info = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    is_info_options = models.CharField(max_length=128, blank=1, null=1)
    is_success = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    is_success_options = models.CharField(max_length=128, blank=1)
    is_redirect = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    is_redirect_options = models.CharField(max_length=128, blank=1)
    is_error = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    is_error_options = models.CharField(max_length=128, blank=1, null=1)
    is_in_page = models.CharField(max_length=128, blank=1, null=1)
    is_in_page_action = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    is_in_page_options = models.CharField(max_length=128, blank=1, null=1)
    is_in_url = models.CharField(max_length=128, blank=1, null=1)
    is_in_url_action = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    is_in_url_options = models.CharField(max_length=128, blank=1, null=1)
    is_in_url_redirect = models.CharField(max_length=128, blank=1, null=1)
    is_in_url_redirect_action = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    is_in_url_redirect_options = models.CharField(max_length=128, blank=1, null=1)
    is_post = models.BooleanField(default=0)
    verify_mech_cert = models.BooleanField(default=1)
    def __unicode__(self):
        return self.name
    class Meta:
        db_table='sso'

#Linked to SSO (SSO Forward)
class Field(models.Model):
    HTML_INPUT_TYPES = (
        ('text', 'text'),
        ('hidden', 'hidden'),
        ('password', 'password'),
        ('submit', 'submit'),
        ('checkbox', 'checkbox'),
        ('radio', 'radio'),
        ('button', 'button'),
        ('cookie', 'cookie'),
        ('current user', 'autologon_user'),
        ('current password', 'autologon_password'),
	('script','script'),
	('script-cookie','script-cookie'),
        )
    sso = models.ForeignKey('SSO')
    field_desc = models.CharField(max_length=128)
    field_var = models.CharField(max_length=100)
    field_mapped = models.CharField(max_length=100,null=1, blank=1)
    field_type = models.CharField(max_length=20, choices=HTML_INPUT_TYPES)
    field_encrypted = models.BooleanField()
    field_value = models.CharField(max_length=100,null=1, blank=1)
    field_prefix = models.CharField(max_length=50,null=1, blank=1)
    field_suffix = models.CharField(max_length=50,null=1, blank=1)
    def __str__(self):
        return self.field_desc
    class Meta:
        db_table = 'field'

class App(models.Model):
    SSL_PROXY_VERIFY = (
        ('none', 'none'),
        ('optional', 'optional'),
        ('require', 'require'),
    )
    ACTIONS = (
        ('nothing', 'nothing'),
        ('template', 'template'),
        ('log', 'log'),
        ('message', 'message'),
        ('redirect', 'redirect'),
        ('script', 'script'),
        )
    RESTRICTED_ACTIONS = (
        ('message', 'message'),
        ('redirect', 'redirect'),
        ('script', 'script'),
        )
    MS_ACTIONS = (
        ('Log_Only','Log Only'),
        ('Log_Block','Log And Block'),
        )
    MOTOR = (
        ('Anomaly','Anomaly Scoring Block Mode'),
        ('Traditional','Traditional Block Mode'),
        )
    BALANCER_ALGO = (
        ('byrequests','byrequests'),
        ('bytraffic','bytraffic'),
        ('bybusyness','bybusyness'),
        )
    DEFLATE_LEVEL = (
        (1,'min'),
        (2,'2'),(3,'3'),(4,'4'),(5,'5'),
        (6,'6'),(7,'7'),(8,'8'),(9,'max'),
        )
    DEFLATE_WIN_SIZE = (
        (1,'min'),
        (2,'2'),(3,'3'),(4,'4'),(5,'5'),
        (6,'6'),(7,'7'),(8,'8'),(9,'9'),
        (10,'10'),(11,'11'),(12,'12'),(13,'13'),
        (14,'14'),(15,'max')
        )
    CACHE_TYPE = (
        ('disk','disk'),
        ('mem','mem'),
        )
    name = models.CharField(max_length=128)
    alias = models.CharField(max_length=128, blank=1, null=1)
    url = models.CharField(max_length=256)
    intf = models.ManyToManyField('Intf',db_table='app_intf')
    log = models.ForeignKey('Log')
    security = models.ForeignKey('ModSecConf',null=1,blank=1)
    logon_url = models.CharField(max_length=256,null=1,blank=1)
    logout_url = models.CharField(max_length=256,null=1,blank=1)
    up = models.BooleanField(default=1)
    available = models.BooleanField(default=1)
    remote_proxy = models.URLField(blank=1, null=1, verify_exists=0)
    remote_proxy_SSLProxyMachineCertificateFile = models.CharField(max_length=512, blank=1, null=1)
    remote_proxy_SSLProxyCACertificateFile = models.CharField(max_length=512, blank=1, null=1)
    remote_proxy_SSLProxyCARevocationFile = models.CharField(max_length=512, blank=1, null=1)
    remote_proxy_SSLProxyVerify = models.CharField(max_length=10,blank=1,choices=SSL_PROXY_VERIFY)
    timeout = models.IntegerField(null=1,blank=1)
    auth= models.ForeignKey('Auth',null=1,blank=1)
    auth_url = models.CharField(max_length=256,blank=1)
    auth_basic = models.BooleanField(default=0)
    display_portal = models.BooleanField()
    check_csrf = models.BooleanField(default=True)
    auth_server_failure_action = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    auth_server_failure_options = models.CharField(max_length=128, blank=1, null=1)
    account_locked_action = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    account_locked_options = models.CharField(max_length=128, blank=1, null=1)
    login_failed_action = models.CharField(max_length=128, blank=1, null=1, choices=RESTRICTED_ACTIONS, default='template')
    login_failed_options = models.CharField(max_length=128, blank=1, null=1)
    need_change_pass_action = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    need_change_pass_options = models.CharField(max_length=128, blank=1, null=1)
    acl_failed_action = models.CharField(max_length=128, blank=1, null=1, choices=RESTRICTED_ACTIONS, default='template')
    acl_failed_options = models.CharField(max_length=128, blank=1, null=1)
    acl = models.ForeignKey('ACL',null=1,blank=1)
    rewrite = models.CharField(max_length=100,blank=1)
    proxy_config =  models.CharField(max_length=100,blank=1)
    follow_post = models.CharField(max_length=1,blank=1)
    no_cookie_mode = models.BooleanField(default=0)
    sso_forward = models.ForeignKey('SSO',null=1,blank=1)
    appearance = models.ForeignKey('Appearance', blank=1, null=1)
    canonicalise_url = models.BooleanField(default=1)
    virtualhost_directives = models.TextField(blank=1,null=1)
    timeout = models.IntegerField(null=1,blank=1)
    update_access_time = models.BooleanField(default=0)
    sso_learning_ext = models.CharField(max_length=128,null=1,blank=1)
    secondary_authentification_failure_action = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    secondary_authentification_failure_options = models.CharField(max_length=128, blank=1, null=1)
    Balancer_Activated = models.BooleanField()
    Balancer_Name = models.CharField(max_length=128,blank=1,null=1)
    Balancer_Node = models.TextField(blank=1, null=1)
    Balancer_Algo = models.CharField(max_length=128,choices=BALANCER_ALGO,default='byrequests')
    Balancer_Stickyness = models.CharField(max_length=128,blank=1,null=1)
    deflate_activated = models.BooleanField(default=False)
    deflate_types = models.CharField(max_length=128,blank=1,null=1)
    deflate_buf_size = models.IntegerField(default=8096)
    deflate_compression = models.IntegerField(default=9,
            choices = DEFLATE_LEVEL)
    deflate_memory = models.IntegerField(default=9,
            choices = DEFLATE_LEVEL)
    deflate_win_size = models.IntegerField(default=15,
            choices =DEFLATE_WIN_SIZE)
    cache_activated = models.BooleanField(default=False)
    cache_type = models.CharField(max_length=128, choices=CACHE_TYPE, default='disk')
    cache_disable = models.CharField(max_length=512,blank=1,null=1,default="NULL")
    cache_default_exptime = models.IntegerField(default=3600)
    cache_ignore_cache_control = models.BooleanField(default=False)
    cache_ignore_headers = models.CharField(max_length=128, blank=1, default='')
    cache_ignore_nolastmod = models.BooleanField(default=False)
    cache_ignore_querystring = models.BooleanField(default=False)
    cache_ignore_URLSessionIdentifiers = models.CharField(max_length=512,null=1,blank=1,default='none')
    cache_last_modified_factor = models.FloatField(default=0.1)
    cache_lock = models.BooleanField(default=False)
    cache_lock_maxage = models.IntegerField(default=5)
    cache_lock_path = models.CharField(max_length=128, blank=1,null=1)
    cache_max_expire = models.IntegerField(default=86400)
    cache_store_no_store = models.BooleanField(default=False)
    cache_store_private = models.BooleanField(default=False)
    policy=models.ForeignKey('Politique', blank=True, null=True) 
    proxypass_directives = models.TextField(blank=1,null=1)
    
    def isWildCard (self):
        return self.alias.startswith('*')

    def isFtp (self):
        if self.Balancer_Activated:
            url_ = self.Balancer_Node
        else:
            url_ = self.url
        return url_.lower().startswith('ftp://')

    def hasHeaderHost (self):
        return Header.objects.filter(app = self).filter(name__iexact="Host")

    def hasBlackIp (self):
        return BlackIP.objects.filter(app = self)

    def getJKDirective (self):
        return JKDirective.objects.filter(app=self)

    def getCookieDomain (self):
        p = re.compile ('https?://(.*)/?')
        match=p.match(self.url)
    	if not match:
	        return " "
        domain = match.group(1)
        newdomain = self.name
    	if "/" in newdomain:
            newdomain=newdomain.split("/",1)[0]
        if domain:
            return "ProxyPassReverseCookieDomain "+domain+" "+newdomain
        return " "

    def getCookiePath (self):
        if "/" in self.name:
            path = self.name.split("/",1)[1]
            return "ProxyPassReverseCookiePath / /"+path
        return " "
 
    def __str__(self):
        return self.name# + " : " + ", ".join([i.name for i in self.intf.all()])
    class Meta:
        db_table = 'app'
        permissions = (
            ("reload_app", "Can stop/start application"),
        )

class Plugin(models.Model):
    PLUGIN_TYPES = (
    ('Static', 'Static'),
    ('Rewrite', 'Rewrite'),
    ('SQLPASS', 'Change SQL pass'),
    ('Block', 'Block'),
    ('Logout', 'Logout'),
    ('Logout_ALL', 'Logout_ALL'),
    ('Logout_ALL2', 'Logout_ALL2'),
    ('Logout_BROWSER', 'Logout_BROWSER'),
    ('CAS','CAS'),
    ('REDIRECT_NO_LOG','REDIRECT_NO_LOG'),
    ('REDIRECT_IF_REFERER','REDIRECT_IF_REFERER'),
    ('REDIRECT_NO_REFERER','REDIRECT_NO_REFERER'),
    )
    app = models.ForeignKey(App,null=1,blank=1)
    uri_pattern = models.CharField(max_length=200)
    type = models.CharField(max_length=20, choices=PLUGIN_TYPES)
    options = models.CharField(max_length=200, null=1, blank=1)
    def __str__(self):
        return self.type + ' - ' + self.uri_pattern
    class Meta:
        db_table = 'plugin'

class BlackIP(models.Model):
    app = models.ForeignKey(App,unique=1,null=1,blank=1)
    ip = models.CharField(max_length=200, null=1, blank=1)
    def __str__(self):
        return self.ip
    class Meta:
        db_table = 'blackip'

class Header(models.Model):
    HEADER_TYPE = (
    ('CUSTOM', 'CUSTOM'),
    ('CUSTOM-CONCAT','CUSTOM-CONCAT'),
    ('REMOTE_ADDR', 'REMOTE_ADDR'),
    ('SSL_CLIENT_I_DN', 'SSL_CLIENT_I_DN'),
    ('SSL_CLIENT_M_SERIAL', 'SSL_CLIENT_M_SERIAL'),
    ('SSL_CLIENT_S_DN', 'SSL_CLIENT_S_DN'),
    ('SSL_CLIENT_V_START', 'SSL_CLIENT_V_START'),
    ('SSL_CLIENT_V_END', 'SSL_CLIENT_V_END'),
    ('SSL_CLIENT_S_DN_C', 'SSL_CLIENT_S_DN_C'),
    ('SSL_CLIENT_S_DN_ST', 'SSL_CLIENT_S_DN_ST'),
    ('SSL_CLIENT_S_DN_Email', 'SSL_CLIENT_S_DN_Email'),
    ('SSL_CLIENT_S_DN_L', 'SSL_CLIENT_S_DN_L'),
    ('SSL_CLIENT_S_DN_O', 'SSL_CLIENT_S_DN_O'),
    ('SSL_CLIENT_S_DN_OU', 'SSL_CLIENT_S_DN_OU'),
    ('SSL_CLIENT_S_DN_CN', 'SSL_CLIENT_S_DN_CN'),
    ('SSL_CLIENT_S_DN_T', 'SSL_CLIENT_S_DN_T'),
    ('SSL_CLIENT_S_DN_I', 'SSL_CLIENT_S_DN_I'),
    ('SSL_CLIENT_S_DN_G', 'SSL_CLIENT_S_DN_G'),
    ('SSL_CLIENT_S_DN_S', 'SSL_CLIENT_S_DN_S'),
    ('SSL_CLIENT_S_DN_D', 'SSL_CLIENT_S_DN_D'),
    ('SSL_CLIENT_S_DN_UID', 'SSL_CLIENT_S_DN_UID'),
    )
    name = models.CharField(max_length=128)
    type = models.CharField(max_length=20,choices=HEADER_TYPE)
    value = models.CharField(max_length=128,blank=1)
    app = models.ForeignKey('App')
    def __str__(self):
        return self.name
    class Meta:
        db_table = 'header'

class CSS(models.Model):
    name = models.CharField(max_length=128, unique=1)
    value = models.TextField()
    
    def __unicode__(self):
        return self.name

    class Meta:
        db_table = 'style_css'

class Template(models.Model):
    TEMPLATE_TYPES = (
        ('DOWN', 'App Down'),
        ('LOGIN','Login'),
        ('ACL','ACL'),
        ('PORTAL','Portal'),
        ('LEARNING', 'Learning'),
        ('LOGOUT', 'Logout'),
        ('SSO_LOGIN', 'SSO Login'),
        )
    name = models.CharField(max_length=128,unique=1)    
    type = models.CharField(max_length=50, choices=TEMPLATE_TYPES)
    head = models.TextField(blank=1)
    value = models.TextField()
    
    def __unicode__(self):
        return self.name

    class Meta:
        db_table = 'style_tpl'

class Image(models.Model):
    name = models.CharField(max_length=128,unique=1)
    image = models.ImageField(upload_to='img/')
    
    def __unicode__(self):
        return self.name

    class Meta:
        db_table = 'style_image'

class Localization(models.Model):
    COUNTRY_CHOICES = (
        ('en','English'),
        ('fr','Fran??ais'),
        ('de','Deutch'),
        ('es','Espanol'),
        ('it','Italiano'),
        ('pt','Portuguese'),
        ('nl','Dutch'),
        )
    ERRORS_CHOICES = (
        ('USER', 'User'),
        ('PASSWORD', 'Password'),
        ('LOGIN_FAILED','Login failed'),
        ('MISSING_USER','Missing login'),
        ('MISSING_PASSWORD','Missing password'),
        ('NEED_CHANGE_PASS','Need change pass'),
        ('AUTH_SERVER_FAILURE', 'Authentication server failure'),
        ('ACCOUNT_LOCKED', 'Account locked'),
        ('ACL_FAILED','ACL failed'),
        ('APPLICATION', 'Application'),
        ('APP_DOWN', 'App down'),
        ('SSO_LEARNING', 'SSO Learning'),
        ('SSO_LOGIN', 'SSO Login'),
        ('DISCONNECTED', 'Disconnected'),
        ('SUBMIT', 'Submit'),
        ('PENDING_LOGIN','Unfinished login'),
        )
    country = models.CharField(max_length=2, choices=COUNTRY_CHOICES)
    message = models.CharField(max_length=50, choices=ERRORS_CHOICES)
    translation = models.CharField(max_length=128)

    def __unicode__(self):
        return self.country+' - '+self.message
    class Meta:
        db_table = 'localization'

class Appearance(models.Model):
    name = models.CharField(max_length=128,unique=1)
    css = models.ForeignKey('CSS',blank=1,null=1)
    app_down_tpl = models.ForeignKey('Template', related_name='app_down_tpl', blank=1, null=1, limit_choices_to = {'type__exact' : 'DOWN'})
    login_tpl = models.ForeignKey('Template', related_name='login_tpl', limit_choices_to = {'type__exact' : 'LOGIN'})
    acl_tpl = models.ForeignKey('Template', related_name='acl_tpl', blank=1, null=1, limit_choices_to = {'type__exact' : 'ACL'})
    sso_portal_tpl = models.ForeignKey('Template', related_name='sso_portal_tpl', blank=1, null=1, limit_choices_to = {'type__exact' : 'PORTAL'})
    sso_learning_tpl = models.ForeignKey('Template', related_name='sso_learning_tpl', blank=1, null=1, limit_choices_to = {'type__exact' : 'LEARNING'})
    logout_tpl = models.ForeignKey('Template', related_name='logout_tpl', blank=1, null=1, limit_choices_to = {'type__exact' : 'LOGOUT'})
    sso_login_tpl = models.ForeignKey('Template', related_name='sso_login_tpl', blank=1, null=1, limit_choices_to = {'type__exact' : 'SSO_LOGIN'})
    image = models.ForeignKey('Image',blank=1,null=1)
    
    def __str__(self):
        return self.name

    class Meta:
        db_table = 'style_style'

class Plugincontent(models.Model):
    PLUGIN_TYPES = (
    ('Header Add', 'Header Add'),
    ('Header Modify', 'Header Modify'),
    ('Header Replacement', 'Header Replacement'),
    ('Mime Forbidden', 'Mime Forbidden'),
    ('Header Unset','Header Unset'),
    ('Rewrite Content','Rewrite Content'),
    ('Rewrite Link','Rewrite Link'),
    )
    app = models.ForeignKey(App,null=1,blank=1)
    pattern = models.CharField(max_length=200)
    type = models.CharField(max_length=20, choices=PLUGIN_TYPES)
    options = models.CharField(max_length=200, null=1, blank=1)
    options1 = models.CharField(max_length=200, null=1, blank=1)
    def __str__(self):
        return self.type + ' - ' + self.pattern
    class Meta:
        db_table = 'plugincontent'

class Pluginheader(models.Model):
    PLUGIN_TYPES = (
    ('Header Modify', 'Header Modify'),
    ('Header Replacement', 'Header Replacement'),
    ('Header Unset','Header Unset'),
    ('Header Concat','Header Concat'),
    )
    app = models.ForeignKey(App,null=1,blank=1)
    pattern = models.CharField(max_length=200)
    type = models.CharField(max_length=20, choices=PLUGIN_TYPES)
    options = models.CharField(max_length=200, null=1, blank=1)
    options1 = models.CharField(max_length=200, null=1, blank=1)
    def __str__(self):
        return self.type + ' - ' + self.pattern
    class Meta:
        db_table = 'pluginheader'

class JKWorkerProp(models.Model):
    WORKER_PROPS = (
        ('type', 'type'),
        ('host', 'host'),
        ('port', 'port'),
        ('socket_timeout','socket_timeout'),
        ('socket_connect_timeout','socket_connect_timeout'),
        ('socket_keepalive','socket_keepalive'),
        ('ping_mode','ping_mode'),
        ('ping_timeout','ping_timeout'),
        ('connection_ping_interval','connection_ping_interval'),
        ('connection_pool_size','connection_pool_size'),
        ('connection_pool_minsize','connection_pool_minsize'),
        ('connection_pool_timeout','connection_pool_timeout'),
        ('connection_acquire_timeout','connection_acquire_timeout'),
        ('lbfactor','lbfactor'),
        ('balance_workers','balance_workers'),
        ('sticky_session','sticky_session'),
        ('sticky_session_force','sticky_session_force'),
        ('method','method'),
        ('lock','lock'),
        ('retries','retries'),
        ('css','css'),
        ('read_only','read_only'),
        ('user','user'),
        ('user_case_insensitive','use_case_insensitive'),
        ('good','good'),
        ('bad','bad'),
        ('prefix','prefix'),
        ('ns','ns'),
        ('xmlns','xmlns'),
        ('doctype','doctype'),
        ('connect_timeout','connect_timeout'),
        ('prepost_timeout','prepost_timeout'),
        ('reply_timeout','reply_timeout'),
        ('retries','retries'),
        ('retry_interval','retry_interval'),
        ('recover_options','recover_options'),
        ('fail_on_status','fail_on_status'),
        ('max_packet_size','max_packet_size'),
        ('mount','mount'),
        ('secret','secret'),
        ('max_reply_timeout','max_reply_timeout'),
        ('recover_time','recover_time'),
        ('error_escalation_time','error_escalation_time'),
        ('activation','activation'),
        ('route','route'),
        ('distance','distance'),
        ('domain','domain'),
        ('redirect','redirect'),
        ('session_cookie','session_cookie'),
        ('session_path','session_path'),
    )
    prop = models.CharField(max_length=128, choices=WORKER_PROPS)
    value = models.CharField(max_length=128)
    worker = models.ForeignKey('JKWorker')
    def __str__(self):
        return "%s.%s=%s"%(str(self.worker),self.prop,self.value)
    class Meta:
        db_table="jk_worker_prop"

class JKWorker(models.Model):
    name = models.CharField(max_length=128,blank=0,null=0,unique=1)
    reference = models.ForeignKey('JKWorker',blank=1,null=1)
    is_template = models.BooleanField(default=False)
    @staticmethod
    def genConf():
        sconf = "worker.list=%s\n\n"%", ".join(
            [j.name for j in JKWorker.objects.filter(is_template=False)]
        )
        return sconf + "\n\n".join(
            [w.getConf() for w in JKWorker.objects.all()]
        )
    def getConf(self):
        mconf = ''
        if self.reference :
            mconf = "%s.reference=%s\n"%(str(self),str(self.reference))
        return mconf + "\n".join(
            [str(p) for p in JKWorkerProp.objects.filter(worker=self)]
        )
    def __str__(self):
        return "worker.%s"%self.name
    class Meta:
        db_table = 'jk_worker'

class JKDirective(models.Model):
    JK_DIRECTIVES = (
        ('JkMount','JkMount'),
        ('JkUnMount','JkUnmount')
    )
    directive = models.CharField(max_length=128,null=0,choices=JK_DIRECTIVES)
    worker = models.ForeignKey('JKWorker',null=0)
    url = models.CharField(max_length=128,null=0,blank=0)
    app = models.ForeignKey('App',null=0)
    def __str__(self):
        if self.directive == 'JkUnMount':
            return "#unmount jk server and setting env variable no-jk to explicitly remove this url when calling jakarta-servlet handler\n%s %s %s\nSetEnvIf REQUEST_URI %s no-jk"%(self.directive,self.url,self.worker.name,self.url)
        else:
            return "%s %s %s"%(self.directive,self.url,self.worker.name)
    class Meta:
        db_table='jk_worker_directives'



class ModSecConf(models.Model):
    SSL_PROXY_VERIFY = (
        ('none', 'none'),
        ('optional', 'optional'),
        ('require', 'require'),
    )
    ACTIONS = (
        ('nothing', 'nothing'),
        ('template', 'template'),
        ('log', 'log'),
        ('message', 'message'),
        ('redirect', 'redirect'),
        ('script', 'script'),
        )
    RESTRICTED_ACTIONS = (
        ('message', 'message'),
        ('redirect', 'redirect'),
        ('script', 'script'),
        )
    MS_ACTIONS = (
        ('Log_Only','Log Only'),
        ('Log_Block','Log And Block'),
        )
    MOTOR = (
        ('Anomaly','Anomaly Scoring Block Mode'),
        ('Traditional','Traditional Block Mode'),
        )
    BALANCER_ALGO = (
        ('byrequests','byrequests'),
        ('bytraffic','bytraffic'),
        ('bybusyness','bybusyness'),
        )
    DEFLATE_LEVEL = (
        (1,'min'),
        (2,'2'),(3,'3'),(4,'4'),(5,'5'),
        (6,'6'),(7,'7'),(8,'8'),(9,'max'),
        )
    DEFLATE_WIN_SIZE = (
        (1,'min'),
        (2,'2'),(3,'3'),(4,'4'),(5,'5'),
        (6,'6'),(7,'7'),(8,'8'),(9,'9'),
        (10,'10'),(11,'11'),(12,'12'),(13,'13'),
        (14,'14'),(15,'max')
        )
    CACHE_TYPE = (
        ('disk','disk'),
        ('mem','mem'),
        )
    
    name = models.CharField(max_length=128, blank=False, null=False)
    action = models.CharField(max_length=128, choices=MS_ACTIONS, default='Log_Block')
    allowed_content_type = models.TextField(blank=1, null=1,default='application/x-www-form-urlencoded multipart/form-data text/xml application/xml application/x-amf')
    allowed_http = models.TextField(blank=1, null=1,default='GET HEAD POST OPTIONS')
    allowed_http_version = models.TextField(blank=1, null=1,default='HTTP/1.0 HTTP/1.1')
    arg_length = models.CharField(max_length=128,blank=1, null=1)
    arg_name_length = models.CharField(max_length=128,blank=1, null=1)
    BodyAccess = models.BooleanField()
    BT_activated = models.BooleanField()
    BT_block_timeout = models.CharField(max_length=128,blank=1, null=1,default=600)
    BT_burst_time_slice = models.CharField(max_length=128,blank=1, null=1,default=60)
    BT_counter_threshold = models.CharField(max_length=128,blank=1, null=1,default=100)
    cache_max_file_size = models.IntegerField(default=1000000)
    combined_file_size = models.CharField(max_length=128,blank=1, null=1)
    critical_score = models.CharField(max_length=128,blank=1, null=1, default=5)
    Custom = models.TextField(blank=1, null=1)
    DoS_activated = models.BooleanField()
    DoS_block_timeout = models.CharField(max_length=128,blank=1, null=1,default=600)
    DoS_burst_time_slice = models.CharField(max_length=128,blank=1, null=1,default=60)
    DoS_counter_threshold = models.CharField(max_length=128,blank=1, null=1,default=100)
    inbound_score = models.CharField(max_length=128,blank=1, null=1,default=5)
    max_file_size = models.CharField(max_length=128,blank=1, null=1)
    max_num_args = models.CharField(max_length=128,blank=1, null=1)
    motor = models.CharField(max_length=128, choices=MOTOR, default='Anomaly')
    notice_score = models.CharField(max_length=128,blank=1, null=1,default=2)
    outbound_score = models.CharField(max_length=128,blank=1, null=1,default=4)
    paranoid = models.BooleanField()
    protected_urls = models.CharField(max_length=128,blank=1, null=1)
    restricted_extensions = models.TextField(blank=1, null=1)
    restricted_headers = models.TextField(blank=1, null=1)
    total_arg_length = models.CharField(max_length=128,blank=1, null=1)
    UTF = models.BooleanField()
    warning_score = models.CharField(max_length=128,blank=1, null=1,default=3)
    
    def to_file(self):
        t = get_template("mod_secu.conf")
        return t.render(Context({'conf':self}))
    
    def get_conf_path(self):
        return "%ssecurity-rules/%s.conf"%(settings.CONF_PATH, self.name.replace(" ","_").lower())

    def is_uptodate(self):
        if os.path.exists(self.get_conf_path()):
            f=open(self.get_conf_path(),"r")
            content=f.read()
            f.close()
            return content == self.to_file()
        return False

    def deploy(self):
        if not self.is_uptodate():
            f=open(self.get_conf_path(),"w")
            f.write(self.to_file())
            f.close()
        return True 

    def __str__(self):
        return self.name
    class Meta:
        db_table = 'modsecuconf'

class AdminStyle(models.Model):
    name = models.CharField(max_length=255,null=0,blank=0)
    style = models.TextField(blank=0,null=0)
    class Meta:
        db_table = 'adminstyle'
    def __unicode__(self):
        return self.name

class UserProfile(models.Model):
    user=models.OneToOneField(DjangoUser)
    style=models.ForeignKey('AdminStyle', null=1)
    class Meta:
        db_table = 'user_profile'
    def __unicode__(self):
        return self.user

def create_user_profile(sender, instance, created, **kwargs):  
    if created:  
        profile, created = UserProfile.objects.get_or_create(user=instance)  
post_save.connect(create_user_profile, sender=DjangoUser) 
