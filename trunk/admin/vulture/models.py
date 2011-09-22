# -*- coding: utf-8 -*-
from django.template.loader import get_template
from django.template import Context
from django.conf import settings
from django.db import models
from django.contrib import admin
from time import sleep
import time
import sqlite3
from datetime import date
import string
import ldap
import ldap.modlist as modlist
import operator
import datetime, os, time
import smtplib
import os
import re
from random import choice
from django.utils.translation import ugettext_lazy as _
from re import escape
import types
from OpenSSL import crypto
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders
from django.contrib.auth.models import User as DjangoUser
from django import forms
import base64

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
    name = models.CharField(max_length=200, unique=1)
    level = models.CharField(max_length=10, blank=1,choices=LOG_LEVELS)
    format = models.CharField(max_length=500, blank=1)
    dir = models.CharField(max_length=200)
    def __str__(self):
        return self.name
    class Meta:
        db_table = 'log'
    def get_absolute_url(self):
        return "/log/"

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
    SSL_PROXY_VERIFY = (
        ('none', 'none'),
        ('optional', 'optional'),
        ('require', 'require'),
    )
    desc = models.CharField(max_length=128, unique=1)
    ip = models.IPAddressField()
    port = models.IntegerField()
    ssl_engine = models.CharField(max_length=10,blank=1,choices=SSL_ENGINES)
    log = models.ForeignKey(Log)
    sso_portal = models.CharField(max_length=256,blank=1,null=1)    
    style = models.ForeignKey('Style', blank=1, null=1)
    remote_proxy = models.URLField(blank=1, null=1, verify_exists=0)
    remote_proxy_SSLProxyMachineCertificateFile = models.CharField(max_length=500, blank=1, null=1)
    remote_proxy_SSLProxyCACertificateFile = models.CharField(max_length=500, blank=1, null=1)
    remote_proxy_SSLProxyCARevocationFile = models.CharField(max_length=500, blank=1, null=1)
    remote_proxy_SSLProxyVerify = models.CharField(max_length=10,blank=1,choices=SSL_PROXY_VERIFY)
    
    cert = models.TextField(blank=1,null=1)
    key = models.TextField(blank=1,null=1)
    ca = models.TextField(blank=1,null=1)

    def get_absolute_url(self):
        return "/intf/"

    def __str__(self):
        return self.desc

    def conf(self):
        t = get_template("vulture_httpd.conf")
        c = Context({"VultureID" : self.id,
                     "VulturePath" : settings.VULTURE_PATH,
                     "VultureConfPath" : settings.CONF_PATH,
                     "VultureWWWPath" : settings.WWW_PATH,
                     "VultureStaticPath" : settings.MEDIA_ROOT,
                     "PerlSwitches" : settings.PERL_SWITCHES,
                     "dbname" : settings.DATABASE_NAME,
                     "app_list" : App.objects.filter(intf=self.id),
                     "ip" : self.ip,
                     "log" : self.log,
                     "port" : self.port,
                     "ssl" : self.cert,
                     "ssl_engine" : self.ssl_engine,
                     "remote_proxy" : self.remote_proxy,
		     "remote_proxy_SSLProxyMachineCertificateFile" : self.remote_proxy_SSLProxyMachineCertificateFile,
		     "remote_proxy_SSLProxyCACertificateFile" : self.remote_proxy_SSLProxyCACertificateFile,
		     "remote_proxy_SSLProxyCARevocationFile" : self.remote_proxy_SSLProxyCARevocationFile,
   		     "remote_proxy_SSLProxyVerify" : self.remote_proxy_SSLProxyVerify,
                     "sso_portal" : self.sso_portal,
                     })
        return t.render(c)

    def write(self):
        f=open("%s/%s.conf" % (settings.CONF_PATH, self.id), 'w')
        f.write(self.conf())
        f.close()
        if self.cert:
            f=open("%s/%s.crt" % (settings.CONF_PATH, self.id), 'w')
            f.write(self.cert)
            f.close()
        if self.key:
            f=open("%s/%s.key" % (settings.CONF_PATH, self.id), 'w')
            f.write(self.key)
            f.close()
        if self.ca:
            f=open("%s/%s.chain" % (settings.CONF_PATH, self.id), 'w')
            f.write(self.ca)
            f.close()
	for app in App.objects.filter(intf=self.id).all():
	    auth_list=app.auth.all()
	    for auth in auth_list:
	        if auth.auth_type == 'ssl':
	            f=open("%s/%s.ca" % (settings.CONF_PATH, str(self.id)+'-'+app.name), 'w')
                    f.write(auth.getAuth().crt)
                    f.close()

    def checkIfEqual(self):
        try:
            f=open("%s/%s.conf" % (settings.CONF_PATH, self.id), 'r')
            content=f.read()
            content2 = self.conf()
        except:
            return False
        return (content == content2)
            
    def pid(self):
        try:
            pid = string.strip((open("%s/%s.pid" % (settings.CONF_PATH, self.id), 'r').read()))
        except:
            return None
        pidof = str(os.popen("pidof %s" % settings.HTTPD_PATH).read()).split()
        if len(pidof) and pid not in pidof:
            return None
        return pid

    def need_restart(self):
        try:
            f=open("%s/%s.conf" % (settings.CONF_PATH, self.id), 'r')
        except:
            return True
        if f.read() != self.conf() :
            return True
        if self.ca:
	        try:
	            f=open("%s/%s.chain" % (settings.CONF_PATH, self.id), 'r')
	        except:
	            return True
	        if f.read() != self.ca :
	            return True
        if self.cert:
	        try:
	            f=open("%s/%s.crt" % (settings.CONF_PATH, self.id), 'r')
	        except:
	            return True
	        if f.read() != self.cert :
	            return True
        if self.key:
	        try:
	            f=open("%s/%s.key" % (settings.CONF_PATH, self.id), 'r')
	        except:
	            return True
	        if f.read() != self.key :
	            return True
	for app in App.objects.filter(intf=self.id).all():
            auth_list=app.auth.all()
            for auth in auth_list:
                if auth.auth_type == 'ssl':
		    try:
                        f=open("%s/%s.ca" % (settings.CONF_PATH, str(self.id)+'-'+app.name), 'r')
	            except:
	                return True
	            if f.read() != auth.getAuth().crt :
	                return True
        f.close()
    
    def k(self, cmd):
        return os.popen("%s -f %s/%s.conf -k %s 2>&1" % (settings.HTTPD_PATH, settings.CONF_PATH, self.id, cmd)).read()

    class Meta:
        db_table = 'intf'

class Auth(models.Model):
    name = models.TextField()
    auth_type = models.CharField(max_length=20)
    id_method = models.IntegerField()
    def getAuth(self):
        if self.auth_type == 'sql':
            return SQL.objects.get(id=self.id_method)
        elif self.auth_type == 'ldap':
            return LDAP.objects.get(id=self.id_method)
        elif self.auth_type == 'ssl':
            return SSL.objects.get(id=self.id_method)
        elif self.auth_type == 'ntlm':
            return NTLM.objects.get(id=self.id_method)
        elif self.auth_type == 'kerberos':
            return Kerberos.objects.get(id=self.id_method)
        else:
            return None
    def is_ssl(self):
	if self.auth_type == 'ssl':
		return True
	return False
    class Meta:
        db_table = 'auth'
    def __unicode__(self):
            return self.name

class ACL(models.Model):
    name = models.CharField(max_length=20)
    auth = models.ForeignKey(Auth)
    users_ok = models.ManyToManyField('UserOK',null=1,blank=1,db_table='acl_userok')
    groups_ok = models.ManyToManyField('GroupOK',null=1,blank=1,db_table='acl_groupok') 
    def __unicode__(self):
            return self.name    
    def get_absolute_url(self):
        return "/acl/"
    class Meta:
        db_table = 'acl'

class UserOK(models.Model):
    user = models.CharField(max_length=100,unique=1)
    def __unicode__(self):
        return self.user
    class Meta:
        db_table = 'userok'

class Conf(models.Model):
    var = models.TextField(unique=1)
    value = models.TextField(null=1)
    class Meta:
        db_table = 'conf'

class GroupOK(models.Model):
    group = models.CharField(max_length=100,unique=1)
    def __unicode__(self):
        return self.group
    class Meta:
        db_table = 'groupok'

class SQL(models.Model):
    SQL_DRIVERS = (
        ('SQLite', 'SQLite'),
        ('Pg', 'PostgreSQL'),
        )
    SQL_ALGOS = (
        ('plain', 'plain'),
        ('md5', 'md5'),
        ('sha1', 'sha1'),
        ('crypt', 'crypt'),
        )
    name = models.CharField(max_length=128)
    driver = models.CharField(max_length=10,choices=SQL_DRIVERS)
    database = models.CharField(max_length=128)
    user = models.CharField(max_length=100, blank=1)
    password = models.CharField(max_length=100, blank=1)
    host = models.CharField(max_length=128, blank=1)
    port = models.IntegerField(null=1, blank=1)
    table = models.CharField(max_length=100)
    user_column = models.CharField(max_length=50)
    pass_column = models.CharField(max_length=50)
    pass_algo = models.CharField(max_length=10,choices=SQL_ALGOS)
    def user_ko(self, user_ok):
        user_ko = []
        if self.driver == 'SQLite':
            con = sqlite3.connect(self.database)
            cur = con.cursor()
            query = "select %s from %s" % (self.user_column, self.table)
            sep = " WHERE "
            for user in user_ok:
                query += sep + "%s != '%s'" % (self.user_column, user.user)
                sep = " AND "
            print query
            cur.execute(query)
            for user in cur:
                user_ko.append(('%s' % user, '%s' % user))
        return user_ko
    def get_absolute_url(self):
        return "/sql/"
    class Meta:
        db_table = 'sql'

class Kerberos(models.Model):
    name = models.CharField(max_length=128,unique=1)
    realm = models.CharField(max_length=256)

    def get_absolute_url(self):
        return "/kerberos/"
    class Meta:
        db_table = 'kerberos'

class ModSecurity(models.Model):
    name = models.CharField(max_length=200,unique=1)
    rules = models.TextField()
    def get_absolute_url(self):
        return "/security/"
    def __unicode__(self):
        return self.name
    class Meta:
        db_table = 'modsecurity'

class SSO(models.Model):
    SSO_TYPES = (
        ('sso_forward_htaccess', 'sso_forward_htaccess'),
        ('sso_forward', 'sso_forward'),
        )
    desc = models.CharField(max_length=128)
    type = models.CharField(max_length=20, choices=SSO_TYPES, blank=1)
    auth = models.ForeignKey(Auth, blank=1, null=1)
    table_mapped = models.CharField(max_length=128, blank=1, null=1)
    base_dn_mapped = models.CharField(max_length=128, blank=1, null=1)
    user_mapped = models.CharField(max_length=128, blank=1, null=1)
    app_mapped = models.CharField(max_length=128, blank=1, null=1)
    def __unicode__(self):
        return self.desc
    class Meta:
        db_table='sso'

#Linked to SSO (SSO Forward)
class Post(models.Model):
    HTML_INPUT_TYPES = (
        ('text', 'text'),
        ('hidden', 'hidden'),
        ('password', 'password'),
        ('submit', 'submit'),
        ('checkbox', 'checkbox'),
        ('radio', 'radio'),
        ('button', 'button'),
        ('current user', 'autologon_user'),
        ('current password', 'autologon_password'),
        )
    sso = models.ForeignKey(SSO)
    field_desc = models.CharField(max_length=128)
    field_var = models.CharField(max_length=100)
    field_mapped = models.CharField(max_length=100,null=1, blank=1)
    field_type = models.CharField(max_length=20, choices=HTML_INPUT_TYPES)
    field_encrypted = models.BooleanField()
    field_value = models.CharField(max_length=100,null=1, blank=1)
    field_prefix = models.CharField(max_length=50,null=1, blank=1)
    field_suffix = models.CharField(max_length=50,null=1, blank=1)
    class Meta:
        db_table = 'post'

class Profile(models.Model):
    app = models.ForeignKey('App')
    user = models.TextField()
    login = models.CharField(max_length=50,null=1)
    password = models.CharField(max_length=100,null=1, blank=1)
    class Meta:
        db_table = 'profile'

class App(models.Model):
    name = models.CharField(max_length=100,unique=1)
    desc = models.CharField(max_length=128,blank=1)
    url = models.CharField(max_length=255)
    intf = models.ForeignKey(Intf)
    alias = models.CharField(max_length=150,blank=1)
    log = models.ForeignKey(Log)
    security = models.ManyToManyField(ModSecurity,null=1,blank=1,db_table='app_security')
    logon_url = models.CharField(max_length=150,null=1,blank=1)
    logout_url = models.CharField(max_length=150,null=1,blank=1)
    up = models.BooleanField(default=1)
    timeout = models.IntegerField(null=1,blank=1)
    auth= models.ManyToManyField(Auth,null=1,blank=1,db_table='auth_multiple')
    auth_basic = models.BooleanField(default=0)
    acl = models.ForeignKey(ACL,null=1,blank=1)
    rewrite = models.CharField(max_length=100,blank=1)
    proxy_config =  models.CharField(max_length=100,blank=1)
    virtualhost_config =   models.CharField(max_length=100,blank=1)
    follow_post = models.CharField(max_length=1,blank=1)
    no_cookie_mode = models.BooleanField(default=0)
    display_portal = models.BooleanField()
    sso_forward = models.ForeignKey(SSO,null=1,blank=1)
    style = models.ForeignKey('Style',blank=1,null=1)
    canonicalise_url = models.BooleanField(default=1)
    virtualhost_directives = models.TextField(blank=1,null=1)
    timeout = models.IntegerField(null=1,blank=1)
    update_access_time = models.BooleanField(default=0)
    def __str__(self):
        return self.name
    def get_absolute_url(self):
        return "/app/"
    def getCookieDomain (self):
        p = re.compile ('https?://(.*)/')
	domain=p.findall(self.url)
	if domain:
           return "ProxyPassReverseCookieDomain "+domain+" "+self.name
        return " "

    class Meta:
        db_table = 'app'

class MapURI(models.Model):
    PLUGIN_TYPES = (
	('Static', 'Static'),
        ('Rewrite', 'Rewrite'),
	('Block', 'Block'),
        )
    app = models.ForeignKey(App,null=1,blank=1)
    uri_pattern = models.CharField(max_length=200)
    type = models.CharField(max_length=20, choices=PLUGIN_TYPES)
    options = models.CharField(max_length=200, null=1, blank=1)
    class Meta:
        db_table = 'map_uri'

class BlackIP(models.Model):
    app = models.ForeignKey(App)
    ip = models.IPAddressField()
    class Meta:
        db_table = 'blackip'

class UserOK(models.Model):
    acl = models.ForeignKey(ACL)
    user = models.CharField(max_length=20,unique=1)
    class Meta:
        db_table = 'userok'
		
class GroupOK(models.Model):
    acl = models.ForeignKey(ACL)
    group = models.CharField(max_length=20,unique=1)
    class Meta:
        db_table = 'groupok'
		
class SSL(models.Model):
    SSL_REQUIRE = (
        ('optional', 'optional'),
        ('require', 'require'),
        )
    name = models.CharField(max_length=100,unique=1)
    require = models.CharField(max_length=20, choices=SSL_REQUIRE)
    crt = models.TextField()
    constraint = models.TextField()
    def get_absolute_url(self):
        return "/ssl/"
    class Meta:
        db_table = 'ssl'

class NTLM(models.Model):
    name = models.CharField(max_length=100,unique=1)
    domain = models.CharField(max_length=100)
    primary_dc = models.CharField(max_length=100)
    secondary_dc = models.CharField(max_length=100, blank=1, null=1)
    def get_absolute_url(self):
        return "/ntlm/"
    class Meta:
        db_table = 'ntlm'

class RADIUS(models.Model):
    name = models.CharField(max_length=128)
    host = models.CharField(max_length=100)
    port = models.IntegerField()
    secret = models.CharField(max_length=50)
    timeout = models.IntegerField()
    #one_time_password = models.BooleanField()
    def get_absolute_url(self):
        return "/radius/"
    class Meta:
        db_table = 'radius'

class Header(models.Model):
    HEADER_TYPE = (
    ('CUSTOM', 'CUSTOM'),
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
    name = models.CharField(max_length=20,unique=1)
    type = models.CharField(max_length=20,choices=HEADER_TYPE)
    value = models.CharField(max_length=30,blank=1)
    app = models.ForeignKey(App)
    class Meta:
        db_table = 'header'

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
        name = models.CharField(max_length=128)
        host = models.CharField(max_length=100)
        port = models.IntegerField()
        protocol = models.CharField(max_length=1,choices=LDAP_VERSIONS, default="3")
        scheme = models.CharField(max_length=10,choices=LDAP_ENC_SCHEMES, default="none")
        cacert_path = models.CharField(max_length=20, blank=1, null=1)
        base_dn = models.CharField(max_length=50)
        dn = models.CharField(max_length=50)
        password = models.CharField(max_length=50)
        user_ou = models.CharField(max_length=100, blank=1, null=1)
        user_attr = models.CharField(max_length=20)
        user_scope = models.IntegerField(choices=LDAP_SCOPE)
        user_filter = models.CharField(max_length=100, blank=1, null=1)
        group_ou = models.CharField(max_length=100, blank=1, null=1)
        group_attr = models.CharField(max_length=50)
        group_scope = models.IntegerField(choices=LDAP_SCOPE)
        group_filter = models.CharField(max_length=100, blank=1, null=1)
        group_member = models.CharField(max_length=20, blank=1, null=1)
        are_members_dn = models.BooleanField()
        url_attr = models.CharField(max_length=20, blank=1)
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
            user_filter = "(&"+self.user_filter
            for user in user_ok:
                name = user.user
                user_filter += "(!("+self.user_attr+"="+name.decode('utf-8')+"))"
            user_filter += "(|(objectclass=posixAccount)(objectclass=inetOrgPerson)(objectclass=person)))"
            ret = self.search(self.base_dn, self.user_scope, user_filter, [ str(self.user_attr) ])
            return ret
    
        def group_ok(self, dn):
            group_filter = "(&"+self.group_filter+"(member="+dn+"))"
            ret = self.search(self.base_dn, self.group_scope, group_filter, [ str(self.group_attr) ])
            return ret
    
        def all_groups(self):
             ret = self.search(self.base_dn, self.group_scope, self.group_filter, [ str(self.group_attr) ])
             return ret
    
        def group_ko(self, group_ok):
            group_filter = "(&"+self.group_filter
            for group in group_ok:
                name = group.group
                group_filter += "(!("+self.group_attr+"="+name.decode('utf-8')+"))"
            group_filter += ")"
            ret = self.search(self.base_dn, self.group_scope, group_filter, [ str(self.group_attr) ])
            return ret
    
        def modify(self, dn, attrs):
            try:
                l = ldap.open(self.host)
                l.simple_bind_s(self.dn, self.password)
                l.modify_s(dn.encode('latin-1'), attrs)
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
        
        def __unicode__(self):
            return self.host
    
        def get_absolute_url(self):
            return "/ldap/"

def add_member(con2, uid, groups):
    dn = "uid="+uid+",ou="+l.user_ou+","+l.base_dn
    for group in groups:
        l.member(ldap.MOD_ADD, group, dn)
        if group == 'Gestion projets':
            cur = con.cursor()
            query = "UPDATE utilisateur SET actif='Y' WHERE login='%s'" % uid
            cur.execute(query.encode('latin-1'))
            con.commit()
        if group == 'Gestion Insertion' or group == u'Requête Insertion' or group == 'Administrateur Insertion':
            cur = con2.cursor()
            query = "UPDATE webmasters SET actif=1 WHERE web_user='%s'" % uid
            cur.execute(query.encode('latin-1'))
            con2.commit()    

def del_member(con2, uid, groups):
    dn = "uid="+uid+",ou="+l.user_ou+","+l.base_dn
    for group in groups:
        l.member(ldap.MOD_DELETE, group, dn)
        if group == 'Gestion projets':
            cur = con.cursor()
            query = "UPDATE utilisateur SET actif='N' WHERE login='%s'" % uid
            cur.execute(query.encode('latin-1'))
            con.commit()
        if group == 'Gestion Insertion' or group == u'Requête Insertion' or group == 'Administrateur Insertion':
            cur = con2.cursor()
            query = "UPDATE webmasters SET actif=0 WHERE web_user='%s'" % uid
            cur.execute(query.encode('latin-1'))
            con2.commit()


def passphrase():
    return DjangoUser.objects.make_random_password(length=10, allowed_chars='abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789')

def personalTitles():
    ret = (
        ('Mademoiselle','Mademoiselle'),
        ('Monsieur','Monsieur'),
        ('Madame','Madame')
        )
    return ret

class St(models.Model):
    code = models.CharField(max_length=2,unique=1,primary_key=1)
    name = models.CharField(max_length=200)
    def get_absolute_url(self):
        return "/o/"
    def __unicode__(self):
        return u'%s' % self.code

class O(models.Model):
    name = models.CharField(max_length=200,unique=1)
    def get_absolute_url(self):
        return "/o/"
    def __unicode__(self):
        return u'%s' % self.name

class OU(models.Model):
    name = models.CharField(max_length=200,unique=1)
    def get_absolute_url(self):
        return "/ou/"
    def __unicode__(self):
        return u'%s' % self.name

class DisplayGroup(models.Model):
    name = models.CharField(max_length=200,unique=1)
    def get_absolute_url(self):
        return "/displaygroup/"
    def __unicode__(self):
        return u'%s' % self.name
    class Meta:
        db_table = 'displaygroup'

class GroupLDAP(models.Model):
    cn = models.CharField(_("cn"), max_length=100)

    def add(self, l):
        dn = "cn="+self.cn+",ou="+l.group_ou+","+l.base_dn
        attrs = {}
        attrs['objectclass'] = [ 'top', 'groupOfNames' ]
        attrs['cn'] = [ self.cn.encode('utf-8') ]
        attrs['member'] = [ l.dn.encode('utf-8') ]
        attrs['adminMember'] = [ l.dn.encode('utf-8') ]
        ml = modlist.addModlist(attrs)
        print ml
        l.add(dn, ml)
    class Meta:
        db_table = 'groupldap'

class UserLDAP(models.Model):
    uid = models.CharField(_("login"), max_length=100)
    userPassword = models.CharField(_("password"), max_length=100,blank=True)
    userActive = models.BooleanField(_("active"))
    st = models.CharField(_("departement"), max_length=3, blank=True)
    agora_profil = models.CharField(max_length=100,blank=True, editable=False)
    agora_acteur = models.CharField(max_length=100,blank=True, editable=False)
    sn = models.CharField(_("lastname"), max_length=100)
    cn = models.CharField(_("firstname"), max_length=100)
    mail = models.CharField(_("mail"), max_length=100,blank=True)
    businessCategory = models.CharField(_("businessCategory"), max_length=100,blank=True)
    businessCategory2 = models.CharField(_("businessCategory2"), max_length=100,blank=True)
    o = models.CharField(_("organization"), max_length=100,blank=True)
    service = models.CharField(max_length=100,blank=True)
    personalTitle = models.CharField(_("personalTitle"),max_length=100,blank=True,choices=personalTitles())
    personalTitle2 = models.CharField(_("personalTitle2"),max_length=100,blank=True)
    title = models.CharField(_("title"), max_length=300,blank=True)
    telephoneNumber = models.CharField(_("phone"), max_length=100,blank=True)
    facsimileTelephoneNumber = models.CharField(_("fax"), max_length=100,blank=True)
    mobile = models.CharField(_("mobile"), max_length=100,blank=True)
    postalAddress = models.CharField(_("postalAddress"),max_length=100,blank=True)
    postalAddress2 = models.CharField(_("postalAddress2"),max_length=100,blank=True)
    postalCode = models.CharField(_("postalCode"),max_length=100,blank=True)
    l = models.CharField(_("city"), max_length=100,blank=True)
    ou = models.CharField(_("ou"), max_length=100, null=True,blank=True)
    observations = models.CharField(max_length=100,blank=True)
    projet = models.CharField(max_length=100,blank=True)
    pager = models.BooleanField(_("pager"))
    modifyDate = models.CharField(_("modifyDate"), max_length=100,editable=False)
    createDate = models.CharField(_("createDate"), max_length=100,editable=False)
    connectDate = models.CharField(_("connectDate"), max_length=100,editable=False)
    description = models.CharField(max_length=100,blank=True, editable=False)

    def search(self, l, user, profil=None):
        search = l.search(l.base_dn, ldap.SCOPE_SUBTREE, "(uid="+user+")", self.to_array().keys())
        print search
        self.dn = search[0][0][0]
        entry = search[0][0][1]
        self.search_operational_attr(l, user)
        self.from_array(entry, profil=profil)

    def search_operational_attr(self, l, user):
        search = l.search(l.base_dn, ldap.SCOPE_SUBTREE, "(uid="+user+")", ["+"])
        tmp = search[0][0][1]['modifyTimestamp'][0]
        self.modifyDate = "%s/%s/%s" % (tmp[6:8], tmp[4:6], tmp[:4])
        tmp = search[0][0][1]['createTimestamp'][0]
        self.createDate = "%s/%s/%s" % (tmp[6:8], tmp[4:6], tmp[:4])

    def update(self, l, u, profil=None):
        attrs = self.to_array(profil=profil)
        if (not attrs.has_key('userPassword') or attrs['userPassword'] == "") and profil == "Admin":
            attrs['userPassword'] = passphrase()
        ml = modlist.modifyModlist(u.to_array(profil=profil), attrs)
        print "====== UPDATE =============="
        print ml
        l.modify(u.dn, ml)
        if profil == "Admin":
            update_acteur(l, u.dn, self)

    def delete(self, l, con2):
        dn = "uid="+self.uid+",ou="+l.user_ou+","+l.base_dn
        print "DELETE %s" % dn
        groups_ok = []
        for g in l.group_ok(dn):
            groups_ok.append(g[0][1]['cn'][0])
        print groups_ok
        del_member(con2, self.uid, groups_ok)
        l.delete_user(self.uid)

    def add(self, l):
        dn = "uid="+self.uid+",ou="+l.user_ou+","+l.base_dn
        attrs = self.to_array(profil="Admin")
        attrs['objectclass'] = [ 'top', 'person', 'inetOrgPerson' ]
        attrs['userPassword'] = passphrase()
        attrs['userActive'] = [ '1' ]
        attrs['o'] = [ self.o.encode('utf-8') ]
        attrs['uid'] = [ self.uid.encode('utf-8') ]
        ml = modlist.addModlist(attrs)
        print ml
        l.add(dn, ml)

    def from_array_set(self, attr_name, entry):
        try:
            return entry[attr_name][0].decode('utf-8')
        except:
            return ''

    def from_array(self, entry, profil=None):
        self.uid = self.from_array_set("uid", entry)
        if profil == "Admin":
            self.userPassword = self.from_array_set("userPassword", entry)
        else:
            self.userPassword = 'xxxxxxx'
        self.cn = self.from_array_set("cn", entry)
        self.o = O(name=self.from_array_set("o", entry))
        self.ou = self.from_array_set("ou", entry)
        self.service = self.from_array_set("service", entry)
        self.projet = self.from_array_set("projet", entry)
        self.title = self.from_array_set("title", entry)
        self.observations = self.from_array_set("carLicense", entry)
        self.mail = self.from_array_set("mail", entry)
        self.sn = self.from_array_set("sn", entry)
        self.st = self.from_array_set("st", entry)
        self.l = self.from_array_set("l", entry)
        self.telephoneNumber = self.from_array_set("telephoneNumber", entry)
        self.mobile = self.from_array_set("mobile", entry)
        self.facsimileTelephoneNumber = self.from_array_set("facsimileTelephoneNumber", entry)
        self.businessCategory = self.from_array_set("businessCategory", entry)
        self.businessCategory2 = self.from_array_set("businessCategory2", entry)
        self.postalAddress = self.from_array_set("postalAddress", entry)
        self.postalAddress2 = self.from_array_set("postalAddress2", entry)
        self.postalCode = self.from_array_set("postalCode", entry)
        self.personalTitle = self.from_array_set("personalTitle", entry)
        self.personalTitle2 = self.from_array_set("personalTitle2", entry)
        self.connectDate = self.from_array_set("lastConnect", entry)
        if self.from_array_set("userActive", entry) == '':
            self.userActive = None
        elif self.from_array_set("userActive", entry) == '0':
            self.userActive = 0
        else:
            self.userActive = 1
        self.description = self.from_array_set("description", entry)

    def to_array(self, profil=None):
        if self.userActive == 1:
            user_active = '1'
        elif self.userActive == 0:
            user_active = '0'
        else:
            user_active = None

        if profil == "Admin":
            ret = {
                'userPassword' : [ self.userPassword.encode('utf-8') ],
                'cn' : [ self.cn.encode('utf-8') ],
                'ou' : [ self.ou.encode('utf-8') ],
                'service' : [ self.service.encode('utf-8') ],
                'projet' : [ self.projet.encode('utf-8') ],
                'title' : [ self.title.encode('utf-8') ],
                'mail' : [ self.mail.encode('utf-8') ],
                'sn' : [ self.sn.encode('utf-8') ],
                'st' : [ self.st.encode('utf-8') ],
                'telephoneNumber' : [ self.telephoneNumber.encode('utf-8') ],
                'mobile' : [ self.mobile.encode('utf-8') ],
                'facsimileTelephoneNumber' : [ self.facsimileTelephoneNumber.encode('utf-8') ],
                'l' : [ self.l.encode('utf-8') ],
                'businessCategory' : [ self.businessCategory.encode('utf-8') ],
                'businessCategory2' : [ self.businessCategory2.encode('utf-8') ],
                'postalAddress' : [ self.postalAddress.encode('utf-8') ],
                'postalAddress2' : [ self.postalAddress2.encode('utf-8') ],
                'postalCode' : [ self.postalCode.encode('utf-8') ],
                'personalTitle' : [ self.personalTitle.encode('utf-8') ],
                'personalTitle2' : [ self.personalTitle2.encode('utf-8') ],
                'description' : [ str(agora_profil + agora_acteur).encode('utf-8') ]
                }
        else:
            ret = {
                }
        for k in ret.keys():
            if ret[k][0] == '':
                del ret[k]
        return ret
    class Meta:
        db_table = 'userldap'

class User(models.Model):
    login = models.CharField(max_length=100,unique=1)
    password = models.CharField(max_length=100)
    is_admin = models.BooleanField()
    def __unicode__(self):
        return self.login
    def get_absolute_url(self):
        return "/user/"
    class Meta:
        db_table = 'user'

class CSS(models.Model):
    name = models.CharField(max_length=200,unique=1)
    value = models.TextField()
    def get_absolute_url(self):
        return "/style_css/"
    def __unicode__(self):
        return self.name
    class Meta:
        db_table = 'style_css'

class TPL(models.Model):
    TPL_TYPES = (
        ('LOGIN','Login'),
#        ('SSO_LEARNING','SSO Learning'),
        )
    name = models.CharField(max_length=200,unique=1)    
    type = models.CharField(max_length=50, choices=TPL_TYPES)
    value = models.TextField()
    def get_absolute_url(self):
        return "/style_tpl/"
    def __unicode__(self):
        return self.name
    class Meta:
        db_table = 'style_tpl'

class Image(models.Model):
    name = models.CharField(max_length=200,unique=1)
    image = models.ImageField(upload_to='img/')
    def get_absolute_url(self):
        return "/style_images/"
    def __unicode__(self):
        return self.name
    class Meta:
        db_table = 'style_image'

class Translation(models.Model):
    COUNTRY_CHOICES = (
        ('en','English'),
        ('fr','Français'),
        ('de','Deutch'),
        ('es','Espanol'),
        ('it','Italiano'),
        )
    ERRORS_CHOICES = (
        ('USER', 'User'),
        ('PASSWORD', 'Password'),
        ('LOGIN_FAILED','Login failed'),
        ('WRONG_USER','Wrong user'),
        ('WRONG_PASSWORD','Wrong password'),
        ('NEED_CHANGE_PASS','Need change pass'),
        )
    country = models.CharField(max_length=4, choices=COUNTRY_CHOICES)
    message = models.CharField(max_length=50, choices=ERRORS_CHOICES)
    translation = models.CharField(max_length=200)
    def get_absolute_url(self):
        return "/style_translation/"
    def __unicode__(self):
        return self.country+'-'+self.message
    class Meta:
        db_table = 'style_translation'

class Style(models.Model):
    name = models.CharField(max_length=200,unique=1)
    css = models.ForeignKey(CSS,blank=1,null=1)
    tpl = models.ManyToManyField(TPL, db_table='style_tpl_mapping')
    image = models.ForeignKey(Image,blank=1,null=1)
    def get_absolute_url(self):
        return "/style_style/"
    def __unicode__(self):
        return self.name
    class Meta:
        db_table = 'style_style'
    
