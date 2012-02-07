# -*- coding: utf-8 -*-
from django.template.loader import get_template
from django.template import Context
from django.conf import settings
from django.db import models
from django.contrib import admin
from time import sleep
import time
from pysqlite2 import dbapi2 as sqlite3
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
from django.contrib.auth.models import User as DjangoUser, UserManager as DjangoUserManager
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
    name = models.CharField(max_length=128, unique=1)
    level = models.CharField(max_length=10, blank=1,choices=LOG_LEVELS)
    format = models.CharField(max_length=500, blank=1)
    dir = models.CharField(max_length=200)
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
    name = models.CharField(max_length=128, unique=1)
    ip = models.IPAddressField()
    port = models.IntegerField()
    ssl_engine = models.CharField(max_length=10,blank=1,choices=SSL_ENGINES)
    log = models.ForeignKey('Log')
    sso_portal = models.CharField(max_length=256,blank=1,null=1)
    sso_timeout = models.IntegerField(blank=1,null=1)
    sso_update_access_time = models.BooleanField(default=0)
    appearance = models.ForeignKey('Appearance', blank=1, null=1)
    cas_portal = models.CharField(max_length=256,blank=1,null=1)
    cas_auth = models.ManyToManyField('Auth',null=1,blank=1,db_table='intf_auth_multiple')
    cas_auth_basic = models.BooleanField(default=0)
    cas_st_timeout = models.IntegerField(blank=1,null=1)
    cas_redirect = models.CharField(max_length=256,blank=1,null=1)
    cas_display_portal = models.BooleanField(default=0);

    #handle login problem like in a app
    auth_server_failure_action = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    auth_server_failure_options = models.CharField(max_length=128, blank=1, null=1)
    account_locked_action = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    account_locked_options = models.CharField(max_length=128, blank=1, null=1)
    login_failed_action = models.CharField(max_length=128, blank=1, null=1, choices=RESTRICTED_ACTIONS, default='template')
    login_failed_options = models.CharField(max_length=128, blank=1, null=1)
    need_change_pass_action = models.CharField(max_length=128, blank=1, null=1, choices=ACTIONS, default='nothing')
    need_change_pass_options = models.CharField(max_length=128, blank=1, null=1)

	
    cert = models.TextField(blank=1,null=1)
    key = models.TextField(blank=1,null=1)
    ca = models.TextField(blank=1,null=1)
    cacert = models.TextField(blank=1,null=1)
    virtualhost_directives = models.TextField(blank=1,null=1)


    def conf(self):
        t = get_template("vulture_httpd.conf")
        c = Context({"VultureConfPath" : settings.CONF_PATH,
                     "VultureStaticPath" : settings.MEDIA_ROOT,
                     "PerlSwitches" : settings.PERL_SWITCHES,
                     "dbname" : settings.DATABASES['default']['NAME'],
                     "serverroot" : settings.SERVERROOT,
                     "www_user" : settings.WWW_USER,
                     "httpd_custom" : settings.HTTPD_CUSTOM,
                     "app_list" : App.objects.filter(intf=self.id).order_by('name', '-alias'),
                     "intf" : self,
                     })
        return t.render(c)

    def write(self):
        f=open("%s%s.conf" % (settings.CONF_PATH, self.id), 'w')
        f.write(str(self.conf()))
        f.close()
        if self.cert:
            f=open("%s%s.crt" % (settings.CONF_PATH, self.id), 'w')
            f.write(str(self.cert))
            f.close()
        if self.key:
            f=open("%s%s.key" % (settings.CONF_PATH, self.id), 'w')
            f.write(str(self.key))
            f.close()
        if self.ca:
            f=open("%s%s.chain" % (settings.CONF_PATH, self.id), 'w')
            f.write(str(self.ca))
            f.close()
        if self.cacert:
            f=open("%s%s.cacrt" % (settings.CONF_PATH, self.id), 'w')
            f.write(str(self.cacert))
            f.close()
        for app in App.objects.filter(intf=self.id).all():
            auth_list=app.auth.all()
            for auth in auth_list:
                if auth.auth_type == 'ssl':
                    f=open("%s%s.ca" % (settings.CONF_PATH, str(self.id)+'-'+app.name), 'w')
                    f.write(str(auth.getAuth().crt))
                    f.close()

    def checkIfEqual(self):
        try:
            f=open("%s%s.conf" % (settings.CONF_PATH, self.id), 'r')
            content=f.read()
            content2 = self.conf()
            f.close()
        except:
            return False
        return (content == content2)
            
    def pid(self):
        pid = string.strip(os.popen("sudo /bin/cat %s%s.pid" % (settings.CONF_PATH, self.id)).read())
        pidof = str(os.popen("pidof %s" % settings.HTTPD_PATH).read()).split()
        if len(pidof) and pid not in pidof:
            return None
        return pid

    def need_restart(self):
        try:
            f=open("%s%s.conf" % (settings.CONF_PATH, self.id), 'r')
            content = f.read()
            f.close()
            if content != self.conf() :
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
            auth_list=app.auth.all()
            for auth in auth_list:
                if auth.auth_type == 'ssl':
                    try:
                        f=open("%s%s.ca" % (settings.CONF_PATH, str(self.id)+'-'+app.name), 'r')
                        content = f.read()
                        f.close()
                        if content != auth.getAuth().crt :
                            return True
                    except:
                        return True
    
    def k(self, cmd):
        return os.popen("%s -f %s%s.conf -k %s 2>&1" % (settings.HTTPD_PATH, settings.CONF_PATH, self.id, cmd)).read()
        
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

class Auth(models.Model):
    name = models.CharField(max_length=128, unique=1)
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
        elif self.auth_type == 'cas':
            return CAS.objects.get(id=self.id_method)
        else:
            return None
    def is_ssl(self):
        if self.auth_type == 'ssl':
            return True
        return False
    def __str__(self):
        return self.name
    class Meta:
        db_table = 'auth'

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
    var = models.TextField(unique=1)
    value = models.TextField(null=1)
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
    timestamp = models.DateField(auto_now_add=True, null=1, blank=1)
    info = models.CharField(max_length = 256, null=1, blank=1)
    class Meta:
        db_table = 'event_logger'
    
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
    def user_ko(self, user_ok):
        user_ko = []
        if self.driver == 'SQLite':
            con = sqlite3.connect(self.database)
            cur = con.cursor()
            query = "SELECT %s from %s" % (self.user_column, self.table)
            sep = " WHERE "
            for user in user_ok:
                query += sep + "%s != '%s'" % (self.user_column, user.user)
                sep = " AND "
            print query
            cur.execute(query)
            for user in cur:
                user_ko.append(('%s' % user, '%s' % user))
        return user_ko
    def __str__(self):
        return self.name
    class Meta:
        db_table = 'sql'

class Kerberos(models.Model):
    name = models.CharField(max_length=128,unique=1)
    realm = models.CharField(max_length=256)
    def __str__(self):
        return self.name
    class Meta:
        db_table = 'kerberos'
        
class CAS(models.Model):
    name = models.CharField(max_length=128,unique=1)
    url_login = models.CharField(max_length=256)
    url_validate = models.CharField(max_length=256)
    def __str__(self):
        return self.name
    class Meta:
        db_table = 'cas'

class ModSecurity(models.Model):
    name = models.CharField(max_length=128,unique=1)
    rules = models.TextField()
    def __unicode__(self):
        return self.name
    class Meta:
        db_table = 'modsecurity'

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
        )
    name = models.CharField(max_length=128, unique=1)
    type = models.CharField(max_length=20, choices=SSO_TYPES, blank=1)
    auth = models.ForeignKey('Auth', blank=1, null=1)
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
    name = models.CharField(max_length=128,unique=1)
    alias = models.CharField(max_length=128, blank=1, null=1)
    url = models.CharField(max_length=256)
    intf = models.ManyToManyField('Intf',db_table='app_intf')
    log = models.ForeignKey('Log')
    security = models.ManyToManyField('ModSecurity',null=1,blank=1,db_table='app_security')
    logon_url = models.CharField(max_length=128,null=1,blank=1)
    logout_url = models.CharField(max_length=128,null=1,blank=1)
    up = models.BooleanField(default=1)
    available = models.BooleanField(default=1)
    remote_proxy = models.URLField(blank=1, null=1, verify_exists=0)
    remote_proxy_SSLProxyMachineCertificateFile = models.CharField(max_length=512, blank=1, null=1)
    remote_proxy_SSLProxyCACertificateFile = models.CharField(max_length=512, blank=1, null=1)
    remote_proxy_SSLProxyCARevocationFile = models.CharField(max_length=512, blank=1, null=1)
    remote_proxy_SSLProxyVerify = models.CharField(max_length=10,blank=1,choices=SSL_PROXY_VERIFY)
    timeout = models.IntegerField(null=1,blank=1)
    auth= models.ManyToManyField('Auth',null=1,blank=1,db_table='auth_multiple')
    auth_basic = models.BooleanField(default=0)
    display_portal = models.BooleanField()
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
    
    def isWildCard (self):
        return self.alias.startswith('*')

    def hasHeaderHost (self):
        return Header.objects.filter(app = self).filter(name__iexact="Host")

    def hasBlackIp (self):
        return BlackIP.objects.filter(app = self)

    def getCookieDomain (self):
        p = re.compile ('https?://(.*)/?')
        match=p.match(self.url)
        domain = match.group(1)
        if domain:
            return "ProxyPassReverseCookieDomain "+domain+" "+self.name
        return " "
    def __str__(self):
        return self.name
    class Meta:
        db_table = 'app'
        permissions = (
            ("reload_app", "Can stop/start application"),
        )

class Plugin(models.Model):
    PLUGIN_TYPES = (
    ('Static', 'Static'),
    ('Rewrite', 'Rewrite'),
    ('Block', 'Block'),
    ('Logout', 'Logout'),
    ('Logout_ALL', 'Logout_ALL'),
    ('CAS','CAS'),
	('REDIRECT_NO_LOG','REDIRECT_NO_LOG'),
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

class SSL(models.Model):
    SSL_REQUIRE = (
        ('optional', 'optional'),
        ('require', 'require'),
        )
    name = models.CharField(max_length=128,unique=1)
    require = models.CharField(max_length=20, choices=SSL_REQUIRE)
    crt = models.TextField()
    constraint = models.TextField()
    def __str__(self):
        return self.name
    class Meta:
        db_table = 'ssl'

class NTLM(models.Model):
    name = models.CharField(max_length=128,unique=1)
    domain = models.CharField(max_length=128)
    primary_dc = models.CharField(max_length=128)
    secondary_dc = models.CharField(max_length=128, blank=1, null=1)
    def __str__(self):
        return self.name
    class Meta:
        db_table = 'ntlm'

class RADIUS(models.Model):
    name = models.CharField(max_length=128,unique=1)
    host = models.CharField(max_length=128)
    port = models.IntegerField()
    secret = models.CharField(max_length=64)
    timeout = models.IntegerField()
    url_attr = models.CharField(max_length=32, blank=1)
    def __str__(self):
        return self.name
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
    name = models.CharField(max_length=128)
    type = models.CharField(max_length=20,choices=HEADER_TYPE)
    value = models.CharField(max_length=128,blank=1)
    app = models.ForeignKey('App')
    def __str__(self):
        return self.name
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
    name = models.CharField(max_length=128, unique=1)
    host = models.CharField(max_length=128)
    port = models.IntegerField()
    protocol = models.CharField(max_length=1,choices=LDAP_VERSIONS, default="3")
    scheme = models.CharField(max_length=128,choices=LDAP_ENC_SCHEMES, default="none")
    cacert_path = models.CharField(max_length=64, blank=1, null=1)
    base_dn = models.CharField(max_length=64)
    dn = models.CharField(max_length=64)
    password = models.CharField(max_length=64)
    user_ou = models.CharField(max_length=128, blank=1, null=1)
    user_attr = models.CharField(max_length=32)
    user_scope = models.IntegerField(choices=LDAP_SCOPE)
    user_filter = models.CharField(max_length=128, blank=1, null=1)
    user_account_locked_attr = models.CharField(max_length=128, blank=1, null=1)
    group_ou = models.CharField(max_length=128, blank=1, null=1)
    group_attr = models.CharField(max_length=32)
    group_scope = models.IntegerField(choices=LDAP_SCOPE)
    group_filter = models.CharField(max_length=128, blank=1, null=1)
    group_member = models.CharField(max_length=32, blank=1, null=1)
    are_members_dn = models.BooleanField()
    url_attr = models.CharField(max_length=32, blank=1)
    chpass_attr = models.CharField(max_length=32, blank=1)
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
        if group == 'Gestion Insertion' or group == u'Requ??te Insertion' or group == 'Administrateur Insertion':
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
        if group == 'Gestion Insertion' or group == u'Requ??te Insertion' or group == 'Administrateur Insertion':
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
    
def getAllIntfs():
    return Intf.objects.all()

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
        )
    name = models.CharField(max_length=128,unique=1)    
    type = models.CharField(max_length=50, choices=TEMPLATE_TYPES)
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
        )
    ERRORS_CHOICES = (
        ('USER', 'User'),
        ('PASSWORD', 'Password'),
        ('LOGIN_FAILED','Login failed'),
        ('MISSING_LOGIN','Missing login'),
        ('MISSING_PASSWORD','Missing password'),
        ('NEED_CHANGE_PASS','Need change pass'),
        ('AUTH_SERVER_FAILURE', 'Authentication server failure'),
        ('ACCOUNT_LOCKED', 'Account locked'),
        ('ACL_FAILED','ACL failed'),
        ('APPLICATION', 'Application'),
        ('APP_DOWN', 'App down'),
        ('SSO_LEARNING', 'SSO Learning'),
        ('DISCONNECTED', 'Disconnected'),
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
    ('Mime Forbiden', 'Mime Forbiden'),
    ('Header Unset','Header Unset'),
    ('Header to link','Header to link'),
    ('Header to proxy','Header to proxy'),
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
