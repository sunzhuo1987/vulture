# -*- coding: utf-8 -*-
from vulture.models import *
from vulture.forms import *
from django.template import Variable, Library
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response, get_object_or_404
from django.views.generic.list_detail import object_list
from django.views.generic.create_update import update_object, create_object, delete_object
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required, user_passes_test, permission_required
from django.contrib.auth.forms import UserChangeForm, SetPasswordForm
from django.utils.html import escape
from django.forms import ModelForm
from django import forms
from django.utils import simplejson
from time import sleep
import datetime
import time
import re
import pylibmc
from django.db.models import Q
from django.db import connection
import ldap
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.utils.http import urlquote
from django.core.mail import send_mail
from django.core.paginator import Paginator, InvalidPage, EmptyPage
from django.contrib.formtools.wizard import FormWizard
from django.core.exceptions import ObjectDoesNotExist

def logon(request):
    if request.POST:
        user = authenticate(username=request.POST['username'], password=request.POST['password'])
        if user is not None:
            login(request, user)
            #u = User.objects.get(username=request.POST['username'])
            #if u.is_admin == True:
            #    user.is_staff = 1
            #user.save()
            #request.session['version'] = '2.0'
            return HttpResponseRedirect(request.POST.get('next'))
    logout(request)
    return render_to_response('logon.html', { 'next' : request.GET.get('next')})

@login_required
def update_security(request):
    k_output = os.popen("/bin/sh %s/update-rules.sh 2>&1" % (settings.BIN_PATH)).read()
    return render_to_response('vulture/modsecurity_list.html',
                              {'object_list': ModSecurity.objects.all(), 'k_output': k_output, 'user' : request.user })

@login_required
def start_intf(request, intf_id):
    Intf.objects.get(pk=intf_id).write()
    k_output = Intf.objects.get(pk=intf_id).k('start')
#    sleep(1)
    return render_to_response('vulture/intf_list.html',
                              {'object_list': Intf.objects.all(), 'k_output': k_output, 'user' : request.user })

@login_required
def stop_intf(request, intf_id):
    k_output = Intf.objects.get(pk=intf_id).k('stop')
#    sleep(1)
    return render_to_response('vulture/intf_list.html',
                              {'object_list': Intf.objects.all(), 'k_output': k_output, 'user' : request.user})

@login_required
def reload_intf(request, intf_id):
    Intf.objects.get(pk=intf_id).write()
    k_output = Intf.objects.get(pk=intf_id).k('graceful')
    return render_to_response('vulture/intf_list.html',
                              {'object_list': Intf.objects.all(), 'k_output': k_output, 'user' : request.user})
                              
@login_required
def reload_all_intfs(request):
    intfs = Intf.objects.all()
    for intf in intfs :
        if intf.need_restart:
            intf.write()
            intf.k('graceful')
    else:
        return render_to_response('vulture/intf_list.html', {'object_list': intfs, 'user' : request.user})

@user_passes_test(lambda u: u.is_staff)
def vulture_update_object_adm(*args, **kwargs):
    return update_object(*args, **kwargs)

@user_passes_test(lambda u: u.is_staff)
def vulture_create_object_adm(*args, **kwargs):
    return create_object(*args, **kwargs)

@user_passes_test(lambda u: u.is_staff)
def vulture_delete_object_adm(*args, **kwargs):
    return delete_object(*args, **kwargs)

@user_passes_test(lambda u: u.is_staff)
def vulture_object_list_adm(*args, **kwargs):
    return object_list(*args, **kwargs)

@login_required
def start_app(request,object_id):
    app = get_object_or_404(App, id=object_id)
    app.up = 1
    app.save()
    return HttpResponseRedirect("/app/")

@login_required
def stop_app(request,object_id):
    app = get_object_or_404(App, id=object_id)
    app.up = 0
    app.save()
    return HttpResponseRedirect("/app/")

@login_required
def edit_auth(request, url, object_id=None):
    if url == 'sql':
        form = SQLForm(request.POST or None,instance=object_id and SQL.objects.get(id=object_id))
    elif url == 'ldap':
        form = LDAPForm(request.POST or None,instance=object_id and LDAP.objects.get(id=object_id))
    elif url == 'ssl':
        form = SSLForm(request.POST or None,instance=object_id and SSL.objects.get(id=object_id))
    elif url == 'ntlm':
        form = NTLMForm(request.POST or None,instance=object_id and NTLM.objects.get(id=object_id))
    elif url == 'kerberos':
        form = KerberosForm(request.POST or None,instance=object_id and Kerberos.objects.get(id=object_id))
    elif url == 'radius':
        form = RADIUSForm(request.POST or None,instance=object_id and RADIUS.objects.get(id=object_id))
    elif url == 'cas':
        form = CASForm(request.POST or None,instance=object_id and CAS.objects.get(id=object_id))

    # Save new/edited auth
    if request.method == 'POST' and form.is_valid():
        instance = form.save()
        try:
            auth = Auth.objects.get(id_method=instance.pk, auth_type=url)
            auth.name = form.cleaned_data['name']
        except Auth.DoesNotExist:               
            auth = Auth(name = form.cleaned_data['name'],auth_type = url,id_method = instance.pk)
        auth.save()

        return HttpResponseRedirect('/' + url +'/')

    return render_to_response('vulture/'+ url +'_form.html', {'form': form, 'user' : request.user})

@login_required
def remove_auth(request, url, object_id=None):
    if url == 'sql':
        object = get_object_or_404(SQL, id=object_id)
    elif url == 'ldap':
        object = get_object_or_404(LDAP, id=object_id)
    elif url == 'ssl':
        object = get_object_or_404(SSL, id=object_id)
    elif url == 'ntlm':
        object = get_object_or_404(NTLM, id=object_id)
    elif url == 'kerberos':
        object = get_object_or_404(Kerberos, id=object_id)
    elif url == 'radius':
        object = get_object_or_404(RADIUS, id=object_id)
    elif url == 'cas':
        object = get_object_or_404(CAS, id=object_id)
    # Remove auth
    if request.method == 'POST' and object_id:       
        auth = get_object_or_404(Auth, id_method=object.pk, auth_type=url)
        auth.delete()
        object.delete()
        return HttpResponseRedirect('/'+ url +'/')
    return render_to_response('vulture/generic_confirm_delete.html', {'object':object, 'category' : 'Authentication', 'name' : url.capitalize(),'url' : '/' + url, 'user' : request.user})

@login_required
def edit_app(request,object_id=None):
    form = AppForm(request.POST or None,instance=object_id and App.objects.get(id=object_id))
    form.header = Header.objects.order_by("-id").filter(app=object_id)
    # Save new/edited app
    if request.method == 'POST' and form.is_valid():
        
        
        dataPosted = request.POST
        #app = form.save(commit=False)
        app = form.save()
        
        # Delete memcached records to update config
        mc = pylibmc.Client(["127.0.0.1:9091"])
        intfs = Intf.objects.all()
        for intf in intfs :
            mc.delete(app.name + ':' + intf.id + ':app')
        
        #Delete old headers
        headers = Header.objects.filter(app=object_id)
        headers.delete()

        #Writing new ones
        for data in dataPosted:
            m = re.match('header_id-(\d+)',data)
            if m != None:
                id = m.group(1)
                desc = dataPosted['field_desc-' + id]
                type = dataPosted['field_type-' + id]
                if desc and type:
                    if type != "CUSTOM" or (type == "CUSTOM" and dataPosted['field_value-' + id]):
                        instance = Header(app=app, name = desc, value = dataPosted['field_value-' + id], type=type)
                        instance.save()
        #form.save_m2m()

        return HttpResponseRedirect('/app/')

    return render_to_response('vulture/app_form.html', {'form': form, 'user' : request.user})

@login_required
def copy_app(request,object_id=None):
    form = AppCopy(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        a1 = App.objects.get(name=form.cleaned_data['app'])
        a1.pk = None
        a1.name = form.cleaned_data['name']
        try:
            a1.save()
        except:
            pass
        return HttpResponseRedirect('/app/')
    return render_to_response('vulture/app_copy.html', {'form': form, 'user' : request.user})

@login_required
def edit_sso(request,object_id=None):
    form = SSOForm(request.POST or None,instance=object_id and SSO.objects.get(id=object_id))
    form.post = Field.objects.order_by("-id").filter(sso=object_id)    
    # Save new/edited component
    if request.method == 'POST' and form.is_valid():
        dataPosted = request.POST
        sso = form.save(commit=False)
        sso.type = 'sso_forward'
        sso.save()

        #Delete old posts
        posts = Field.objects.filter(sso=object_id)
        posts.delete()
        
        #nbfields = dataPosted['nbfields']
        #print request.POST
        #Writing new ones
        for data in dataPosted:
            m = re.match('post_id-(\d+)',data)
            if m != None:
                id = m.group(1)
                desc = dataPosted['field_desc-' + id]
                var = dataPosted['field_var-' + id]
                type = dataPosted['field_type-' + id]
                if dataPosted.has_key('field_encrypted-' + id):
                    if dataPosted['field_encrypted-' + id] == "True" or dataPosted['field_encrypted-' + id] == "on":
                        encryption = True
                    else:
                        encryption = False
                else:
                    encryption = False
                if desc and var and type:
                    instance = Field(sso=sso, field_desc = desc, field_var = var, field_mapped = dataPosted['field_mapped-' + id], field_type = type, field_encrypted = encryption,field_value = dataPosted['field_value-' + id], field_prefix = dataPosted['field_prefix-' + id], field_suffix = dataPosted['field_suffix-' + id])
                    instance.save()
        return HttpResponseRedirect('/sso/')
    return render_to_response('vulture/sso_form.html', {'form': form, 'user' : request.user})

@login_required
def edit_acl(request,object_id=None):
    form = ACLForm(request.POST or None,instance=object_id and ACL.objects.get(id=object_id))
    if object_id:
        acl = ACL.objects.get(id=object_id)
        users_ok = acl.users_ok
        users_ko = acl.auth.getAuth().user_ko(users_ok.all())
        if acl.auth.auth_type == "ldap" :
            groups_ok = acl.groups_ok
            groups_ko = acl.auth.getAuth().group_ko(groups_ok.all())
        else :
            groups_ok = None
            groups_ko = None
    else :
        users_ok = None
        users_ko = None
        groups_ok = None
        groups_ko = None
    # Save new/edited acl     
    if request.method == 'POST' and form.is_valid():
        dataPosted = request.POST
        acl = form.save()   
        acl.users_ok.clear()
        acl.groups_ok.clear()
        for value in dataPosted.getlist('in_user[]'):
            try:
                user = UserOK.objects.get(user=value)
                acl.users_ok.add(user)
            except UserOK.DoesNotExist:
                acl.users_ok.create(user=value)
        for value in dataPosted.getlist('in_group[]'):
            
            try:
                group = GroupOK.objects.get(group=value)
                acl.groups_ok.add(group)
            except GroupOK.DoesNotExist:
                acl.groups_ok.create(group=value)
        #acl.save()
        #form.save_m2m()
        return HttpResponseRedirect('/acl/')

    return render_to_response('vulture/acl_form.html', {'form': form, 'user' : request.user, 'users_ok' : users_ok, 'users_ko' : users_ko, 'groups_ok' : groups_ok, 'groups_ko' : groups_ko})

@login_required
def create_user(request,object_id=None):
    form = UserProfileForm(request.POST or None,instance=object_id and User.objects.get(id=object_id))
    # Save new/edited component
    if request.method == 'POST' and form.is_valid():
        user = form.save(commit=False)
        dataPosted = request.POST
        user.password = hashlib.sha1(dataPosted['password1']).hexdigest()
        user.save()
        return HttpResponseRedirect('/user/')
    return render_to_response('vulture/user_form.html', {'form': form, 'user' : request.user})
    
@login_required
def edit_user(request,object_id=None):
    form = MyUserChangeForm(request.POST or None,instance=object_id and User.objects.get(id=object_id))
    # Save new/edited component
    if request.method == 'POST' and form.is_valid():
        user = form.save(commit=False)
        user.save()
        return HttpResponseRedirect('/user/')
    return render_to_response('vulture/useredit_form.html', {'form': form, 'user' : request.user, 'id' : object_id})
    
@login_required
def edit_user_password(request,object_id=None):    
    user = User.objects.get(id=object_id)
    form = SetPasswordForm(user, request.POST)
    
    # Save new/edited component
    if request.method == 'POST' and form.is_valid():
        dataPosted = request.POST
        user.password = hashlib.sha1(dataPosted['new_password2']).hexdigest()
        user.save()
        return HttpResponseRedirect('/user/')
    return render_to_response('vulture/userpassword_form.html', {'form': form, 'user' : request.user})
    
@login_required
def edit_localization(request,object_id=None):
    form = LocalizationForm(request.POST or None,instance=object_id and Localization.objects.get(id=object_id))
        
    # Save new/edited translation
    if request.method == 'POST' and form.is_valid():
        dataPosted = request.POST
        try:
            result = Localization.objects.filter(country=dataPosted['country'], message=dataPosted['message'])
            result.delete()
        except Localization.DoesNotExist:
            pass
        form.save()
        return HttpResponseRedirect('/localization/')

    return render_to_response('vulture/localization_form.html', {'form': form, 'user' : request.user})
    
@login_required
def view_event (request, object_id=None):

    app_list = App.objects.all()
    file_list = []
    type_list = ('access', 'error', 'authentication', 'security')
    content = None
    length = None
    active_sessions = None
    i = 0
    
    try:
        active_sessions = EventLogger.objects.raw('SELECT id, datetime(timestamp, \'unixepoch\') AS `timestamp`, info FROM event_logger WHERE event_type = \'active_sessions\' ORDER BY timestamp DESC LIMIT 1')[0]
    except:
        pass
    cur = connection.cursor()
    cur.execute("SELECT count(*) FROM event_logger WHERE app_id IS NULL AND event_type='connection_failed'")
    connections_failed = (cur.fetchone())[0]
    cur.close()
    stats_month = None
    stats_day = None
    stats_hour = None
    stats_failed_month = None
    stats_failed_day = None
    stats_failed_hour = None
    
    query = request.GET
    if 'file' in query:
        object_id = query['file']
        cur = connection.cursor()
        cur.execute("SELECT (cast(count(*) as float)/(max(strftime('%%m', timestamp, 'unixepoch')) - min(strftime('%%m', timestamp, 'unixepoch')))) FROM event_logger WHERE app_id = %s AND event_type='connection'",[object_id,])
        stats_month = (cur.fetchone())[0]
        cur.close()
        cur = connection.cursor()
        cur.execute("SELECT (cast(count(*) as float)/(max(strftime('%%d', timestamp, 'unixepoch')) - min(strftime('%%d', timestamp, 'unixepoch')))) FROM event_logger WHERE app_id = %s AND event_type='connection'",[object_id,])
        stats_day = (cur.fetchone())[0]
        cur.close()
        cur = connection.cursor()
        cur.execute("SELECT (cast(count(*) as float)/(max(strftime('%%H', timestamp, 'unixepoch')) - min(strftime('%%H', timestamp, 'unixepoch')))) FROM event_logger WHERE app_id = %s AND event_type='connection'",[object_id,])
        stats_hour = (cur.fetchone())[0]
        cur.close()
        cur = connection.cursor()
        cur.execute("SELECT (cast(count(*) as float)/(max(strftime('%%m', timestamp, 'unixepoch')) - min(strftime('%%m', timestamp, 'unixepoch')))) FROM event_logger WHERE app_id = %s AND event_type='connection_failed'",[object_id,])
        stats_failed_month = (cur.fetchone())[0]
        cur.close()
        cur = connection.cursor()
        cur.execute("SELECT (cast(count(*) as float)/(max(strftime('%%d', timestamp, 'unixepoch')) - min(strftime('%%d', timestamp, 'unixepoch')))) FROM event_logger WHERE app_id = %s AND event_type='connection_failed'",[object_id,])
        stats_failed_day = (cur.fetchone())[0]
        cur.close()
        cur = connection.cursor()
        cur.execute("SELECT (cast(count(*) as float)/(max(strftime('%%H', timestamp, 'unixepoch')) - min(strftime('%%H', timestamp, 'unixepoch')))) FROM event_logger WHERE app_id = %s AND event_type='connection_failed'",[object_id,])
        stats_failed_hour = (cur.fetchone())[0]
        cur.close()
    if 'records' in query:
        records_nb = query['records']
    else:
        records_nb = str(100);
    if 'type' in query and query['type'] in type_list:
        type = query['type']
    else:
        type = 'error'
    if 'filter' in query:
        filter = query['filter']
    else:
        filter = ''

    for app in app_list:
        i = i + 1
        log = Log.objects.get (id=app.log_id)

        if object_id == str (i):
            content = os.popen("sudo /usr/bin/tail -n %s %s | grep -e \"%s\" | tac" % (records_nb, log.dir + 'Vulture-' + app.name + '-' + type + '_log', filter)).read() or "Can't read files"
            length = len(content.split("\n"))
            selected = 'selected'
        else:
            selected=''

        file_list.append ((i,selected,app.name))
    return render_to_response('vulture/event_list.html', {'file_list': file_list, 'log_content': content, 'type_list': type_list, 'type' : type, 'records' : records_nb, 'length' : length, 'filter' : filter, 'active_sessions' : active_sessions, 'user' : request.user, 'stats_month' : stats_month, 'stats_day' : stats_day, 'stats_hour' : stats_hour, 'stats_failed_month' : stats_failed_month, 'stats_failed_day' : stats_failed_day, 'stats_failed_hour' : stats_failed_hour, 'connections_failed' : connections_failed})
    
@login_required
def export_import_config (request, type):
    query = request.POST
    content = None
    path = None
    if 'path' in query:
        path = query['path']
        if type == 'import':
            content = os.popen("if `sudo /bin/cp %s %s/db`; then echo 'Import database is complete'; fi 2>&1" % (path, settings.DATABASE_PATH)).read()
        elif type == 'export':
            content = os.popen("if `sudo /bin/cp %s/db %s`; then echo 'Export database is complete'; fi 2>&1" % (settings.DATABASE_PATH, path)).read()
        else:
            content = 'You had not specify type'
    return render_to_response('vulture/exportimport_form.html', {'type': type, 'path': path, 'content': content})