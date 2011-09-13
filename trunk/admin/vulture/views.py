# -*- coding: utf-8 -*-
from vulture.models import *
from vulture.forms import *
from django.template import Variable, Library
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response
from django.views.generic.list_detail import object_list
from django.views.generic.create_update import update_object, create_object, delete_object
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from django.utils.html import escape
from django.forms import ModelForm
from django import forms
from django.utils import simplejson
from time import sleep
import datetime
import time
import re
from django.db.models import Q
from django.db import connection
import ldap
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.utils.http import urlquote
from django.core.mail import send_mail
from django.core.paginator import Paginator, InvalidPage, EmptyPage
from django.contrib.formtools.wizard import FormWizard

def logon(request):
    if request.POST:
        user = authenticate(username=request.POST['username'], password=request.POST['password'])
        if user is not None:
            login(request, user)
            u = User.objects.get(login=request.POST['username'])
            if u.is_admin == True:
                user.is_staff = 1
            user.save()
            request.session['version'] = '2.0'
            return HttpResponseRedirect(request.POST.get('next'))
    logout(request)
    return render_to_response('logon.html', { 'next' : request.GET.get('next')})

class UserForm(ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    class Meta:
        model = User

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
def ldap_mail_lookup(request):
    return ldap_lookup(request, 'mail')

@login_required
def ldap_cn_lookup(request):
    return ldap_lookup(request, 'cn')

def ldap_lookup(request,attr):
    results = []
    if request.method == "GET":
        if request.GET.has_key(u'q'):
            value = request.GET[u'q']
            if len(value) > 2:
                if request.session.has_key('profile'):
                    if CertProfile.objects.get(id=request.session['profile']).ldap:
                        l = CertProfile.objects.get(id=request.session['profile']).ldap
                        model_results = l.search("ou="+l.user_ou+","+l.base_dn, ldap.SCOPE_SUBTREE, "("+attr+"=*"+value+"*)", [attr])
                        results = [ x[0][1][attr][0] for x in model_results ]
    json = simplejson.dumps(results)
    return HttpResponse(json, mimetype='application/json')

@user_passes_test(lambda u: u.is_staff)
def create_user(request):
    return HttpResponseRedirect("/user/")

@user_passes_test(lambda u: u.is_staff)
def update_user(request, object_id):
    return HttpResponseRedirect("/user/")

@login_required
def start_app(request,object_id):
    try:
        app = App.objects.get(id=object_id)
    except App.DoesNotExist:
        return HttpResponseRedirect("/app/")
    app.up = 1
    app.save()
    return HttpResponseRedirect("/app/")

@login_required
def stop_app(request,object_id):
    try:
        app = App.objects.get(id=object_id)
    except App.DoesNotExist:
        return HttpResponseRedirect("/app/")
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
    try:
        if url == 'sql':
                object = SQL.objects.get(id=object_id)
        elif url == 'ldap':
                object = LDAP.objects.get(id=object_id)
        elif url == 'ssl':
                object = SSL.objects.get(id=object_id)
        elif url == 'ntlm':
                object = NTLM.objects.get(id=object_id)
        elif url == 'kerberos':
                object = Kerberos.objects.get(id=object_id)
        elif url == 'radius':
                object = RADIUS.objects.get(id=object_id)
    except DoesNotExist:
        return HttpResponseRedirect('/'+ url +'/')
    # Remove auth
    if request.method == 'POST' and object_id:       
        try:
            auth = Auth.objects.get(id_method=object.pk, auth_type=url)
            auth.delete()
            object.delete()
        except Auth.DoesNotExist:                 
            return HttpResponseRedirect('/'+ url +'/')
        return HttpResponseRedirect('/'+ url +'/')
    return render_to_response('vulture/'+ url +'_confirm_delete.html', {'object':object, 'user' : request.user})

@login_required
def edit_app(request,object_id=None):
    form = AppForm(request.POST or None,instance=object_id and App.objects.get(id=object_id))
    form.header = Header.objects.order_by("-id").filter(app=object_id)
    # Save new/edited app
    if request.method == 'POST' and form.is_valid():
        dataPosted = request.POST
        #app = form.save(commit=False)
        app = form.save()    
        
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
def edit_sso(request,object_id=None):
    form = SSOForm(request.POST or None,instance=object_id and SSO.objects.get(id=object_id))
    form.post = Post.objects.order_by("-id").filter(sso=object_id)    
    # Save new/edited component
    if request.method == 'POST' and form.is_valid():
        dataPosted = request.POST
        sso = form.save(commit=False)
        sso.type = 'sso_forward'
        sso.save()
	    
        #Delete old posts
        posts = Post.objects.filter(sso=object_id)
        posts.delete()
        
        #nbfields = dataPosted['nbfields']
        #print request.POST
        #Writing new ones
        for id in range((int(str(dataPosted['nbfields']))+1)):
            try:
                desc = dataPosted['field_desc-' + str(id)]
                var = dataPosted['field_var-' + str(id)]
                type = dataPosted['field_type-' + str(id)]
                if dataPosted.has_key('field_encrypted-' + str(id)):
                    if dataPosted['field_encrypted-' + str(id)] == "True" or dataPosted['field_encrypted-' + str(id)] == "on":
                        encryption = True
                    else:
                        encryption = False
                else:
                    encryption = False
                if desc and var and type:
                    instance = Post(sso=sso, field_desc = desc, field_var = var, field_mapped = dataPosted['field_mapped-' + str(id)], field_type = type, field_encrypted = encryption,field_value = dataPosted['field_value-' + str(id)], field_prefix = dataPosted['field_prefix-' + str(id)], field_suffix = dataPosted['field_suffix-' + str(id)])
                    instance.save()
            except:
                pass
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
def edit_translation(request,object_id=None):
    form = TranslationForm(request.POST or None,instance=object_id and Translation.objects.get(id=object_id))
        
    # Save new/edited translation
    if request.method == 'POST' and form.is_valid():
        dataPosted = request.POST
        result = Translation.objects.filter(country=dataPosted['country'], message=dataPosted['message'])
        result.delete()
        form.save()
        return HttpResponseRedirect('/style_translation/')

    return render_to_response('vulture/translation_form.html', {'form': form, 'user' : request.user})

@login_required
def edit_plugin(request,object_id=None):
    form = MapURIForm(request.POST or None,instance=object_id and MapURI.objects.get(id=object_id))
        
    # Save new/edited translation
    if request.method == 'POST' and form.is_valid():
        dataPosted = request.POST
        result = MapURI.objects.filter(id=object_id)
        result.delete()
        if dataPosted['app']:
	    app = App.objects.get(id=dataPosted['app'])
	else:
	    app = None 
        uri = dataPosted['uri_pattern']
        type = dataPosted['type']
        if type != 'Rewrite':
            options = type
            type = 'Plugin'
        else:
            options = dataPosted['options']
        instance = MapURI(app=app, uri_pattern = uri, type = type, options = options)
        instance.save()
        return HttpResponseRedirect('/map_uri/')
    return render_to_response('vulture/mapuri_form.html', {'form': form, 'user' : request.user})
