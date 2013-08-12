# -*- coding: utf-8 -*-
from django.db import connection
from django.db.models import Q
from django.forms.models import inlineformset_factory
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required, user_passes_test, permission_required
from django.contrib.auth.forms import SetPasswordForm
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render_to_response, get_object_or_404
from django.template.loader import get_template
from django.views.generic.list_detail import object_list
from django.views.generic.create_update import update_object, create_object, delete_object
from time import sleep
from django.core.exceptions import FieldError
import ldap
import re
from memcached import MC, SynchroDaemon
import vulture.models
from vulture.models import *
from vulture.forms import *

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

@permission_required('vulture.can_modsecurity')
def update_security(request):
    k_output = os.popen("/bin/sh %s/update-rules.sh 2>&1" % (settings.BIN_PATH)).read()
    return render_to_response('vulture/modsecurity_list.html',
                              {'object_list': ModSecurity.objects.all(), 'k_output': k_output, 'user' : request.user })

@permission_required('vulture.manage_cluster')
def manage_cluster(request):
    version_conf = Conf.objects.get(var='version_conf')
    curversion=int(version_conf.value or 0)
    if request.method == 'POST': 
        curversion += 1
        version_conf.value = str(curversion)
        version_conf.save()
    daemon = SynchroDaemon()
    return render_to_response('vulture/cluster_list.html', {'last_version':curversion, 'object_list':daemon.list_servers()})

@permission_required('vulture.delete_appearance')
def remove_appearance(request,object_id=None):
    appearance = get_object_or_404(Appearance, id=object_id)
    if request.method == 'POST' and object_id:
        number = Intf.objects.filter(appearance=object_id).count()
        if number == 0:
            appearance.delete()
            return HttpResponseRedirect("/appearance")
        else:
            raise FieldError("You can t delete Appearance linked with interface")
    return render_to_response("vulture/generic_confirm_delete.html",{"object":appearance,"category":"Application","name" : "Appearance", "url":"/appearance","user":request.user}) 

@permission_required('vulture.delete_template')
def remove_template(request,object_id=None):
    template = get_object_or_404(Template, id=object_id)
    if request.method == 'POST' and object_id:
        number = Appearance.objects.filter(Q(app_down_tpl=object_id) | Q(login_tpl=object_id) | Q(acl_tpl=object_id) | Q(sso_portal_tpl=object_id) | Q(sso_learning_tpl=object_id) | Q(logout_tpl=object_id)).count()
        if number == 0:
            template.delete()
            return HttpResponseRedirect("/template")
        else:
            raise FieldError("You can t delete html model linked with appearance")
    return render_to_response("vulture/generic_confirm_delete.html",{"object":template,"category":"Application","name" : "template", "url":"/template","user":request.user}) 

@permission_required('vulture.delete_template_css')
def remove_template_css(request,object_id=None):
    template_css = get_object_or_404(CSS, id=object_id)
    if request.method == 'POST' and object_id:
        number = Appearance.objects.filter(css=object_id).count()
        if number == 0:
            template_css.delete()
            return HttpResponseRedirect("/template_css")
        else:
            raise FieldError("You can t delete css linked with appearance")
    return render_to_response("vulture/generic_confirm_delete.html",{"object":template_css,"category":"Application","name" : "css", "url":"/template_css","user":request.user}) 

@permission_required('vulture.delete_image')
def remove_image(request,object_id=None):
    image = get_object_or_404(Image, id=object_id)
    if request.method == 'POST' and object_id:
        number = Appearance.objects.filter(image=object_id).count()
        if number == 0:
            image.delete()
            return HttpResponseRedirect("/image")
        else:
            raise FieldError("You can t delete image linked with appearance")
    return render_to_response("vulture/generic_confirm_delete.html",{"object":image,"category":"Application","name" : "log", "url":"/image","user":request.user}) 

@permission_required('vulture.delete_log')
def remove_log(request,object_id=None):
    log = get_object_or_404(Log, id=object_id)
    if request.method == 'POST' and object_id:
        number = App.objects.filter(log=object_id).count()
        number += Intf.objects.filter(log=object_id).count()
        if number == 0:
            log.delete()
            return HttpResponseRedirect("/log")
        else:
            raise FieldError("You can t delete log linked with app or interface")
    return render_to_response("vulture/generic_confirm_delete.html",{"object":log,"category":"System","name" : "log", "url":"/log","user":request.user}) 

@permission_required('vulture.change_intf')
def edit_intf(request,object_id=None):
    form = IntfForm(request.POST or None,instance = object_id and Intf.objects.get(id=object_id))
    if request.method == 'POST' and form.is_valid():
        intf = form.save()
        intf.cas_auth = get_logic_auth_for(intf.cas_auth)
        intf.save()
        return HttpResponseRedirect("/intf")
    return render_to_response('vulture/intf_form.html',
            {'form':form, 'user': request.user })

@permission_required('vulture.change_vintf')
def edit_vintf(request,object_id=None):
    form = VintfForm(request.POST or None,instance = object_id and VINTF.objects.get(id=object_id))
    if object_id:
        vintf = VINTF.objects.get(id=object_id)
        name = vintf.name
        intf = vintf.intf
        ip = vintf.ip
        netmask = vintf.netmask
        broadcast = vintf.broadcast
    else:
        name = None
        ip = None
        intf = None
        netmask = None
        broadcast = None
    if request.method == 'POST' and form.is_valid():
        vintf = form.save()
        return HttpResponseRedirect('/vintf')
    return render_to_response('vulture/vintf_form.html', {'form': form, 'name' : name, 'intf' : intf, 'ip' : ip, 'netmask' : netmask, 'broadcast' : broadcast})

@permission_required('vulture.delete_vintf')
def remove_vintf(request,object_id=None):
    vintf = get_object_or_404(VINTF, id=object_id)
    if request.method == 'POST' and object_id:
        vintf.stop()
        vintf.delete()
        return HttpResponseRedirect("/vintf")
    return render_to_response("vulture/generic_confirm_delete.html",{"object":vintf,"category":"System","name" : "VINTF", "url":"/vintf","user":request.user}) 

@permission_required('vulture.reload_vintf')
def start_vintf(request, object_id=None):
    if object_id:
        vintf = get_object_or_404(VINTF, id=object_id)
        vintf.start()
        return HttpResponseRedirect("/vintf")
    return render_to_response('vulture/vintf_list.html',
                              {'object_list': VINTF.objects.all(), 'user' : request.user })

@permission_required('vulture.reload_vintf')
def stop_vintf(request, object_id=None):
    if object_id:
        vintf = get_object_or_404(VINTF, id=object_id) 
        vintf.stop()
        return HttpResponseRedirect("/vintf")
    return render_to_response('vulture/vintf_list.html',
                              {'object_list': VINTF.objects.all(),'user' : request.user })
    
@permission_required('vulture.reload_vintf')
def reload_all_vintfs(request):
    vintfs = VINTF.objects.all()
    if request.method == 'POST' and object_id:
        for vintf in vintfs :
            vintf.reload()
        return HttpResponseRedirect("/vintf") 
    return render_to_response('vulture/vintf_list.html',
                              {'object_list': VINTF.objects.all(), 'user' : request.user })

@permission_required('vulture.reload_intf')
def start_intf(request, intf_id):
    intf = Intf.objects.get(pk=intf_id)
    fail = intf.maybeWrite()
    if fail: 
        k_output = fail
    else:
        k_output = intf.k('start')
    sleep(2)
    return render_to_response('vulture/intf_list.html',
                              {'object_list': Intf.objects.all(), 'k_output': k_output, 'user' : request.user })

@permission_required('vulture.reload_intf')
def stop_intf(request, intf_id):
    intf = Intf.objects.get(pk=intf_id)
    k_output = intf.k('stop')
    apps = App.objects.filter(intf=intf).all()
    mc = MC()
    for app in apps:
        # Delete memcached records to update config
        mc.delete(app.name + ':app')
    sleep(2)
    return render_to_response('vulture/intf_list.html',
                              {'object_list': Intf.objects.all(), 'k_output': k_output, 'user' : request.user})

@permission_required('vulture.reload_intf')
def reload_intf(request, intf_id):
    intf = Intf.objects.get(pk=intf_id)
    fail = intf.maybeWrite()
    if fail:
        k_output = fail
    else:
        k_output = intf.k('graceful')
    
        apps = App.objects.filter(intf=intf).all()
        mc = MC()
        for app in apps:
            # Delete memcached records to update config
            mc.delete("%s:app"%app.name)
    return render_to_response('vulture/intf_list.html',
                              {'object_list': Intf.objects.all(), 'k_output': k_output, 'user' : request.user})
                              
@permission_required('vulture.reload_intf')
def reload_all_intfs(request):
    k_output = "Reloading all interface :<br>"
    intfs = Intf.objects.all()
    mc = MC()
    for intf in intfs :
        if intf.need_restart:
            fail = intf.maybeWrite()
            if fail:
                k_output += "%s:%s"%(intf.name,fail)
            else:
                k_output += intf.name+":"
                outp = intf.k('graceful')
                if outp:
                    k_output += outp
                else: 
                    k_output += "everything ok"
                k_output += "<br>"
                # Delete memcached records to update config
                for app in App.objects.filter(intf=intf).all():
                    mc.delete(app.name + ':app')
    return render_to_response('vulture/intf_list.html', {'object_list': intfs, 'k_output': k_output, 'user' : request.user})

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

@permission_required('vulture.reload_app')
def start_app(request,object_id):
    app = get_object_or_404(App, id=object_id)
    app.up = 1
    app.save()
    return HttpResponseRedirect("/app/")

@permission_required('vulture.reload_app')
def stop_app(request,object_id):
    app = get_object_or_404(App, id=object_id)
    app.up = 0
    app.save()
    return HttpResponseRedirect("/app/")

@permission_required('vulture.change_auth')
def edit_auth(request, url, object_id=None):
    form_types = {
            'sql':SQLForm,
            'ldap':LDAPForm,
            'ssl':SSLForm,
            'ntlm':NTLMForm,
            'kerberos':KerberosForm,
            'radius':RADIUSForm,
            'cas':CASForm,
            'logic':LogicForm,
            'otp':OTPForm
        }
    obj_cls = Auth.TYPES[url]
    form_cls = form_types[url]
    form = form_cls(
            request.POST or None,
            instance = object_id and obj_cls.objects.get(id=object_id)
            )
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

@permission_required('vulture.delete_auth')
def remove_auth(request, url, object_id=None):
    obj = get_object_or_404(Auth.TYPES[url],id=object_id)
    # Remove auth
    if request.method == 'POST' and object_id:       
       # auth = get_object_or_404(Auth, id_method=obj.pk, auth_type=url)
        obj.delete()
       # auth.delete()
        return HttpResponseRedirect('/'+ url +'/')
    return render_to_response('vulture/generic_confirm_delete.html', {'object':obj, 'category' : 'Authentication', 'name' : url.capitalize(),'url' : '/' + url, 'user' : request.user})

def link_path(src,dst,regex):
    if not os.path.exists(src):
    	return
    files=os.listdir(src)
    for f in files:
        if not regex or re.match(regex,f):
            try:
                os.symlink(src+"/"+f , dst+"/"+f)
            except:
                pass

def get_logic_auth_for(auth):
    if auth and auth.auth_type != 'logic':
        right_auth = [l for l in Logic.objects.filter(login_auth=auth.pk) if l.auths.count()==1]
        if right_auth:
            return Auth.objects.get(auth_type='logic',id_method=right_auth[0].pk)
        else:
            l = Logic(name=auth.name, op='AND', login_auth=auth)
            l.save()
            l.auths = [auth]
            l.save()
            auth = Auth(name=auth.name,auth_type='logic',id_method=l.pk)
            auth.save()
    return auth

@permission_required('vulture.change_app')
def edit_app(request,object_id=None):
    inst = object_id and App.objects.get(pk=object_id)
    form = AppForm(request.POST or None,instance=inst)
    form.header = Header.objects.order_by("-id").filter(app=object_id)
    FJKD = inlineformset_factory(App, JKDirective, extra=4)
    # Save new/edited app
    if request.method == 'POST' and form.is_valid():
        appdirname = request.POST['name']
        appdirname = appdirname.replace("/","")
        regex = re.compile("[\w\-\.]+")
        if not regex.match(appdirname): 
            raise ValueError(appdirname+" does not match a valid app name")
        dataPosted = request.POST
        app = form.save()
        fjkd = FJKD(request.POST,instance=inst)
        if fjkd.is_valid():
            fjkd.save()
        else:
            raise ValueError("bad inline formset !!!!")
        
        # headers .. 
        headers = Header.objects.filter(app=object_id)#Delete old headers
        headers.delete()
        for data in dataPosted:
            m = re.match('header_id-(\d+)',data)
            if m != None:
                id_ = m.group(1)
                desc = dataPosted['field_desc-' + id_]
                type_ = dataPosted['field_type-' + id_]
                if desc and type_:
                    instance = Header(app=app, name = desc, value = dataPosted['field_value-' + id_], type=type_)
                    instance.save()
        # delete cached version of this app in memcache
        MC().delete('%s:app'%app.name)
        # Make sure we're using logic auth there
        app.auth = get_logic_auth_for(app.auth)
        app.save()
        return HttpResponseRedirect('/app/')
    fjkd = FJKD(instance=inst)
    return render_to_response('vulture/app_form.html', {'form': form, 'user' : request.user, 'fjkd':fjkd})
########################################################################

@permission_required('vulture.add_app')
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

@permission_required('vulture.change_sso')
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
def plugincas_config (request):
    allcas = PluginCAS.objects.all()
    conf = allcas and allcas[0] or None
    form = PluginCASForm(request.POST or None, instance = conf)
    if request.method == 'POST' and form.is_valid(): 
        if not conf: 
            conf = form.save(commit=False)
        conf.auth = request.POST['auth'] and Auth.objects.get(id=request.POST['auth']) or None
        conf.field = request.POST['field'] and request.POST['field'] or None
        conf.save()
    return render_to_response('vulture/plugincas_form.html', {'form': form, 'user' : request.user})

@permission_required('vulture.change_acl')
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
    user_profile_form = UserProfileForm2(request.POST or None,instance=object_id and UserProfile.objects.get(user=object_id))

    # Save new/edited component
    if request.method == 'POST' and form.is_valid():
        user = form.save(commit=False)
        user.save()
        if user_profile_form.is_valid():
            user_profile_form.save()
        return HttpResponseRedirect('/user/')
    return render_to_response('vulture/useredit_form.html', {'form': form, 'user_profile': user_profile_form, 'user' : request.user, 'id' : object_id})
    
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
    
@permission_required('vulture.change_localization')
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
    filter_ = ''
    type_list = ('access', 'error', 'authentication', 'security')
    type_ = 'error'
    records_nb = 100;
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
        object_id = str(int(query['file']))
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
        records_nb = int(query['records'])

    app = None
    if object_id and 'type' in query and query['type'] in type_list:
        app = get_object_or_404(App, id=object_id)
        type_ = query['type']
        log = Log.objects.get (id=app.log_id)
        location="%s/Vulture-%s-%s_log"%(log.dir,app.name,type_)
        f = open(location,'rb')
        lines = f.readlines()
        f.close()
        if 'filter' in query:
            filter_ = query['filter']
            reg = re.compile(filter_)
            lines = [l for l in lines if reg.match(l)]
        start = len(lines)-records_nb
        if start < 0:
            start = 0
        content = "\n".join(lines[start:start+records_nb]) 
        length = len(content.split("\n"))
    file_list = [(a.pk,(app and app.pk==a.pk and 'selected' or ''),a.name) for a in App.objects.all()]
    return render_to_response('vulture/event_list.html', {'file_list': file_list, 'log_content': content, 'type_list': type_list, 'type' : type_, 'records' : str(records_nb), 'length' : length, 'filter' : filter_, 'active_sessions' : active_sessions, 'user' : request.user, 'stats_month' : stats_month, 'stats_day' : stats_day, 'stats_hour' : stats_hour, 'stats_failed_month' : stats_failed_month, 'stats_failed_day' : stats_failed_day, 'stats_failed_hour' : stats_failed_hour, 'connections_failed' : connections_failed})
    
@login_required
def export_import_config (request, type_):
    content = None
    path = None
    if request.method == "POST": 
        query = request.POST
        if 'path' in query:
            path = query['path']
            argsOK = True
            if type_ == 'import':
                nIN=path
                nOUT=settings.DATABASE_PATH+"/db"
            elif type_ == 'export':
                nIN=settings.DATABASE_PATH+"/db"
                nOUT=path
                if os.path.exists(path):
                    argsOK = False
        else:    
            content = 'Invalid query'
            argsOK = False
        if argsOK:
            try:
                fIN=open(nIN,"r")
                fOUT=open(nOUT,"w")
                fOUT.write(fIN.read())
                fOUT.close()
                fIN.close()
                content=type_+" database: complete"
            except:
                content = type_+" database: failed"
    return render_to_response('vulture/exportimport_form.html', {'type': type_, 'path': path, 'content': content})
    
@login_required    
def edit_security (request, object_id=None):
    form = ModSecurityForm(request.POST or None,instance=object_id and ModSecConf.objects.get(id=object_id))
    if request.method == 'POST':
        if form.is_valid():
            form.save()
            return HttpResponseRedirect('/security')
    return render_to_response('vulture/modsecurity_form.html', {'form' : form, })

@login_required    
def edit_group(request, object_id=None):
    inst=object_id != None and Groupe.objects.get(pk=object_id) or None
    if request.method == 'POST':
        form = GroupSecurityForm(request.POST,request.FILES,instance=inst)
        if form.is_valid(): 
            groupe = form.save()
            try:
                if form.cleaned_data.get('path'):
                    fd = groupe.get_file(filecontent = request.FILES['path'].read())
                else:
                    fd = groupe.get_file(url = form.cleaned_data.get('url'))
                groupe.extract_archive(fd)
            except:
                groupe.delete()
                raise
            return HttpResponseRedirect('/group/%s/'%groupe.pk)
    else:
        form = GroupSecurityForm(instance=inst )
    return render_to_response('vulture/group_form.html', {'form' : form, })

@login_required    
def edit_rule(request, object_id=None):
    form = CustomRuleForm(request.POST or None,instance=object_id and CustomRule.objects.get(id=object_id))
    if request.method == 'POST':
        if form.is_valid():
            form.save()
        return HttpResponseRedirect('/customrule')
    return render_to_response('vulture/custom_rule_form.html', {'form' : form, })

def view_group(request, object_id):
    groupe = Groupe.objects.get(pk=object_id);
    return render_to_response('vulture/group_view.html', {'groupe':groupe})

def edit_policy_files(request, object_id):
    policy = get_object_or_404(Politique, id=object_id)
    
    if request.method=="POST":
        #regex des files affectes a une policy
        reg=re.compile('^file_(\d+)$')
        ids=[int(m.group(1)) for m in [ reg.match(n) for n in request.POST] if m]
                
        #== delete from fichier_politique where politique.id == politique.pk and Fichier.id not in ids #query_set, on met un filter
        FichierPolitique.objects.filter(politique=policy).exclude(fichier__in=ids).delete()
        left_ids = [f.fichier.pk for f in FichierPolitique.objects.filter(politique=policy)]
        
        for new_id in set(ids)-set(left_ids):
            policy.fichierpolitique_set.create(fichier_id=new_id)

        return HttpResponseRedirect('/policy/%s'%policy.pk)

    selected = [f.fichier.pk for f in FichierPolitique.objects.filter(politique=policy)]
    t=[]
    for g in Groupe.objects.all():
        fichiers = []
        for f in g.fichier_set.filter(name__endswith='.conf'):
            fichiers += [{'name':f.name,'pk':f.pk,'checked':f.pk in selected}]
        t+=[{'nom':g.name, 'fichiers':fichiers}]

    return render_to_response('vulture/policy_file_form.html', {'groups':t})

def edit_policy(request, object_id=None):
    if object_id!= None:
        politique = get_object_or_404(Politique, pk=object_id)
    else:
        politique = None
    form = PolicyForm(request.POST or None, instance = politique)

    if request.method=="POST":
        if form.is_valid():
            policy = form.save()
            IgnoreRules.objects.filter(fichier_politique__in=policy.fichierpolitique_set.all()).delete() 
            
            #creation des ignores rules en base
            reg = re.compile('ignore_file_(\d+)_(\d+)')
            for data in request.POST:
                n = reg.match(data)
                if n:
                    fichier_politique = n.group(1)
                    
                    if request.POST[data]: 
                        ignore_rule = IgnoreRules(fichier_politique = FichierPolitique.objects.get(pk=fichier_politique), rules_number =request.POST[data])
                        ignore_rule.save()
                        
            if 'add_button' in request.POST :
                return HttpResponseRedirect('/policy/%s/files'%policy.pk)
            return HttpResponseRedirect('/policy/')
    return render_to_response('vulture/policy_form.html', {'form':form,'policy_files': politique and politique.fichierpolitique_set.all() })


@login_required
def generator (request):
    return render_to_response('vulture/modsecurity_generator.html')

@login_required
def remove_security(request,object_id=None):
    security = get_object_or_404(ModSecConf, id=object_id)
    if request.method == 'POST':
        security.delete()
        return HttpResponseRedirect('/security')
    return render_to_response("vulture/generic_confirm_delete.html",{"object":security,"category":"Web Firewall","name" : "ModSecurity", "url":"/security","user":request.user})

@login_required
def edit_jkworker(request, object_id=None):
    if object_id != None:
        jkw = JKWorker.objects.get(pk=object_id)
    else:
        jkw = None
    form = JKWorkerForm(request.POST or None,instance=jkw)
    JIL = inlineformset_factory(JKWorker, JKWorkerProp, extra=3)
    if request.method == 'POST':
        if form.is_valid():
            jkw = form.save()
        else :
            raise ValueError("bad form!!!! %s"%form.errors);
        jkpf = JIL(request.POST,instance=jkw)
        if jkpf.is_valid():
            jkpf.save()
            fpath = "%sworker.properties"%settings.CONF_PATH
            f = open(fpath,'w+')
            f.write(jkw.genConf())
        else:
            raise ValueError("bad inline formset !!!!");
        return HttpResponseRedirect('/jk/')
    jkpf = JIL(instance=jkw)
    return render_to_response('vulture/jk_form.html', {'form': form, 'formset':jkpf}) 

@login_required
def delete_jkworker(request, object_id=None):
    #obj = get_object_or_404(JKWorker,pk=object_id)
    jkw = JKWorker.objects.get(pk=object_id)
    if request.method == 'POST':
        jkw.delete()
        fpath = "%sworker.properties"%settings.CONF_PATH
        f = open(fpath,'w+')
        f.write(jkw.genConf())
        return HttpResponseRedirect("/jk")
    return render_to_response("vulture/generic_confirm_delete.html",{"object":jkw,"category":"Web Applications","name":"Mod_JK","url":"/jk","user":request.user})

@login_required
def edit_style(request, object_id=None):
    inst=object_id != None and AdminStyle.objects.get(pk=object_id) or None
    if request.method == 'POST':
        form = AdminStyleForm(request.POST,instance=inst)
        if form.is_valid(): 
            form.save()
            return render_to_response('vulture/style_form.html', {'form' : form, })
    else:
        form = AdminStyleForm(instance=inst )
    return render_to_response('vulture/style_form.html', {'form' : form, })

def view_css(request):
    try:
        if request.user:
            # TODO : fix this (use post_save instead)
            try:
                style = request.user.get_profile().style 
                return HttpResponse(content=style.style, mimetype='text/css')
            except:
                up = UserProfile(user=request.user)
                up.save()
                style = up.style 
    except:
        style = AdminStyle.objects.get(name='default')
    return HttpResponse(content=style.style, mimetype='text/css')
