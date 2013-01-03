# -*- coding: utf-8 -*-
from django.db import connection
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required, user_passes_test, permission_required
from django.contrib.auth.forms import SetPasswordForm
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response, get_object_or_404
from django.template.loader import get_template
from django.views.generic.list_detail import object_list
from django.views.generic.create_update import update_object, create_object, delete_object
from time import sleep
import ldap
import re
from memcached import MC
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
    if request.method == 'POST': 
        version = str(int(request.POST['version'])) 
        cur = connection.cursor()
        Conf.objects.filter(var='version_conf').update(value=version)
        myname = Conf.objects.get(var='name').value
        MC.set(myname+":version",version)
    last = MC.get(MC.VERSIONKEY) or 0
    next_ = str(int(last)+1)
    return render_to_response('vulture/cluster_list.html', {'last_version':last, 'next_version':next_, 'object_list':MC.list_servers()})

@permission_required('vulture.change_intf')
def edit_intf(request,object_id=None):
    form = IntfForm(request.POST or None,instance = object_id and Intf.objects.get(id=object_id))
    if request.method == 'POST' and form.is_valid():
        intf = form.save()
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
    for app in apps:
        # Delete memcached records to update config
        MC.delete(app.name + ':app')
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
        for app in apps:
            # Delete memcached records to update config
            MC.delete("%s:app"%app.name)
    return render_to_response('vulture/intf_list.html',
                              {'object_list': Intf.objects.all(), 'k_output': k_output, 'user' : request.user})
                              
@permission_required('vulture.reload_intf')
def reload_all_intfs(request):
    k_output = "Reloading all interface :<br>"
    intfs = Intf.objects.all()
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
                    MC.delete(app.name + ':app')
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
        auth = get_object_or_404(Auth, id_method=obj.pk, auth_type=url)
        auth.delete()
        obj.delete()
        return HttpResponseRedirect('/'+ url +'/')
    return render_to_response('vulture/generic_confirm_delete.html', {'object':obj, 'category' : 'Authentication', 'name' : url.capitalize(),'url' : '/' + url, 'user' : request.user})

def link_path(src,dst,regex):
    files=os.listdir(src)
    for f in files:
        if not regex or re.match(regex,f):
            try:
                os.symlink(src+"/"+f , dst+"/"+f)
            except:
                pass

#@permission_required('vulture.change_app')
#def edit_app2(request,object_id=None):
#   form = AppForm(request.POST or None,instance=object_id and App.objects.get(id=object_id))
#   form.header = Header.objects.order_by("-id").filter(app=object_id)
#   # Save new/edited app
#   if request.method == 'POST' and form.is_valid():
#       appdirname = request.POST['name']
#       appdirname = appdirname.replace("/","_")
#       regex = re.compile("[\w\-\.]+")
#       if not regex.match(appdirname): 
#           raise ValueError(appdirname+"%s does not match a valid app name")
#       path = settings.CONF_PATH+"security-rules/"
#       dataPosted = request.POST
#       #app = form.save(commit=False)
#       app = form.save()
#       #Delete old headers
#       headers = Header.objects.filter(app=object_id)
#       headers.delete()
#       modsecurityconf = ('version', 'action', 'motor', 'paranoid', 'UTF', 'XML', 'BodyAccess', 'max_num_args', 'arg_name_length', 'arg_length', 'total_arg_length', 'max_file_size', 'combined_file_size', 'allowed_http', 'BT_activated', 'DoS_activated', 'DoS_burst_time_slice', 'DoS_counter_threshold', 'DoS_block_timeout', 'Custom' )
#       modsecurityfile = []
#       if "MS_Activated" in dataPosted:
#           if not os.path.exists(path):
#               os.mkdir(path,0770)
#           if not os.path.exists(path+"CUSTOM/"):
#               os.mkdir(path+"CUSTOM/",0770)
#           if not os.path.exists(path+"CUSTOM/"+appdirname):
#               os.mkdir(path+"CUSTOM/"+appdirname,0770)
#           f = open(path+"CUSTOM/"+appdirname+"/vulture-"+appdirname+".conf",'w')            
#           #deal with data for modsecurity
#           for row in modsecurityconf:
#               if row in dataPosted:
#                   if row == 'version':
#                       if not "/" in app.name:
#                           f.write("# Specify CRS version in the audit logs.\n")
#                           f.write("SecComponentSignature \"core ruleset/"+dataPosted['version']+"\""+"\n")
#                           f.write("\n\n")
#                   elif row == 'action':
#                       if dataPosted['action'] == "Log_Only":
#                           f.write("SecRuleEngine DetectionOnly"+"\n")
#                           f.write("SecDefaultAction \"phase:2,pass,nolog,auditlog\""+"\n")
#                           f.write("\n\n")
#                       elif dataPosted['action'] == "Log_Block":
#                           f.write("SecRuleEngine On"+"\n")
#                           f.write("SecAuditEngine RelevantOnly"+"\n")
#                           f.write("SecDefaultAction \"phase:2,deny,nolog,auditlog\""+"\n")
#                           f.write("\n\n")
#                   elif row == 'motor':
#                       if dataPosted['motor'] == "Anomaly":
#                           f.write("SecAction \"phase:1,id:'981206',t:none,nolog,pass,setvar:tx.anomaly_score_blocking=on\""+"\n")
#                           f.write("SecAction \"phase:1,id:'981207',t:none,nolog,pass,setvar:tx.critical_anomaly_score="+dataPosted['critical_score']+",setvar:tx.error_anomaly_score="+dataPosted['error_score']+",setvar:tx.warning_anomaly_score="+dataPosted['warning_score']+",setvar:tx.notice_anomaly_score="+dataPosted['notice_score']+"\""+"\n")
#                           f.write("SecAction \"phase:1,id:'981208',t:none,nolog,pass,setvar:tx.inbound_anomaly_score_level="+dataPosted['inbound_score']+"\""+"\n")
#                           f.write("SecAction \"phase:1,id:'981209',t:none,nolog,pass,setvar:tx.outbound_anomaly_score_level="+dataPosted['outbound_score']+"\""+"\n")
#                           f.write("\n\n")
#                   elif row == 'paranoid':
#                       f.write("SecAction \"phase:1,id:'981210',t:none,nolog,pass,setvar:tx.paranoid_mode=1\""+"\n")
#                       f.write("\n\n")                    
#                   elif row == 'UTF':
#                       f.write("SecAction \"phase:1,id:'981216',t:none,nolog,pass,setvar:tx.crs_validate_utf8_encoding=1\""+"\n")
#                       f.write("\n\n")                    
#                   elif row == 'XML':
#                       f.write("SecRule REQUEST_HEADERS:Content-Type \"text/xml\" \"chain,phase:1,id:'981053',t:none,t:lowercase,pass,nolog\""+"\n")
#                       f.write("SecRule REQBODY_PROCESSOR \"!@streq XML\" \"ctl:requestBodyProcessor=XML\""+"\n")
#                       f.write("\n\n")                    
#                   elif row == 'BodyAccess':
#                       f.write("SecRequestBodyAccess On"+"\n")        
#                       f.write("\n\n")
#                   elif row == 'max_num_args':
#                       if dataPosted[row] == '':
#                           f.write("#SecAction \"phase:1,id:'981211',t:none,nolog,pass,setvar:tx.max_num_args=\""+"\n")
#                       else:
#                           f.write("SecAction \"phase:1,id:'981211',t:none,nolog,pass,setvar:tx.max_num_args="+dataPosted[row]+"\""+"\n")
#                   elif row == 'arg_name_length':
#                       if dataPosted[row] == '':
#                           f.write("#SecAction \"phase:1,t:none,nolog,pass,setvar:tx.arg_name_length=100\""+"\n")
#                       else:
#                           f.write("SecAction \"phase:1,t:none,nolog,pass,setvar:tx.arg_name_length="+dataPosted[row]+"\""+"\n")
#                   elif row == 'arg_length':
#                       if dataPosted[row] == '':
#                           f.write("#SecAction \"phase:1,t:none,nolog,pass,setvar:tx.arg_length=400\""+"\n")
#                       else:
#                           f.write("SecAction \"phase:1,t:none,nolog,pass,setvar:tx.arg_length="+dataPosted[row]+"\""+"\n")
#                   elif row == 'total_arg_length':
#                       if dataPosted[row] == '':
#                           f.write("#SecAction \"phase:1,t:none,nolog,pass,setvar:tx.total_arg_length=64000\""+"\n")
#                       else:
#                           f.write("SecAction \"phase:1,t:none,nolog,pass,setvar:tx.total_arg_length="+dataPosted[row]+"\""+"\n")
#                   elif row == 'max_file_size':
#                       if dataPosted[row] == '':
#                           f.write("#SecAction \"phase:1,t:none,nolog,pass,setvar:tx.max_file_size=1048576\""+"\n")
#                       else:
#                           f.write("SecAction \"phase:1,t:none,nolog,pass,setvar:tx.max_file_size="+dataPosted[row]+"\""+"\n")
#                   elif row == 'combined_file_size':
#                       if dataPosted[row] == '':
#                           f.write("#SecAction \"phase:1,t:none,nolog,pass,setvar:tx.combined_file_sizes=1048576\""+"\n")
#                       else:
#                           f.write("SecAction \"phase:1,t:none,nolog,pass,setvar:tx.combined_file_sizes="+dataPosted[row]+"\""+"\n")
#                   elif row == 'allowed_http':
#                       f.write("SecAction \"phase:1,id:'981212',t:none,nolog,pass, setvar:'tx.allowed_methods="+dataPosted['allowed_http']+"', setvar:'tx.allowed_request_content_type="+dataPosted['allowed_content_type']+"', setvar:'tx.allowed_http_versions="+dataPosted['allowed_http_version']+"', setvar:'tx.restricted_extensions="+dataPosted['restricted_extensions']+"', setvar:'tx.restricted_headers="+dataPosted['restricted_headers']+"'\""+"\n")
#                       f.write("\n\n")             
#                   elif row == 'BT_activated':
#                       f.write("SecAction \"phase:1,id:'981214',t:none,nolog,pass, setvar:'tx.brute_force_protected_urls="+dataPosted['protected_urls']+"', setvar:'tx.brute_force_burst_time_slice="+dataPosted['BT_burst_time_slice']+"', setvar:'tx.brute_force_counter_threshold="+dataPosted['BT_counter_threshold']+"', setvar:'tx.brute_force_block_timeout="+dataPosted['BT_block_timeout']+"'\""+"\n")
#                   elif row == 'DoS_activated':
#                       f.write("SecAction \"phase:1,id:'981215',t:none,nolog,pass, setvar:'tx.dos_burst_time_slice="+dataPosted['DoS_burst_time_slice']+"', setvar:'tx.dos_counter_threshold="+dataPosted['DoS_counter_threshold']+"', setvar:'tx.dos_block_timeout="+dataPosted['DoS_block_timeout']+"'\""+"\n")
#                   elif row == 'Custom':
#                       f.write(dataPosted[row]+"\n")
#           f.write("SecRule REQUEST_HEADERS:User-Agent \"^(.*)$\" \"phase:1,id:'981217',t:none,pass,nolog,t:sha1,t:hexEncode,setvar:tx.ua_hash=%{matched_var}\""+"\n")
#           f.write("SecRule REQUEST_HEADERS:x-forwarded-for \"^\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b\" \"phase:1,id:'981225',t:none,pass,nolog,capture,setvar:tx.real_ip=%{tx.1}\""+"\n")
#           f.write("SecRule &TX:REAL_IP \"!@eq 0\" \"phase:1,id:'981226',t:none,pass,nolog,initcol:global=global,initcol:ip=%{tx.real_ip}_%{tx.ua_hash}\""+"\n")
#           f.write("SecRule &TX:REAL_IP \"@eq 0\"  \"phase:1,id:'981218',t:none,pass,nolog,initcol:global=global,initcol:ip=%{remote_addr}_%{tx.ua_hash}\""+"\n")
#           f.close()
#           #deal with directories
#           directory = {
#                           "base_rules/":"securitybase",
#                           "experimental_rules/":'securityexp',
#                           "optional_rules/":'securityopt',
#                           "slr_rules/":'securityslr'
#                      }
#           
#           #create directory for app conf if needed
#           if not os.path.exists(path+'activated/'+appdirname):
#               os.mkdir(path+'activated/'+appdirname,0770)
#               
#           for key, v in directory.iteritems():
#               value = request.POST.getlist(v)
#               for init in form.fields[v].initial:
#                   found = 0
#                   for val in value:
#                       if init == val:
#                           found = 1
#                           break
#                   if found == 0:
#                       os.remove(path+"activated/"+appdirname+"/"+init)
#               for val in value:
#                   try:
#                       os.symlink(path+key+val,path+"activated/"+appdirname+"/"+val)
#                   except:
#                       pass
#           try:
#               os.symlink(path+"CUSTOM/"+appdirname+"/vulture-"+appdirname+".conf",path+"activated/"+appdirname+"/vulture-"+appdirname+".conf")
#           except:
#               pass
#           for src in ("base_rules","optional_rules","experimental_rules","slr_rules"):
#               link_path(path+src,path+"activated/"+appdirname,".*\.data$")
#       else:
#           if os.path.exists(path+"activated/"+appdirname+"/"):
#               for removefile in os.listdir(path+"activated/"+appdirname+"/"):
#                   os.remove(path+"activated/"+appdirname+"/"+removefile)
#       for data in dataPosted:
#           m = re.match('header_id-(\d+)',data)
#           if m != None:
#               id = m.group(1)
#               desc = dataPosted['field_desc-' + id]
#               type = dataPosted['field_type-' + id]
#               if desc and type:
#                   instance = Header(app=app, name = desc, value = dataPosted['field_value-' + id], type=type)
#                   instance.save()
#       #form.save_m2m()
#       MC.delete('%s:app'%app.name)
#       return HttpResponseRedirect('/app/')
#   #if request.method == 'POST' and not form.is_valid():
#    #   return HttpResponseRedirect('/intf/')
#   return render_to_response('vulture/app_form.html', {'form': form, 'user' : request.user})

@permission_required('vulture.change_app')
def edit_app(request,object_id=None):
    form = AppForm(request.POST or None,instance=object_id and App.objects.get(id=object_id))
    form.header = Header.objects.order_by("-id").filter(app=object_id)
    # Save new/edited app
    if request.method == 'POST' and form.is_valid():
        appdirname = request.POST['name']
        appdirname = appdirname.replace("/","_")
        regex = re.compile("[\w\-\.]+")
        if not regex.match(appdirname): 
            raise ValueError(appdirname+" does not match a valid app name")
        path = "%s/security-rules"%(settings.CONF_PATH)
        custom_p = "%s/CUSTOM"%path
        custom_app_p = "%s/%s"%(custom_p,appdirname)
        app_acti_p = "%s/activated/%s"%(path,appdirname)
        fname = "vulture-%s.conf"%(appdirname)
        fpath = "%s/%s"%(custom_app_p,fname)
        dataPosted = request.POST
        app = form.save()
        #Delete old headers
        headers = Header.objects.filter(app=object_id)
        headers.delete()
        if "MS_Activated" in dataPosted:
            # create needed directories for this app
            for rep in (path,custom_p,custom_app_p,app_acti_p):
                if not os.path.exists(rep):
                    os.mkdir(rep,0770)
            # get variables we send to the template
            mod_secu_vars = {"appname":app.name}
            for row in ('version','action',
                    'motor',
                    'critical_score','warning_score','error_score',
                    'notice_score','inbound_score','outbound_score',
                    'paranoid', 'UTF', 'XML', 'BodyAccess',
                    'max_num_args', 'arg_name_length', 'arg_length',
                    'total_arg_length', 'max_file_size','combined_file_size',
                    'allowed_http','allowed_content_type',
                    'allowed_http_version','restricted_extensions',
                    'restricted_headers',
                    'BT_activated', 'protected_urls',
                    'BT_burst_time_slice', 'BT_counter_threshold',
                    'BT_block_timeout',
                    'DoS_activated', 'DoS_burst_time_slice', 
                    'DoS_counter_threshold', 'DoS_block_timeout', 'Custom' ):
                if row in dataPosted:
                    mod_secu_vars[row]=dataPosted[row]
            # write config file for this app
            t = get_template("mod_secu.conf")
            ctx = Context(mod_secu_vars)
            conf_txt = t.render(ctx)
            f = open(fpath,'wb')
            f.write(conf_txt)
            f.close()
            # create/remove symlinks for activated rules
            directory = {
                            "base_rules":"securitybase",
                            "experimental_rules":'securityexp',
                            "optional_rules":'securityopt',
                            "slr_rules":'securityslr'
                       }
            # create directory for app conf if needed
            # remove deleted rules, add new ones
            for dir_, file_list in directory.iteritems():
                new_files = request.POST.getlist(file_list)
                for old_file in form.fields[file_list].initial:
                    if not old_file in new_files:
                        os.remove("%s/%s"%(app_acti_p,old_file))
                for file_ in new_files:
                    try:
                        os.symlink("%s/%s/%s"%(path,dir_,file_),"%s/%s"%(app_acti_p,file_))
                    except:
                        pass
            # link all data files in app directory
            for src in directory:
                link_path("%s/%s"%(path,src),app_acti_p,".*\.data$")
            try:
                os.symlink(fpath,"%s/%s"%(app_acti_p,fname))
            except:
                pass
        # mod_security was disabled for this app
        else:
            for rep in (custom_app_p,app_acti_p):
                if os.path.exists(rep):
                    for rmfile in os.listdir(rep):
                        os.remove("%s/%s"%(rep,rmfile))
                    os.rmdir(rep)
        # headers .. 
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
        MC.delete('%s:app'%app.name)
        return HttpResponseRedirect('/app/')
    return render_to_response('vulture/app_form.html', {'form': form, 'user' : request.user})
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
        records_nb = str(int(query['records']))
    else:
        records_nb = str(100);
    if 'type' in query and query['type'] in type_list:
        type_ = query['type']
    else:
        type_ = 'error'
    for app in app_list:
        i = i + 1
        log = Log.objects.get (id=app.log_id)
        if object_id == str (i):
            location="%s/Vulture-%s-%s_log"%(log.dir,app.name,type_)
            f = open(location,'rb')
            lines = f.readlines()
            f.close()
            if 'filter' in query:
                reg = re.compile(query['filter'])
                lines = [l for l in lines if reg.match(l)]
            start = len(lines-records_nb)
            if start < 0:
                start = 0
            content = "\n".join(lines[start:start+records_nb]) 
            length = len(content.split("\n"))
            selected = 'selected'
            break;
        else:
            selected=''
        file_list.append ((i,selected,app.name))
    return render_to_response('vulture/event_list.html', {'file_list': file_list, 'log_content': content, 'type_list': type_list, 'type' : type_, 'records' : records_nb, 'length' : length, 'filter' : filter, 'active_sessions' : active_sessions, 'user' : request.user, 'stats_month' : stats_month, 'stats_day' : stats_day, 'stats_hour' : stats_hour, 'stats_failed_month' : stats_failed_month, 'stats_failed_day' : stats_failed_day, 'stats_failed_hour' : stats_failed_hour, 'connections_failed' : connections_failed})
    
@login_required
def export_import_config (request, type):
    query = request.POST
    content = None
    path = None
    if 'path' in query:
        path = query['path']
        argsOK = True
        if type == 'import':
            nIN=path
            nOUT=settings.DATABASE_PATH+"/db"
        elif type == 'export':
            nIN=settings.DATABASE_PATH+"/db"
            nOUT=path
        if os.path.exists(path):
            argsOK = False
    else:    
        content = 'You had not specify type'
        argsOK = False
    if argsOK:
        try:
            fIN=open(nIN,"r")
            fOUT=open(nOUT,"w")
            fOUT.write(fIN.read())
            fOUT.close()
            fIN.close()
            content=type+" database: complete"
        except:
            content = type+" database: failed"
    return render_to_response('vulture/exportimport_form.html', {'type': type, 'path': path, 'content': content})
    
@login_required    
def edit_security (request):
    if request.method == 'POST':
        return HttpResponseRedirect('/security')
    else:
        form = ModSecurityForm()
        return render_to_response('vulture/modsecurity_form.html', {'form' : form, })

