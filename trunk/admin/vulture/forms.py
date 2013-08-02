# -*- coding: utf-8 -*-
from vulture.models import *
from django import forms
from django.contrib.auth.models import Permission
from django.utils.translation import gettext as _
from django.contrib.auth.forms import UserCreationForm, SetPasswordForm, UserChangeForm
import os
import hashlib
import ifconfig

class PolicyForm(forms.ModelForm):
    class Meta:
        model=Politique

class IntfForm(forms.ModelForm):
    def __init__(self,*args,**kwargs):
        super(forms.ModelForm,self).__init__(*args,**kwargs)
        intf = kwargs["instance"]
        runnin_itf = [z.intf for z in VINTF.objects.all()]
        CHOICES = []
        li = []
        for x in [ (f["intf"],f["ip"]) for f in VINTF.objects.values('intf','ip')] + [z for z in ifconfig.getIntfs().items()]:
            if not x in li:    
                li += [x]
        for itf in li:
            CHOICES += [(itf[1],"%s -> %s"%itf)]
        CHOICES += [("0.0.0.0","any -> 0.0.0.0")]
        CHOICES.sort()
        self.fields["ip"] = forms.ChoiceField(choices = CHOICES)
        self.fields['srv_ka'] = forms.BooleanField(initial=intf and intf.srv_ka or True,required=False)
        self.fields['srv_ka'].widget.attrs["onchange"]="srv_ka_changed()"
    def clean_srv_ka_max_req(self):
        ka = self.cleaned_data["srv_ka"]
        max_req = self.cleaned_data["srv_ka_max_req"]
        if ka and not max_req:
            raise forms.ValidationError("MaxKeepAliveRequests must be filled when KeepAlive is in use")
        return max_req
    def clean_srv_ka_timeout(self):
        ka = self.cleaned_data["srv_ka"]
        ka_timeout = self.cleaned_data["srv_ka_timeout"]
        if ka and not ka_timeout:
            raise forms.ValidationError("KeepAliveTimeout must be filled when KeepAlive is in use")
        return ka_timeout
    class Meta:
        model = Intf
#        exclude=('srv_ka')

class VintfForm(forms.ModelForm):
    def __init__(self,*args, **kwargs):
        super(forms.ModelForm,self).__init__(*args, **kwargs)
        vintf = kwargs["instance"]
        if vintf:
            CHOICES = [[vintf.intf]*2]
        else:
            runnin_itf = [z.intf for z in VINTF.objects.all()]
            CHOICES = []
        #retrieve the next available virtual interface name for a given real interface ( ie. eth0 -> eth0:3 )
            for itf in filter(None,[not ':' in x and x or None for x in ifconfig.getIntfs()]):
                id_next = 1
                name_next = "%s:%s"%(itf,id_next)
                while name_next in runnin_itf : 
                    id_next +=1 
                    name_next = "%s:%s"%(itf,id_next)
                CHOICES += [[name_next]*2]
                        
        self.fields["intf"] = forms.ChoiceField(choices = CHOICES)
    class Meta:
        model = VINTF

class UserProfileForm(UserCreationForm):
    is_staff = forms.BooleanField(required=False)
    is_superuser = forms.BooleanField(required=False)
    def __init__(self, *args, **kwargs):
        super(UserProfileForm, self).__init__(*args, **kwargs)

    def save(self, commit=False):
        user = super(UserProfileForm, self).save(commit=False)
        user.is_staff = self.cleaned_data['is_staff']
        user.is_superuser = self.cleaned_data['is_superuser']
        user.save()

        # try:
            # profile = user.get_profile()
        # except:
            # profile = UserProfile(user=user)

        #profile.nickname = self.cleaned_data['nickname']
        #profile.company = self.cleaned_data['company']
        #profile.save()

        return user
        
class MyUserChangeForm(UserChangeForm):
    #Bug in django (must send at least one field)
    edit = forms.BooleanField()
    permissions = forms.ModelMultipleChoiceField(queryset=Permission.objects.filter(content_type__app_label="vulture"), widget=forms.CheckboxSelectMultiple, required=False)
    def __init__(self, *args, **kwargs):
        super(MyUserChangeForm, self).__init__(*args, **kwargs)
        del self.fields['username']
        del self.fields['password']
        del self.fields['last_login']
        del self.fields['date_joined']
        del self.fields['is_active']
        # This is a declared field we really want to be removed
       
class PluginCASForm(forms.ModelForm):
    auth = forms.ModelChoiceField(required=False, queryset=Auth.objects.filter(auth_type__in=['sql','ldap']))
    class Meta:
        model = PluginCAS
         
class AppForm(forms.ModelForm):
    class Meta:
        model = App

class CustomRuleForm(forms.ModelForm):
    class Meta:
        model = CustomRule


class AppCopy(forms.Form):
    app = forms.ModelChoiceField(required=True, queryset=App.objects.all())
    name = forms.CharField()

class ACLForm(forms.ModelForm):
    auth = forms.ModelChoiceField(required=False, queryset=Auth.objects.filter(auth_type__in=['sql','ldap']))
    class Meta:
        model = ACL

class OTPForm(forms.ModelForm):
    auth = forms.ModelChoiceField(required=False, queryset=Auth.objects.filter(auth_type__in=['sql','ldap']))
    class Meta:
        model = OTP

class SQLForm(forms.ModelForm):
    # def clean_database(self):
        # database = self.cleaned_data["database"]
        # try:
            # f=open("%s" % (database), 'r')
        # except:
            # raise forms.ValidationError("Database path is incorrect or cannot be read by Apache")           
        # return database
    password = forms.CharField(widget=forms.PasswordInput,required=False)
    class Meta:
        model = SQL

class LDAPForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    class Meta:
        model = LDAP

class SSLForm(forms.ModelForm):
    class Meta:
        model = SSL

class KerberosForm(forms.ModelForm):
    #def clean_keytab(self):
    #    keytab = self.cleaned_data["keytab"]
    #    try:
    #        f=open("%s" % (keytab), 'r')
    #    except:
    #        raise forms.ValidationError("File path is incorrect or cannot be read by Apache")           
    #    return keytab
    class Meta:
        model = Kerberos

class NTLMForm(forms.ModelForm):
    class Meta:
        model = NTLM

class RADIUSForm(forms.ModelForm):
    secret = forms.CharField(widget=forms.PasswordInput)
    class Meta:
        model = RADIUS
        
class CASForm(forms.ModelForm):
    class Meta:
        model = CAS

class LogicForm(forms.ModelForm):
    class Meta:
        model = Logic

class SSOForm(forms.ModelForm):
    auth = forms.ModelChoiceField(required=False,queryset=Auth.objects.filter(auth_type__in=['sql','ldap']))
    class Meta:
        model= SSO
        
class ModSecurityForm(forms.ModelForm):
    
    class Meta:
        model = ModSecConf

class GroupSecurityForm(forms.ModelForm):
    url  = forms.URLField(required=False)
    path = forms.FileField(required=False)

    def clean(self):
        cleaned_data = super(GroupSecurityForm, self).clean()
        path = cleaned_data.get("path")
        url = cleaned_data.get("url")
        name = cleaned_data.get("name")

        for groupName in [g.name for g in Groupe.objects.all()]:
            if name == groupName:
                raise forms.ValidationError("/!\ already Used Rules set Name")

        if (not url) ^ (not path):
            # Only do something if one field is valid 
            return cleaned_data
        else:
            raise forms.ValidationError("fill in valid url or valid path to validate please")
    
        # Always return the full collection of cleaned data.
    class Meta:
        model = Groupe
        

class LocalizationForm(forms.ModelForm):
    class Meta:
        model = Localization
    
    def clean(self):
        country = self.cleaned_data.get('country')
        message = self.cleaned_data.get('message')

        try:
            messages = Localization.objects.get(country=country, message=message)
            messages.delete()
        except Localization.DoesNotExist:
            pass
        return self.cleaned_data

class PluginForm(forms.ModelForm):
    class Meta:
        model = Plugin
        
class AppearanceForm(forms.ModelForm):
    class Meta:
        model = Appearance

class JKWorkerForm(forms.ModelForm):
    reference = forms.ModelChoiceField(
            queryset=JKWorker.objects.filter(is_template=True),required=False)
    class Meta:
        model = JKWorker

class AdminStyleForm(forms.ModelForm):
    class Meta:
        model = AdminStyle

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
