# -*- coding: utf-8 -*-
from vulture.models import *
from django import forms
from django.utils.translation import gettext as _
import hashlib

class UserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput, max_length=128, required=False)
    c_password = forms.CharField(widget=forms.PasswordInput, max_length=128, required=False)
    def __init__(self, *args, **kwargs):
        self.edit = False
        super(UserForm, self).__init__(*args, **kwargs)
        instance = getattr(self, 'instance', None)
        if instance and instance.id:
            self.edit = True
        # now modify self.fields dependent on the value of self.edit

    def clean(self):
        password = self.cleaned_data.get('password')
        c_password = self.cleaned_data.get('c_password')
        if password == c_password:
            if not password:
                if self.edit :
                    #Nothing to to
                    return self.cleaned_data
                else:
                    msg = u"Password can't be empty"
                    self._errors["password"] = self.error_class([msg])
                    self._errors["c_password"] = self.error_class([msg])
                    
                    if c_password:
                        del self.cleaned_data["c_password"]
                    if password:
                        del self.cleaned_data["password"]
            #Encode to sha1
            else:
                self.cleaned_data["password"] = hashlib.sha1(self.cleaned_data.get("password")).hexdigest()
        else:
            msg = u"Password and confirm password must be the same"
            self._errors["password"] = self.error_class([msg])
            self._errors["c_password"] = self.error_class([msg])
            
            if c_password:
                del self.cleaned_data["c_password"]
            if password:
                del self.cleaned_data["password"]

        return self.cleaned_data
    class Meta:
        model = User
        
class AppForm(forms.ModelForm):
    security = forms.ModelMultipleChoiceField(widget=forms.CheckboxSelectMultiple,required=False, queryset=ModSecurity.objects.all())
    auth = forms.ModelMultipleChoiceField(required=False, queryset=Auth.objects.all())

    def clean_auth(self):
        auth = self.cleaned_data["auth"]
        if len(auth) > 1:
            for a in auth:
                if a.auth_type == "kerberos":
                    raise forms.ValidationError("Kerberos must be the only auth")
                if a.auth_type == "ntlm":
                    raise forms.ValidationError("NTLM must be the only auth")
                if a.auth_type == "radius":
                    raise forms.ValidationError("RADIUS must be the only auth")
        return auth
    class Meta:
        model = App

class ACLForm(forms.ModelForm):
    auth = forms.ModelChoiceField(required=False, queryset=Auth.objects.filter(auth_type__in=['sql','ldap']))
    class Meta:
        model = ACL

class SQLForm(forms.ModelForm):
    # def clean_database(self):
        # database = self.cleaned_data["database"]
        # try:
            # f=open("%s" % (database), 'r')
        # except:
            # raise forms.ValidationError("Database path is incorrect or cannot be read by Apache")           
        # return database
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

class SSOForm(forms.ModelForm):
    auth = forms.ModelChoiceField(required=False, queryset=Auth.objects.filter(auth_type__in=['sql','ldap']))
    class Meta:
        model= SSO

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