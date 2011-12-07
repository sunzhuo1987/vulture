# -*- coding: utf-8 -*-
from vulture.models import *
from django import forms
from django.utils.translation import gettext as _
from django.contrib.auth.forms import UserCreationForm, SetPasswordForm, UserChangeForm
import hashlib

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
    #Bug in django
    edit = forms.BooleanField()
    def __init__(self, *args, **kwargs):
        super(MyUserChangeForm, self).__init__(*args, **kwargs)
        del self.fields['username']
        del self.fields['password']
        del self.fields['last_login']
        del self.fields['date_joined']
        del self.fields['is_active']
        # This is a declared field we really want to be removed
        
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

class AppCopy(forms.Form):
    app = forms.ModelChoiceField(required=True, queryset=App.objects.all())
    name = forms.CharField()

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