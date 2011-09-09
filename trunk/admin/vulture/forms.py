# -*- coding: utf-8 -*-
#from django.newforms import form_for_model
from vulture.models import *
from django import forms
from django.utils.translation import gettext as _

class Headerform(forms.Form):
    name = forms.CharField(label=_('Nom'))
    type = forms.ChoiceField(choices=Header.HEADER_TYPE, initial="none",label=_('Type de header'))
    value = forms.CharField(label=_('Valeur'))

class Rewriteform(forms.Form):
    rewrite_values = forms.CharField(label=_('Regles de reecriture'),widget=forms.Textarea)
    
class Proxydirectivesform(forms.Form):
    proxydirectives_values = forms.CharField(label=_('Directives proxy'),widget=forms.Textarea)
    
class Virtualhostdirectivesform(forms.Form):
    virtualhostdirectives_values = forms.CharField(label=_('Directives VirtualHost'),widget=forms.Textarea)

class CityForm(forms.Form):
    state = forms.ModelChoiceField(queryset=App.objects.all())
    city = forms.ModelChoiceField(queryset=Header.objects.get_empty_query_set())

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
    class Meta:
        model = ACL

class SQLForm(forms.ModelForm):
    def clean_database(self):
        database = self.cleaned_data["database"]
        try:
            f=open("%s" % (database), 'r')
        except:
            raise forms.ValidationError("Database path is incorrect or cannot be read by Apache")           
        return database
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

class SSOForm(forms.ModelForm):
    class Meta:
        model= SSO

class TranslationForm(forms.ModelForm):
    class Meta:
        model = Translation
    def clean(self):
        country = self.cleaned_data.get('country')
        message = self.cleaned_data.get('message')

        messages = Translation.objects.get(country=country, message=message)
        messages.delete()
        return self.cleaned_data

class MapURIForm(forms.ModelForm):
    class Meta:
        model = MapURI

