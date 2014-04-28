#2_0_8_changes.py
new_fields = {}
removed_fields = {}
moved_fields = {}
#2_0_7_636_changes.py
new_fields['vulture.Intf'] = [{'name':'default_url','value':'', 'ask':False, 'legend':'Default redirection url for Intf', 'type':'string'}]
#2_0_7_637_changes.py
new_fields['vulture.App'] = [{'name':'proxypass_directives','value':'', 'ask':False, 'legend':'Proxypass directives', 'type':'string'}]
#2_0_7_640_changes.py
new_fields['vulture.App'].append({'name':'friendly_name','value':'', 'ask':True, 'legend':'Display name of App in Vulture interface, you have to specify distinct name to prevent error', 'type':'string'})
#2_0_7_643_changes.py
new_fields['vulture.App'].append({'name':'sso_kerberos_default','value':False, 'ask':False, 'legend':'', 'type':'string'})
new_fields['vulture.App'].append({'name':'sso_kerberos_domain','value':'', 'ask':False, 'legend':'', 'type':'string'})
#2_0_7_630_changes.py
new_fields['vulture.Log'] = [{'name':'script','value': '', 'ask':False, 'legend':'', 'type':'string'}]

#2_0_7_645_changes.py
new_fields['vulture.SSL_conf'] = [{'name':'ssl_options','value':'+StdEnvVars', 'ask':False, 'legend':'', 'type':'string'}]
new_fields['vulture.SSL_conf'].append({'name':'ssl_protocol','value':'-ALL +SSLv3 +TLSv1', 'ask':False, 'legend':'', 'type':'string'})
new_fields['vulture.SSL_conf'].append({'name':'ssl_cipher_suite','value':'ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM:!LOW:!SSLv2:!EXPORT', 'ask':False, 'legend':'', 'type':'string'})

new_fields['vulture.App'].append({'name':'enable_ssl','value': False, 'ask':False, 'legend':'', 'type':'boolean'})
new_fields['vulture.App'].append({'name':'conf_from_intf','value': False, 'ask':False, 'legend':'', 'type':'boolean'})
new_fields['vulture.App'].append({'name':'ssl_configuration','value': None, 'ask':False, 'legend':'', 'type':'key'})

new_fields['vulture.SSL'] = [{'name':'verify_depth','value':1, 'ask':False, 'legend':'', 'type':'int'}]
moved_fields['vulture.Intf'] = [{'src_field':'cert', 'dest_model':'vulture.SSL_conf', 'dest_field':'cert', 'replacement_field':'ssl_configuration'}]
moved_fields['vulture.Intf'].append({'src_field':'ca', 'dest_model':'vulture.SSL_conf', 'dest_field':'ca', 'replacement_field':'ssl_configuration'})
moved_fields['vulture.Intf'].append({'src_field':'cacert', 'dest_model':'vulture.SSL_conf', 'dest_field':'cacert', 'replacement_field':'ssl_configuration'})
moved_fields['vulture.Intf'].append({'src_field':'key', 'dest_model':'vulture.SSL_conf', 'dest_field':'key', 'replacement_field':'ssl_configuration'})
moved_fields['vulture.Intf'].append({'src_field':'ssl_engine', 'dest_model':'vulture.SSL_conf', 'dest_field':'ssl_engine', 'replacement_field':'ssl_configuration'})
removed_fields['vulture.Intf'] = [{'name':'ca'}]
removed_fields['vulture.Intf'].append({'name':'cert'})
removed_fields['vulture.Intf'].append({'name':'cacert'})
removed_fields['vulture.Intf'].append({'name':'key'})
removed_fields['vulture.Intf'].append({'name':'ssl_engine'})
#2_0_7_633_changes.py
new_fields['vulture.SQL'] = [{'name':'changepass_column','value':'', 'ask':False, 'legend':'Force user to change his password', 'type':'string'}]
#2_0_7_632_changes.py
new_fields['vulture.SSO'] = [{'name':'verify_mech_cert','value':True , 'ask':False, 'legend':'Verifying if remote servername is matching its certificate', 'type':'boolean'}]
