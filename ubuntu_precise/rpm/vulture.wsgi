import os, sys
sys.path.append('/opt/vulture')
sys.path.append('/opt/vulture/admin')
os.environ['DJANGO_SETTINGS_MODULE'] = 'admin.settings'

import django.core.handlers.wsgi

application = django.core.handlers.wsgi.WSGIHandler()
