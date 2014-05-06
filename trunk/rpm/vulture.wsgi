import os, sys
sys.path.append('/opt/vulture')
sys.path.append('/opt/vulture/admin')
sys.path.append("/opt/vulture/lib/Python/modules/django_crontab-0.5.1-py2.6.egg")
os.environ['DJANGO_SETTINGS_MODULE'] = 'admin.settings'

import django.core.handlers.wsgi

application = django.core.handlers.wsgi.WSGIHandler()
