import os, sys
sys.path.append('/var/www/vulture')
sys.path.append('/var/www/vulture/admin')
os.environ['DJANGO_SETTINGS_MODULE'] = 'admin.settings'

import django.core.handlers.wsgi

application = django.core.handlers.wsgi.WSGIHandler()