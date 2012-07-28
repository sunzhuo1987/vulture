import sys,os
sys.path.append("/var/www/vulture")
sys.path.append("/var/www/vulture/admin")
os.environ["DJANGO_SETTINGS_MODULE"] = "admin.settings"
from vulture.models import VINTF
if len(sys.argv)==2:
	vintfs = VINTF.objects.all()
	if sys.argv[1] == "up":
		for v in vintfs:
			v.reload()
	else:
		for v in vintfs:
			v.stop()
