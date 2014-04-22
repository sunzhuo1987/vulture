import sys
from memcached import *
import logging

# This is the function used by django-crontab
# Crontab configuration is in settings.py
# Start or Refresh Daemon

def cronJob():
    daemon = SynchroDaemon()
    if sys.argv[1] == "stop":
        daemon.stop()
    if not daemon.started():
        daemon.refresh()
    else:
        daemon.start()
cronJob()
