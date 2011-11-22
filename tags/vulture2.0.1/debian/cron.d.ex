#
# Regular cron jobs for the vulture package
#
0 4	* * *	root	[ -x /usr/bin/vulture_maintenance ] && /usr/bin/vulture_maintenance
