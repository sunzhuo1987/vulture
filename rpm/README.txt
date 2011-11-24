After install is complete, please add following lines to /etc/sudoers (you can use visudo to do that) :

apache ALL=NOPASSWD:/opt/vulture/httpd/bin/httpd, /bin/cp, /usr/bin/tail
Defaults:apache !requiretty