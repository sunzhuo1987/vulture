INSERT INTO "log" VALUES(1,'Combined','warn',' "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""','/var/log/');
INSERT INTO "log" VALUES(2,'Common','warn','"%h %l %u %t \"%r\" %>s %b "','/var/log/');
INSERT INTO "log" VALUES(3,'SSLFormat','warn','"%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x %{SSL_CLIENT_S_DN_CN}x %{SSL_CLIENT_I_DN_CN}x \"%r\" %b"','/var/log/');
INSERT INTO "log" VALUES(4,'Debug','debug','"%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\""', '/var/log/');

