INSERT INTO "log" VALUES(1,'Combined','warn',' "%%a %%l %%u %%t \"%%r\" %%>s %%b \"%%{Referer}i\" \"%%{User-Agent}i\""','/var/log/','');
INSERT INTO "log" VALUES(2,'Common','warn','"%%a %%l %%u %%t \"%%r\" %%>s %%b "','/var/log/','');
INSERT INTO "log" VALUES(3,'SSLFormat','warn','"%%t %%a %%{SSL_PROTOCOL}x %%{SSL_CIPHER}x %%{SSL_CLIENT_S_DN_CN}x %%{SSL_CLIENT_I_DN_CN}x \"%%r\" %%b"','/var/log/','');
INSERT INTO "log" VALUES(4,'Debug','debug','"%%a %%l %%u %%t \"%%r\" %%>s %%b \"%%{Referer}i\" \"%%{User-Agent}i\""', '/var/log/','');
INSERT INTO "log" VALUES(5,'Logstash','warn','"{ \"@timestamp\": \"%{%Y-%m-%dT%H:%M:%S%z}t\", \"@fields\": { \"client\": \"%a\", \"duration_usec\": %D, \"status\": %s, \"request\": \"%U%q\", \"method\": \"%m\", \"referrer\": \"%{Referer}i\" } }"', '/var/log/','');
INSERT INTO "log" VALUES(6,'Logstash-ext','warn','"{ \"@timestamp\": \"%{%Y-%m-%dT%H:%M:%S%z}t\", \"@message\": \"%r\", \"@fields\": { \"user-agent\": \"%{User-agent}i\", \"client\": \"%a\", \"duration_usec\": %D, \"duration_sec\": %T, \"status\": %s, \"request_path\": \"%U\", \"request\": \"%U%q\", \"method\":\"%m\", \"referrer\": \"%{Referer}i\" } }"', '/var/log/','');


