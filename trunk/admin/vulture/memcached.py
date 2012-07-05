#!/usr/bin/env python
try:
	import sqlite3
except:
	from pysqlite2 import dbapi2 as sqlite3
import socket as S
from django.utils import simplejson
#import json
import re
import time
import signal
from django.conf import settings
import sys,os
try:
	sys.path.append("/opt/vulture")
	sys.path.append("/opt/vulture/admin")
	os.environ["DJANGO_SETTINGS_MODULE"] = "admin.settings"
	from vulture.models import Intf, App, Conf
except:
	sys.path.append("/var/www/vulture")
	sys.path.append("/var/www/vulture/admin")
	os.environ["DJANGO_SETTINGS_MODULE"] = "admin.settings"
	from vulture.models import Intf, App, Conf

class MC:
	lockname = "vulture_lock"
	lockfile = settings.CONF_PATH+"vulture-daemon.lock"
	versionkey = "vulture_version"
	keystore = "vulture_inst"
	tmpfile = "vulture_tmp"
	regex = re.compile("VALUE ([^\s]+) \d+ (\d+)\r\n(.*)",re.MULTILINE|re.DOTALL)
	itv = 30
	con = []
	for mcc in [x.strip() for x in Conf.objects.get(var="memcached").value.split(",")]:
		c = S.socket(S.AF_INET,S.SOCK_STREAM)
		(ip,port) = mcc.split(":")
		try:
			c.connect((ip,int(port)))
			con += [c]
		except:
			pass
	db = sqlite3.connect(settings.DATABASES['default']['NAME'])
	db.row_factory=sqlite3.Row

	@staticmethod
	def start():
		useIt = False
		try:
			useMe = Conf.objects.get(var="use_cluster")
			if useMe and useMe.value == "1" :
				useIt = True
		except:
			pass	
		if not useIt:
			print "[-] Cluster not in use"
			sys.exit(0)
		if os.path.exists(MC.lockfile):
			print "[-] Already started"
			sys.exit(1)
		f = open(MC.lockfile,"w")
		f.write(str(os.getpid()))
		f.close()
		signal.signal(signal.SIGINT, MC.stop2)
		while True:
			if not os.path.exists(MC.lockfile):
				print "[-] Unexcepted stop, missing lockfile"
				MC.stop()
			MC.refresh()
			time.sleep(MC.itv)

	@staticmethod
	def stop():
		MC.stop2(0,0)

	@staticmethod
	def stop2(sig, a):
		MC.lock()
		name = MC.getConf("name")
		MC.delete(name+":version")
		old = MC.get(MC.keystore)
		if old:
			MC.set(MC.keystore,"|".join([f for f in old.split("|") if f != name]))
		try:
			os.remove(MC.lockfile)
		except:
			pass
		MC.unlock()
		sys.exit(0)
	
	@staticmethod
	def status():
		if os.path.exists(MC.lockfile):
			print "[*] Running"
			sys.exit(0)
		else:	
			print "[*] Stopped"
			sys.exit(1)
			
	@staticmethod
	def refresh():
		MC.lock()
		list = MC.get(MC.keystore)
		name = MC.getConf("name")
		if not list:
			MC.set(MC.keystore,name)
		elif not name in list:
			MC.append(MC.keystore, "|"+name)
		MC.check_config()
		MC.unlock()
	
	@staticmethod
	def check_config():
		myversion = int(MC.getConf("version_conf"))
		mcversion = int(MC.get(MC.versionkey) or '-1')
		print "[*] Refreshing conf, current: %s , last: %s"%(myversion,mcversion)
		if myversion == mcversion:
		# nothing to do
			print "[*] Already to last version"
			pass
		elif myversion > mcversion:
		# push my conf in memcache 
			print "[+] Pushing my conf into memcache..."
			MC.fill_memcache()
			print "[+] Done"
		else:
		#new config available
			print "[+] Updating conf..."
			MC.update_database_from_memcache()
			myversion = str(mcversion)
			Conf.objects.filter(var="version_conf").update(value=myversion)
			if MC.is_auto_restart():
				MC.reload_intfs()
			print "[+] Done"
		MC.set(MC.getConf("name")+":version",str(myversion))
		print "set "+MC.getConf("name")+":version to "+str(myversion)
	
	@staticmethod
	def all_elements():
		all = MC.get(MC.keystore)
		if not all:
			return []
		ret = []
		for x in all.split("|"):
			ret += [ {
					"name":x ,	
					"version": MC.get(x+":version") 
				}]
		return ret
		
	@staticmethod
	def reload_intfs():
		intfs= Intf.objects.all()
		k_output = ""
		for intf in intfs :
			if intf.need_restart:
				fail = intf.maybeWrite()
			if fail:
				k_output += intf.name+":"+fail
			else:
				k_output += intf.name+":"
				outp = intf.k('graceful')
				if outp:
					k_output += outp
				else: 
					k_output += "everything ok"
				k_output += "\n"
				apps = App.objects.filter(intf=intf).all()
				for app in apps:
					MC.delete(app.name + ':app')
		print k_output

	@staticmethod
	def getConf(key):	
		return Conf.objects.get(var=key).value

	@staticmethod
	def memcached_cmd(cmd,key,value):
		for c in MC.con:
			try:
				c.send(cmd+" "+key+" 0 0 "+str(len(value))+"\r\n"+value+"\r\n")
			except:
				pass
		
	@staticmethod
	def set(key,value):
		MC.memcached_cmd("set",key,value)
		res = False
		for c in MC.con:
			try:
				if c.recv(8) == 'STORED\r\n':
					res = True
			except:
				pass
		return res
			
	@staticmethod
	def add(key,value):
		MC.memcached_cmd("add",key,value)
		res = False
		for c in MC.con:
			try:
				if c.recv(8) == 'STORED\r\n':
					res = True
			except:
				pass
		return res

	@staticmethod
	def append(key,value):
		MC.memcached_cmd("append",key,value)
		res = False
		for c in MC.con:
			try:
				if c.recv(8) == 'STORED\r\n':
					res = True
			except:
				pass
		return res

	@staticmethod
	def prepend(key,value):
		MC.memcached_cmd("prepend",key,value)
		res = False
		for c in MC.con:
			try:
				if c.recv(8) == 'STORED\r\n':
					res = True
			except:
				pass
		return res

	@staticmethod
	def delete(key):
		for c in MC.con:
			try:
				c.send("delete "+key+" 0\r\n")
			except:
				pass
		res = False
		for c in MC.con:
			try:
				if c.recv(9) != "DELETED\r\n":
					res = True
			except:	
				pass
		return res
	
	@staticmethod
	def lock():
		while not MC.add(MC.lockname,"1"):
			pass

	@staticmethod
	def unlock():
		MC.delete(MC.lockname)

	@staticmethod
	def get(key):
		for c in MC.con:
			try:
				c.send("get "+key+"\r\n")
				res=""
				while "END\r\n" not in res:
					ret = c.recv(4096)
					res += ret
				result = MC.regex.match(res)
				if result:
					return result.group(3)[:int(result.group(2))]
			except:
				pass
			
	@staticmethod	
	def is_auto_restart():
#		if '1' == MC.db.execute("SELECT value FROM conf WHERE var='auto_restart';").fetchone()[0]:
		if '1' == Conf.objects.get(var="auto_restart").value :
			return True

	@staticmethod
	def get_all_tables_name():
		#Here we get all config tables name except django specific tables
		sth = MC.db.execute("SELECT name FROM (SELECT * FROM sqlite_master UNION ALL SELECT * FROM sqlite_temp_master) WHERE type='table' AND name not like 'django%' and name NOT IN ('conf','vintf','event_logger') ORDER BY name;")
		tables = sth.fetchall()
		return [t[0] for t in tables]

	@staticmethod
	def reset():
		tables = MC.get_all_tables_name()
		for t in tables:
			MC.delete("conf:"+t)
		MC.delete(MC.keystore)
		MC.delete(MC.versionkey)
		MC.unlock()
	# When memcache is empty we have to fill it with data from database
	@staticmethod
	def fill_memcache():
		tables = MC.get_all_tables_name()
		#For all tables, we get their content and load it into memcache
		for table in tables:
			val = MC.serialize(MC.get_SQL_table(table))
			MC.set("conf:"+table,val)
#			print "saved "+val+" in conf:"+table
		MC.set(MC.versionkey, MC.getConf("version_conf"))
		os.popen("tar hczf "+MC.tmpfile+" "+settings.CONF_PATH+"security-rules")
		MC.set("conf:mod_secu",open(MC.tmpfile).read())
		os.remove(MC.tmpfile)

	@staticmethod
	def convert_sqliteRow_to_dict(Rows):
		#for easy work, we convert sqliteRow object (return by the query) to table of dictionnary
		tab=[]
		for row in Rows:
			values={}
			for key in row.keys():
				values[key]=row[key]
			tab.append(values)
		return tab

	# because we send the data to memcache, we have to serialize the data
	@staticmethod
	def serialize(values):
		ret = simplejson.dumps(values)
#		print "serialized :\n"+ret
		return ret

	@staticmethod
	def deserialize(value):
#		print "will deserialize :\n"+str(value)
		return simplejson.loads(value)
		
	# get data from memcache and deserialize it to return a table of dictionnary		
	@staticmethod
	def get_memcache_table(table):
		val = MC.get("conf:"+table)
		return MC.deserialize(val)

	#get data from database
	@staticmethod
	def get_SQL_table(table):
		sth = MC.db.execute("SELECT * from "+table+";")
		SRows = sth.fetchall();
		di = MC.convert_sqliteRow_to_dict(SRows)
		return di
	
	@staticmethod
	def update_database_from_memcache():
		tables = MC.get_all_tables_name()
		for table in tables:
			SQL = MC.get_SQL_table(table)
			MEM = MC.get_memcache_table(table)
			Mid = []
			Sid = []
			for Srow in SQL:
				Sid.append(Srow['id'])
			for Mrow in MEM:
				Mid.append(Mrow['id'])
				row = {}
				for v in SQL:
					if v["id"] == Mrow["id"]:
						row = v
						break
				if row.has_key("id"):
					for key,value in Mrow.iteritems():
						if not value == row[key]:
							print "Something has changed"
							MC.db.execute("UPDATE "+table+" set "+str(key)+"=? where id= ?", (value, row["id"]))
				else : 
					print "this row doesn't exist in database : "+str(row)
					vals = ()
					keys ="("
					args ="("
					i=0
					for key,value in Mrow.iteritems():
						if i != 0:
							args+=","
							keys+=","
						i+=1
						vals+=(value,)
						keys+=str(key)
						args+="?"
					args+=")"
					keys+=")"
					MC.db.execute("INSERT INTO "+table+" "+keys+" VALUES "+args+";",vals)
			dels=",".join([str(f) for f in Sid if not f in Mid])
			if dels:
				print "deleting "+dels+" in "+table
				MC.db.execute("DELETE FROM "+table+" where id in (%s);"%(dels))
		MC.db.commit()	
		open(MC.tmpfile,"w").write( MC.get("conf:mod_secu"))
		os.popen("ls -l "+MC.tmpfile)
		os.popen("rm -rf "+settings.CONF_PATH+"security-rules ; tar -zxf "+MC.tmpfile+"; echo mod_secu loaded")
	
	@staticmethod
	def usage():
		sys.stderr.write("usage : vulture-daemon.py {start/stop/status}\n")

if __name__ == '__main__':
	func = {
			'start':MC.start,
			'stop':MC.stop,
			'status':MC.status,
		}
	try:
		f = func[sys.argv[1]]
	except:
		MC.usage()
		sys.exit(1)
	f()
