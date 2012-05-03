#!/usr/bin/env python

import re
import subprocess

ifpath = "/sbin/ifconfig"

#get infos about running interfaces
def getIntfs():
	regex = re.compile("^([\w\d:]+)\s.*\n\s*inet\s+ad+r:(\d+\.\d+\.\d+\.\d+)",re.MULTILINE)
	intf={}
	for k,v in [x.groups() for x in regex.finditer(callIfconfig())]:
		intf[k]=v
	return intf

	# add a virtual interface to existing interface, and return the name of new interface
	# ie.    addIntf("eth0",...) -> "eth0:1"
def addIntf(intf,ip,netmask=None,broadcast=None):
	if ":" not in intf or intf in getIntfs():
		return None
	if startIntf(intf,ip,netmask,broadcast):
		return True 

# stop the given virtual interface
def stopIntf(intf):
	# interface doesnt exist or is not virtual
	if intf not in getIntfs() or ":" not in intf:
		return None
	if callIfconfig([intf,"down"]):
		return True

# configure the given virtual interface
def startIntf(intf, ip, netmask=None, broadcast=None):
	if not ":" in intf:
		return None
	args = [intf, ip]
	if netmask:
		args += ["netmask",netmask]
	if broadcast:
		args += ["broadcast",broadcast]
	if callIfconfig(args):
		return True

#call ifconfig 
def callIfconfig(args=[]):
	proc = subprocess.Popen(["/usr/bin/sudo",ifpath] + args ,0 , "/usr/bin/sudo" , None , subprocess.PIPE)
	if proc.wait():
		raise Exception("failed to call ifconfig")
	return proc.stdout.read()

