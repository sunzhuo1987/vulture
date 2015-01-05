#!/usr/bin/env python

import re
import subprocess

ifpath = "/sbin/ifconfig"
ippath = "/sbin/ip"

#get infos about running interfaces
def getIntfs():
    #ifconfig part
    regex_ifcfg = re.compile(
                  "^([\w\d:]+)\s.*\n\s*inet\s+[a-z]+:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                  re.MULTILINE|re.IGNORECASE
                  )
    intf={}
    for k,v in [x.groups() for x in regex_ifcfg.finditer(callIfconfig())]:
        intf[k]=v

    #ip addr part
    regex_ipaddr = re.compile(
              "^\s+inet ([0-9.]+).* ([\w+:]+)$",
                   re.MULTILINE|re.IGNORECASE
                   )
    tmp_intfs = dict()
    for k,v in [x.groups() for x in regex_ipaddr.finditer(callIpaddr())]:
        try:
            tmp_intfs[v].append(k)
        except:
            tmp_intfs[v] = list()
            tmp_intfs[v].append(k)

    for tmp_intf, ips in tmp_intfs.items():
        for ip in ips:
            if ips.index(ip) != 0:
                tmp_intf = tmp_intf + ':' +  str(ips.index(ip)-1)#Creating interface alias name (ex: eth0:0)
            #We add interface which ifconfig doesn't saw
            if intf.get(tmp_intf) is None:
                intf[tmp_intf] = ip

    return intf

# add a virtual interface to existing interface
def addIntf(intf,ip,netmask=None,broadcast=None):
    if ":" not in intf or intf in getIntfs():
        return False
    return startIntf(intf,ip,netmask,broadcast)

# stop the given virtual interface
def stopIntf(intf):
    # interface doesnt exist or is not virtual
    if ":" not in intf or intf not in getIntfs():
        return False
    return callIfconfig([intf,"down"]) and True or False

# configure the given virtual interface
def startIntf(intf, ip, netmask=None, broadcast=None):
    if not ":" in intf:
        return None
    args = [intf, ip]
    if netmask:
        args += ["netmask",netmask]
    if broadcast:
        args += ["broadcast",broadcast]
    return callIfconfig(args) and True or False

#call ifconfig
def callIfconfig(args=[]):
    proc = subprocess.Popen(["/usr/bin/sudo",ifpath] + args ,0 , "/usr/bin/sudo" , None , subprocess.PIPE)
    if proc.wait():
        raise Exception("failed to call ifconfig")
    return proc.stdout.read()

#call ip addr
def callIpaddr():
    proc = subprocess.Popen([ippath] + ["addr"] ,0 , None, None , subprocess.PIPE)
    if proc.wait():
        raise Exception("failed to call ip addr")
    return proc.stdout.read()

