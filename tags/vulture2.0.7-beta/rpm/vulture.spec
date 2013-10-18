Requires: sudo make gcc httpd httpd-devel krb5-devel libapreq2 perl-DBD-MySQL libidn libmcrypt libmcrypt-devel libmemcached libmemcached-devel postgresql postgresql-devel memcached memcached-devel mod_perl mod_perl-devel mod_python mod_wsgi mysql mysql-server perl-Apache-Session perl-Authen-Krb5 perl-BSD-Resource perl-Cache-Memcached perl-Class-Accessor perl-Class-Data-Inheritable perl-Convert-ASN1 perl-Crypt-Blowfish perl-Crypt-CBC perl-Crypt-OpenSSL-AES perl-Crypt-PasswdMD5 perl-Crypt-SSLeay perl-DBD-Pg perl-DBD-SQLite perl-DBI perl-Devel-Symdump perl-Digest-SHA1 perl-IO-Socket-SSL perl-IO-Tty perl-IPC-Run perl-LDAP perl-libapreq2 perl-Net-Daemon perl-Net-LibIDN perl-Net-SSLeay perl-NTLM perl-Params-Validate perl-String-CRC32 perl-Sub-Name perl-WWW-Mechanize python python-devel python-ldap python-memcached python-sqlite sqlite sqlite-devel python-imaging python-hashlib pyOpenSSL libxml2 libxml2-devel mod_security mod_ssl python-setuptools python-pip
%define serverroot /opt
Vendor: Advens
%define release 0
%define name vulture
%define version 2.0.6
AutoReqProv: no

Summary: Vulture Reverse Proxy
Name: %name
Version: %version
Release: %release
License: GPL
Group: System/Servers
URL: http://www.vultureproject.org
Buildarch: noarch
Source0: %{name}-%{version}.tar.bz2
Patch0: database_path.patch
Patch1: PreConnectionHandler.patch

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: perl
%description
Vulture Reverse Proxy

%prep
%setup -c -a 0
%patch0 -p0 -b .old
%patch1 -p0 -b .old

%build
	rm -rf $RPM_BUILD_ROOT

%install 
     cd %{name}-%{version}
     make PREFIX=$RPM_BUILD_ROOT%{serverroot} PREFIXLIB=$RPM_BUILD_ROOT%{serverroot} UID='-o apache' GID='-g apache' install
     rm -f $RPM_BUILD_ROOT%{serverroot}/%{name}/lib/x86_64-linux-thread-multi/perllocal.pod
     rm -f $RPM_BUILD_ROOT%{serverroot}/%{name}/lib/i386-linux-thread-multi/perllocal.pod
     install -d -m0700 $RPM_BUILD_ROOT/etc/init.d
     %if 0%{?suse_version}
     install -m0755 rpm/vulture.suse $RPM_BUILD_ROOT/etc/init.d/vulture
     %else
     install -m0755 rpm/vulture $RPM_BUILD_ROOT/etc/init.d/vulture
     %endif
     install -d -m0755 $RPM_BUILD_ROOT%{serverroot}/%{name}
     cp -r admin $RPM_BUILD_ROOT%{serverroot}/%{name}
     install -m0644 rpm/settings.py\
     $RPM_BUILD_ROOT%{serverroot}/%{name}/admin/settings.py
     install -d -m0755 $RPM_BUILD_ROOT%{serverroot}/%{name}/conf
     install -d -m0770 $RPM_BUILD_ROOT%{serverroot}/%{name}/conf/security-rules
     install -m0644 rpm/httpd.conf\
     $RPM_BUILD_ROOT%{serverroot}/%{name}/conf/httpd.conf
     install -m0644 rpm/vulture.wsgi\
     $RPM_BUILD_ROOT%{serverroot}/%{name}/conf/vulture.wsgi
     install -m0644 conf/openssl.cnf\
     $RPM_BUILD_ROOT%{serverroot}/%{name}/conf/openssl.cnf
     install -d -m0755 rpm $RPM_BUILD_ROOT%{serverroot}/%{name}/rpm/
     install -m0755 rpm/*.gz $RPM_BUILD_ROOT%{serverroot}/%{name}/rpm/

%clean
     rm -rf $RPM_BUILD_ROOT

%pre
    if (grep -E "^vulture-admin:" /etc/passwd > /dev/null) ; then
       	echo "L'utilisateur admin existe."
    else
       	useradd vulture-admin -G apache
    fi


%post
     chmod +x %{serverroot}/%{name}/bin/test-perl.sh
     cd %{serverroot}/%{name}/rpm
     tar zxf Django-*.tar.gz && cd Django-*/ && python setup.py install
     cd %{serverroot}/%{name}/rpm
     tar zxf Apache-SSLLookup-*.tar.gz && cd Apache-SSLLookup-*/ &&
	perl Makefile.PL CCFLAGS="-I/usr/include/apr-1" && make && make install
     cd %{serverroot}/%{name}/rpm
     tar zxf pysqlite-*.tar.gz && cd pysqlite-* && python setup.py install
     cd %{serverroot}/%{name}/rpm
     tar zxf Apache2-AuthenNTLM-*.tar.gz && cd Apache2-AuthenNTLM-*/ && 
	perl Makefile.PL && make && make install
    if [ ! -f %{serverroot}/%{name}/conf/server.crt ]; then
        PATH=$PATH:%{serverroot}/bin openssl req -x509 -newkey rsa:1024 -batch\
        	-out %{serverroot}/%{name}/conf/server.crt\
        	-keyout %{serverroot}/%{name}/conf/server.key\
        	-nodes -config %{serverroot}/%{name}/conf/openssl.cnf
    fi
    if [ ! -f %{serverroot}/%{name}/conf/server.pem ]; then
        cat %{serverroot}/%{name}/conf/server.key %{serverroot}/%{name}/conf/server.crt > %{serverroot}/%{name}/conf/server.pem
    fi
    /sbin/chkconfig --add vulture
	PYTHONPATH=$PYTHONPATH:%{serverroot}/%{name}%{python_sitearch}/:%{serverroot}/%{name}%{python_sitelib}/
	export PYTHONPATH 
    echo no | python %{serverroot}/%{name}/admin/manage.py syncdb
    /etc/init.d/vulture start
    if [ -f %{serverroot}/%{name}/admin/vulture/sql/log.sql ] ; then
        BASE_RULE=`/usr/bin/sqlite3 %{serverroot}/%{name}/admin/db "SELECT count(*) from log"`
        if [ $BASE_RULE = 0 ]; then
            /usr/bin/sqlite3 %{serverroot}/%{name}/admin/db < %{serverroot}/%{name}/admin/vulture/sql/log.sql
        fi
    fi
    chown vulture-admin:apache %{serverroot}/%{name}/admin/db
    chown vulture-admin:apache %{serverroot}/%{name}/admin
    chmod 660 %{serverroot}/%{name}/admin/db
    chmod 770 %{serverroot}/%{name}/admin/
    chmod 550  %{serverroot}/%{name}/bin/test-perl.sh
    if [ ! -f %{serverroot}/%{name}/conf/cacert.pem ]; then
        openssl req -x509 -days 3650 -newkey rsa:1024 -batch\
        	-out %{serverroot}/%{name}/conf/cacert.pem\
        	-keyout %{serverroot}/%{name}/conf/cacert.key\
        	-nodes -config %{serverroot}/%{name}/conf/openssl.cnf -extensions v3_ca
    fi
    if [ ! -f %{serverroot}/%{name}/conf/index.txt ]; then
		touch %{serverroot}/%{name}/conf/index.txt
    fi
    if [ ! -f %{serverroot}/%{name}/conf/serial ]; then
		echo 01 > %{serverroot}/%{name}/conf/serial
    fi
    if [ ! -f %{serverroot}/%{name}/conf/server.crt ]; then
        openssl req -newkey rsa:1024 -batch\
        	-out %{serverroot}/%{name}/conf/server.req\
        	-keyout %{serverroot}/%{name}/conf/server.key\
        	-nodes -config %{serverroot}/%{name}/conf/openssl.cnf
	cd  %{serverroot}/%{name}/conf &&\
	openssl ca -in %{serverroot}/%{name}/conf/server.req\
		-out %{serverroot}/%{name}/conf/server.crt\
		-config %{serverroot}/%{name}/conf/openssl.cnf\
		-keyfile %{serverroot}/%{name}/conf/cacert.key\
		-cert %{serverroot}/%{name}/conf/cacert.pem\
		-outdir %{serverroot}/%{name}/conf/ -batch
    fi
    if ! (grep "^vulture-admin.*NOPASSWD:.*/usr/sbin/httpd.*/sbin/ifconfig" /etc/sudoers > /dev/null  ) ; then 
	    echo "vulture-admin ALL=NOPASSWD: /bin/cat, /usr/sbin/httpd, /sbin/ifconfig" >> /etc/sudoers
    fi
    if ! ( grep '^Defaults:vulture-admin.*!requiretty' /etc/sudoers > /dev/null ) ; then
         echo 'Defaults:vulture-admin !requiretty' >> /etc/sudoers
    fi
    if ( uname -i | grep 'x86_64' > /dev/null ) ; then
        sed s-"/usr/lib/libxml2.so.2"-"/usr/lib64/libxml2.so.2"-g %{serverroot}/%{name}/admin/vulture_httpd.conf > /tmp/vh.conf && \
		mv /tmp/vh.conf %{serverroot}/%{name}/admin/vulture_httpd.conf;
    fi
    if ! ( python -c '
from sys import stdout as o
import base64 as B
try:
    f = open("/dev/urandom")
except:
    try:
        f = open("/dev/random")
    except:	
        exit(1)
o.write(B.b64encode(f.read(128))[:32])' > %{serverroot}/%{name}/conf/aes-encrypt-key.key ); then	
	echo "This should be changed"  > %{serverroot}/%{name}/conf/aes-encrypt-key.key
	echo "[Warning] : AES key must be configured manually in" %{serverroot}/%{name}/conf/aes-encrypt-key.key
    fi
    

%preun
    /etc/init.d/vulture stop
    /sbin/chkconfig --del vulture

%files
%defattr(-,apache,apache,-)
%config(noreplace) %{serverroot}/%{name}/sql
%{serverroot}/%{name}/static
%{serverroot}/%{name}/rpm
%defattr(-,vulture-admin,apache,-)
%config(noreplace) %{serverroot}/%{name}/conf
%defattr(-,vulture-admin,apache)
%config(noreplace) %{serverroot}/%{name}/conf/security-rules
%defattr(-,vulture-admin,vulture-admin,-)
%{serverroot}/%{name}/bin
%{serverroot}/%{name}/admin
%defattr(-,root,root)
%{serverroot}/%{name}/lib
/etc/init.d/%{name}


%changelog
* Fri Jan 18 2018 Etienne Helluy <etienne.helluy-lafont@advens.fr> 2.0.5-0
- 2.0.5 

* Wed Jul 25 2012 Etienne Helluy <etienne.helluy-lafont@advens.fr> 2.0.4-0
- 2.0.4
- add clustering support
- balancer proxifying support
- add support for ftp:// proxifying
- add support for virtual directories
- add network interfaces configuration interface
- fix vulnerability in get_translations
- fix several xss vulnerabilities
- fix file disclosure vulnerability
- fix weak ciphers allowed for ssl
- fix command execution in admin panel
- fix bugs

* Fri Oct 7 2011 Arnaud Desmons <logarno@gmail.com> 2.0.1-1
- 2.0.1

* Fri Jul 29 2011 Arnaud Desmons <logarno@gmail.com> 2.0-1
- admin Django
- perl rewrite