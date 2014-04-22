Requires: sudo gcc make httpd krb5-devel libapreq2-3 libidn libmcrypt libmcrypt-devel libmemcached libmemcached-devel postgresql postgresql-devel memcached apache2-devel apache2-mod_perl apache2-mod_perl-devel apache2-mod_python apache2-mod_wsgi perl-BSD-Resource perl-Class-Accessor perl-Class-Data-Inheritable perl-Convert-ASN1 perl-Crypt-Blowfish perl-Crypt-CBC perl-Crypt-SSLeay perl-DBD-Pg perl-DBD-SQLite perl-DBI perl-Devel-Symdump perl-Digest-SHA1 perl-IO-Socket-SSL perl-IO-Tty perl-IPC-Run perl-ldap perl-Net-Daemon perl-Net-LibIDN perl-Net-SSLeay perl-Params-Validate perl-Sub-Name perl-WWW-Mechanize python python-devel python-ldap python-sqlite python-pysqlite sqlite sqlite-devel python-imaging pyOpenSSL libxml2 apache2-mod_security2 python-memcached
%define serverroot /opt
Vendor: Advens
%define release 0
%define name vulture
%define version 2.0.5
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
Patch1: vulture-suse.patch

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: perl
%description
Vulture Reverse Proxy

%prep
%setup -c -a 0
%patch0 -p0 -b .old
%patch1 -p0 -b .old

cd ..
%build
	rm -rf $RPM_BUILD_ROOT

%install 
     cd %{name}-%{version}
     make PREFIX=$RPM_BUILD_ROOT%{serverroot} PREFIXLIB=$RPM_BUILD_ROOT%{serverroot} UID='-o wwwrun' GID='-g www' install
     rm -f $RPM_BUILD_ROOT%{serverroot}/%{name}/lib/x86_64-linux-thread-multi/perllocal.pod
     rm -f $RPM_BUILD_ROOT%{serverroot}/%{name}/lib/i386-linux-thread-multi/perllocal.pod
     install -d -m0700 $RPM_BUILD_ROOT/etc/init.d
     install -m0755 rpm/vulture.suse $RPM_BUILD_ROOT/etc/init.d/vulture
     install -d -m0755 $RPM_BUILD_ROOT%{serverroot}/%{name}
     cp -r admin $RPM_BUILD_ROOT%{serverroot}/%{name}
     install -m0644 rpm/settings.py\
     $RPM_BUILD_ROOT%{serverroot}/%{name}/admin/settings.py
     install -d -m0755 $RPM_BUILD_ROOT%{serverroot}/%{name}/conf
     install -m0644 rpm/httpd.conf\
     $RPM_BUILD_ROOT%{serverroot}/%{name}/conf/httpd.conf
     install -m0644 rpm/vulture.wsgi\
     $RPM_BUILD_ROOT%{serverroot}/%{name}/conf/vulture.wsgi
     install -m0644 conf/openssl.cnf\
     $RPM_BUILD_ROOT%{serverroot}/%{name}/conf/openssl.cnf
     install -m0644 debian/aes-encrypt-key.key\
     $RPM_BUILD_ROOT%{serverroot}/%{name}/conf/aes-encrypt-key.key
     install -d -m0755 rpm $RPM_BUILD_ROOT%{serverroot}/%{name}/rpm/
     install -m0755 rpm/*.gz $RPM_BUILD_ROOT%{serverroot}/%{name}/rpm/

%clean
     rm -rf $RPM_BUILD_ROOT


%post
     chmod +x %{serverroot}/%{name}/bin/test-perl.sh
     ln -s /usr/lib/apache2/ /etc/apache2/modules
     ln -s /usr/lib/apache2-prefork/mod_ssl.so /usr/lib/apache2/mod_ssl.so
     ln -s /usr/lib/apache2-prefork/mod_info.so /usr/lib/apache2/mod_info.so
     ln -s /usr/lib/apache2-prefork/mod_cgi.so /usr/lib/apache2/mod_cgi.so
     mkdir /var/lock/subsys/ 2>/dev/null
     cd %{serverroot}/%{name}/rpm
     tar zxf Django-*.tar.gz && cd Django-*/ && python setup.py install
     cd %{serverroot}/%{name}/rpm
     tar zxf Apache-SSLLookup-*.tar.gz && cd Apache-SSLLookup-*/ &&
	perl Makefile.PL CCFLAGS="-I/usr/include/apr-1" && make && make install
     cd %{serverroot}/%{name}/rpm
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
    /etc/init.d/vulture start
	PYTHONPATH=$PYTHONPATH:%{serverroot}/%{name}%{python_sitearch}/:%{serverroot}/%{name}%{python_sitelib}/
	export PYTHONPATH 
    echo no | python %{serverroot}/%{name}/admin/manage.py syncdb
    if [ -f %{serverroot}/%{name}/admin/vulture/sql/log.sql ] ; then
        BASE_RULE=`/usr/bin/sqlite3 %{serverroot}/%{name}/admin/db "SELECT count(*) from log"`
        if [ $BASE_RULE = 0 ]; then
            /usr/bin/sqlite3 %{serverroot}/%{name}/admin/db < %{serverroot}/%{name}/admin/vulture/sql/log.sql
        fi
    fi
    if [ -f %{serverroot}/%{name}/admin/vulture/sql/modsecurity.sql ] ; then
        BASE_RULE=`/usr/bin/sqlite3 %{serverroot}/%{name}/admin/db "SELECT count(*) from modsecurity"`
        if [ $BASE_RULE = 0 ]; then
            /usr/bin/sqlite3 %{serverroot}/%{name}/admin/db < %{serverroot}/%{name}/admin/vulture/sql/modsecurity.sql
        fi
    fi
    chown wwwrun:www %{serverroot}/%{name}/admin/db
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
    if grep "^wwwrun.*ALL=NOPASSWD:.*/usr/sbin/httpd2.*/sbin/ifconfig" /etc/sudoers > /dev/null ; then
        echo "sudo active"
    else
        echo "wwwrun ALL=NOPASSWD:/usr/sbin/httpd2, /sbin/ifconfig" >> /etc/sudoers
    fi
    if ! ( grep '^Defaults:wwwrun.*!requiretty' /etc/sudoers > /dev/null ) ; then
         echo 'Defaults:wwwrun !requiretty' >> /etc/sudoers
    fi

%preun
    /etc/init.d/vulture stop
    /sbin/chkconfig --del vulture

%files
%defattr(-,wwwrun,www,-)
%config(noreplace) %{serverroot}/%{name}/conf
%config(noreplace) %{serverroot}/%{name}/sql
%{serverroot}/%{name}/admin
%{serverroot}/%{name}/bin
%{serverroot}/%{name}/static
%{serverroot}/%{name}/rpm
%defattr(-,root,root)
%{serverroot}/%{name}/lib
/etc/init.d/%{name}


%changelog
* Fri Jan 18 2013 Etienne Helluy <etienne.helluy-lafont@advens.fr> 2.0.5-0
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
