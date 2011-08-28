Summary: vulture common
Name: vulture-common
Version: 2.3
Release: 1
License: GPL
Group: System Environment/Daemons
URL: http://vulture.googlecode.com
Conflicts: INTRINsec-common

Source0: http://www.openssl.org/source/openssl-0.9.8r.tar.gz
Source1: http://apache.cict.fr/httpd/httpd-2.2.19.tar.bz2
Source2: http://www.modsecurity.org/download/modsecurity-apache_2.5.13.tar.gz
Source3: http://be2.php.net/distributions/php-5.2.17.tar.bz2
Source4: http://perl.apache.org/dist/mod_perl-2.0.4.tar.gz
Source5: http://lwp.linpro.no/lwp/libwww-perl-5.805.tar.gz
Source6: http://search.cpan.org/CPAN/authors/id/G/GB/GBARR/perl-ldap-0.33.tar.gz
Source7: http://search.cpan.org/CPAN/authors/id/T/TI/TIMB/DBI-1.607.tar.gz
Source8: http://search.cpan.org/CPAN/authors/id/M/MS/MSERGEANT/DBD-SQLite2-0.33.tar.gz
Source9: http://search.cpan.org/CPAN/authors/id/D/DB/DBDPG/DBD-Pg-1.49.tar.gz
Source10: http://search.cpan.org/CPAN/authors/id/J/JB/JBAKER/Apache-Session-1.81.tar.gz
Source11: http://search.cpan.org/CPAN/authors/id/G/GB/GBARR/Convert-ASN1-0.20.tar.gz
Source12: http://search.cpan.org/CPAN/authors/id/M/MS/MSCHWERN/ExtUtils-MakeMaker-6.42.tar.gz
Source13: http://search.cpan.org/CPAN/authors/id/L/LD/LDS/CGI.pm-3.20.tar.gz
Source14: http://search.cpan.org/CPAN/authors/id/G/GA/GAAS/URI-1.35.tar.gz
Source15: http://search.cpan.org/CPAN/authors/id/G/GE/GEOFF/Apache-SSLLookup-2.00_04.tar.gz
Source16: http://search.cpan.org/CPAN/authors/id/L/LD/LDS/Crypt-CBC-2.18.tar.gz
Source17: http://belnet.dl.sourceforge.net/sourceforge/mcrypt/libmcrypt-2.5.7.tar.gz
Source18: http://search.cpan.org/CPAN/authors/id/G/GA/GAAS/Digest-SHA1-2.11.tar.gz
Source19: php.ini
Source20: http://search.cpan.org/CPAN/authors/id/M/MA/MANOWAR/RadiusPerl-0.12.tar.gz
Source21: http://search.cpan.org/CPAN/authors/id/F/FT/FTASSIN/Data-HexDump-0.02.tar.gz
Source22: http://search.cpan.org/CPAN/authors/id/D/DP/DPARIS/Crypt-Blowfish-2.10.tar.gz
Source23: http://search.cpan.org/CPAN/authors/id/C/CH/CHAMAS/Crypt-SSLeay-0.51.tar.gz
Source24: http://search.cpan.org/CPAN/authors/id/S/SU/SULLR/IO-Socket-SSL-0.98_1.tar.gz
Source25: http://search.cpan.org/CPAN/authors/id/F/FL/FLORA/Net_SSLeay.pm-1.30.tar.gz
Source26: http://www.samse.fr/GPL/ModProxyPerlHtml/Apache2-ModProxyPerlHtml-2.6.tar.gz
Source27: mod_replace.c
Source28: mod_proxy_html.c
Source29: http://search.cpan.org/CPAN/authors/id/C/CA/CAPTTOFU/DBD-mysql-4.001.tar.gz
Source30: http://search.cpan.org/CPAN/authors/id/R/RS/RSOD/IPC-Run-0.80.tar.gz
Source31: http://search.cpan.org/CPAN/authors/id/M/MS/MSERGEANT/DBD-SQLite-1.13.tar.gz
Source32: http://switch.dl.sourceforge.net/sourceforge/mod-fcgid/mod_fcgid.2.1.tar.gz
Source33: http://www.zdziarski.com/projects/mod_evasive/mod_evasive_1.10.1.tar.gz
Source34: http://www.monkey.org/~provos/libevent-1.3e.tar.gz
Source35: http://www.danga.com/memcached/dist/memcached-1.4.5.tar.gz
Source36: http://search.cpan.org/CPAN/authors/id/B/BR/BRADFITZ/Cache-Memcached-1.24.tar.gz
Source37: http://search.cpan.org/CPAN/authors/id/E/EN/ENRYS/Apache-Session-Memcached-0.03.tar.gz
Source38: http://search.cpan.org/CPAN/authors/id/S/SO/SOENKE/String-CRC32-1.4.tar.gz
Source39: http://search.cpan.org/CPAN/authors/id/P/PH/PHRED/Apache-Reload-0.10.tar.gz
Source40: ftp://ftp.ibiblio.org/pub/Linux/ALPHA/freetds/stable/freetds-0.82.tar.gz
Source41: http://search.cpan.org/CPAN/authors/id/D/DP/DPARIS/Crypt-DES-2.05.tar.gz
Source42: http://search.cpan.org/CPAN/authors/id/M/ME/MEWP/DBD-Sybase-1.09.tar.gz
Source43: http://freefr.dl.sourceforge.net/project/mod-qos/mod_qos-9.68.tar.gz
Source44: http://search.cpan.org/CPAN/authors/id/B/BI/BINGOS/Module-Load-0.20.tar.gz
Patch0: Apache-SSLLookup-2.00_04.patch
Patch1: httpd_mod_rewrite.patch
Patch2: freetds.patch
Patch3: ModProxyPerlHtml.patch
Patch4: memcached-fix-strict-aliasing.patch
Patch5: memcached-1.4.5.patch

BuildRequires: gcc postgresql-devel libxml2-devel flex gcc-c++ libidn-devel pcre-devel make autoconf libtool tcl-devel python
%if %(test -e /etc/mandrake-release && echo 1 || echo 0)
BuildRequires: perl-devel libldap2-devel libsasl2-devel
%else
BuildRequires: perl cyrus-sasl-devel
%endif
%if %(test -e /etc/SuSE-release && echo 1 || echo 0)
%ifarch x86_64
BuildRequires: openldap2-devel-32bit libmysqlclient16-32bit
%else
BuildRequires: openldap2-devel libmysqlclient-devel
%endif
BuildRequires: libcurl-devel patch
Requires: mysql-shared
%else
BuildRequires: openldap-devel glibc-headers libtool-ltdl-devel mysql-devel curl-devel > 7.10.55
Requires: mysql
%endif
Requires: perl postgresql-libs curl libxml2 libtool perl-HTML-Parser perl-HTML-Tagset libtool-ltdl
Autoreq: 0

BuildRoot: %{_tmppath}/%{name}-root

%description
vulture common

%prep
%setup -c -a 0 -a 1 -a 2 -a 3 -a 4 -a 5 -a 6 -a 7 -a 8 -a 9 -a 10 -a 11 -a 12 -a 13 -a 14 -a 15 -a 16 -a 17 -a 18 -a 20 -a 21 -a 22 -a 23 -a 24 -a 25 -a 26 -a 29 -a 30 -a 31 -a 32 -a 33 -a 34 -a 35 -a 36 -a 37 -a 38 -a 39 -a 40 -a 41 -a 42 -a 43 -a 44
%patch0 -p0 -b .old
%patch1 -p0 -b .old
%patch2 -p0 -b .old
%patch3 -p0 -b .old
%patch4 -p0 -b .old
%patch5 -p0 -b .old

%build
	rm -rf $RPM_BUILD_ROOT
	cd freetds-0.82 &&\
	./configure --prefix=$RPM_BUILD_ROOT/opt/vulture/freetds &&\
	make CFLAGS="%{optflags}" &&\
	make install &&\
        cd ../openssl-0.9.8r &&\
        ./config --prefix=$RPM_BUILD_ROOT/opt/vulture/openssl shared &&\
        make CPPFLAGS="%{optflags} -DSSL_EXPERIMENTAL_ENGINE" &&\
        make install &&\
	make clean &&\
	export LD_LIBRARY_PATH="$RPM_BUILD_ROOT/opt/vulture/openssl/lib:$LD_LIBRARY_PATH" &&\
        cd ../httpd-2.2.19 &&\
%ifarch x86_64
	mv srclib/apr-util/configure srclib/apr-util/configure.bak &&\
	mv configure configure.bak &&\
	./buildconf &&\
%endif
	./configure --with-mpm=prefork --prefix=$RPM_BUILD_ROOT/opt/vulture/httpd \
%ifarch x86_64
		--enable-lib64 \
%endif
		--enable-ssl --enable-proxy --mandir=$RPM_BUILD_ROOT/opt/vulture/man \
		--with-ssl=$RPM_BUILD_ROOT/opt/vulture/openssl --disable-authn-file \
		--disable-authn-default --disable-authz-groupfile --enable-rewrite \
		--disable-authz-user  --disable-authz-default --disable-auth-basic \
		--disable-userdir --enable-headers --enable-dav \
		--enable-dav-fs --enable-dav-lock --enable-unique-id \
		--enable-cache --enable-disk-cache --enable-mem-cache --enable-deflate \
		--enable-mods-shared="deflate dav dav-fs dav-lock cache disk-cache mem-cache expires" &&\
	make CPPFLAGS="%{optflags} -I/usr/kerberos/include -DSSL_EXPERIMENTAL_ENGINE" &&\
	make install &&\
	make clean &&\
	cd .. &&\
	$RPM_BUILD_ROOT/opt/vulture/httpd/bin/apxs -I./httpd-2.2.4/srclib/pcre/ -cia %{SOURCE27} &&\
	$RPM_BUILD_ROOT/opt/vulture/httpd/bin/apxs -I/usr/include/libxml2/ -cia %{SOURCE28} &&\
	cd mod_fcgid.2.1 &&\
	$RPM_BUILD_ROOT/opt/vulture/httpd/bin/apxs -c -o mod_fcgid.so -Iarch/unix -I. fcgid_bridge.c \
		fcgid_conf.c fcgid_pm_main.c fcgid_protocol.c fcgid_spawn_ctl.c mod_fcgid.c \
		arch/unix/fcgid_proctbl_unix.c arch/unix/fcgid_pm_unix.c \
		arch/unix/fcgid_proc_unix.c fcgid_bucket.c fcgid_filter.c &&\
	install -m 644 .libs/mod_fcgid.so $RPM_BUILD_ROOT/opt/vulture/httpd/modules/mod_fcgid.so &&\
	cd ../libmcrypt-2.5.7 &&\
	./configure --prefix=$RPM_BUILD_ROOT/opt/vulture --disable-posix-threads &&\
	make &&\
	make install &&\
	make clean &&\
        cd ../mod_evasive &&\
        $RPM_BUILD_ROOT/opt/vulture/httpd/bin/apxs -cia mod_evasive20.c &&\
        cd ../mod_qos-9.68 &&\
        $RPM_BUILD_ROOT/opt/vulture/httpd/bin/apxs -cia apache2/mod_qos.c &&\
	cd ../php-5.2.17 &&\
%ifarch x86_64
	export LDFLAGS="-L/usr/lib64 -L$RPM_BUILD_ROOT/opt/vulture/freetds/lib" &&\
%endif
	./configure --prefix=/opt/vulture/php --with-pic \
%ifarch x86_64
		--libdir=/usr/lib64 --with-libdir=lib64 \
		--with-openssl \
		--with-mcrypt \
%else
		--with-openssl=$RPM_BUILD_ROOT/opt/vulture/openssl \
		--with-mcrypt=$RPM_BUILD_ROOT/opt/vulture \
%endif
		--disable-cli --enable-cgi --with-config-file-path=/opt/vulture/etc \
		--with-apxs2=$RPM_BUILD_ROOT/opt/vulture/httpd/bin/apxs \
		--mandir=/opt/vulture/man \
		--with-sqlite --with-pgsql --with-mysql --with-zlib-dir=/usr \
		--with-ldap --enable-fastcgi \
		--with-curl \
		--disable-dom --disable-simplexml \
		--disable-tokenizer --disable-spl \
		--with-sybase=$RPM_BUILD_ROOT/opt/vulture/freetds \
		--disable-xmlreader --disable-xmlwriter &&\
	make DESTDIR=$RPM_BUILD_ROOT CFLAGS="%{optflags}" &&\
	make install &&\
	make clean &&\
	install -m 755 -d $RPM_BUILD_ROOT/opt/vulture/etc/ &&\
	install -m 644 %{SOURCE19} $RPM_BUILD_ROOT/opt/vulture/etc/php.ini &&\
	cd ../modsecurity-apache_2.5.13/apache2 &&\
	./configure --with-apxs=$RPM_BUILD_ROOT/opt/vulture/httpd/bin/apxs \
	    --with-httpd-src=../../httpd-2.2.19 --with-apr=$RPM_BUILD_ROOT/opt/vulture/httpd \
	    --with-apu=$RPM_BUILD_ROOT/opt/vulture/httpd &&\
	make CFLAGS="%{optflags}" &&\
	make install &&\
	make clean &&\
	cd ../../mod_perl-2.0.4 &&\
	CFLAGS="$RPM_OPT_FLAGS -fpic" perl -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL \
		LIB=$RPM_BUILD_ROOT/opt/vulture/lib \
		PERLPREFIX=$RPM_BUILD_ROOT/opt/vulture \
		SITEPREFIX=$RPM_BUILD_ROOT/opt/vulture \
		VENDORPREFIX=$RPM_BUILD_ROOT/opt/vulture \
		INSTALLBIN=$RPM_BUILD_ROOT/opt/vulture/usr/bin \
		INSTALLMAN1DIR=$RPM_BUILD_ROOT/opt/vulture/man/man1 \
		INSTALLMAN3DIR=$RPM_BUILD_ROOT/opt/vulture/man/man3 \
		MP_APXS=$RPM_BUILD_ROOT/opt/vulture/httpd/bin/apxs &&\
	make -C src/modules/perl %{?_smp_mflags} OPTIMIZE="$RPM_OPT_FLAGS -fpic" &&\
	LIBRARY_PATH="$RPM_BUILD_ROOT/opt/vulture/httpd/lib/" make CFLAGS="%{optflags}" &&\
	make install &&\
	make clean &&\
	cd ../Apache2-ModProxyPerlHtml-2.6 &&\
	perl -I $RPM_BUILD_ROOT/opt/vulture/lib/x86_64-linux-thread-multi\
	     -I $RPM_BUILD_ROOT/opt/vulture/lib/i386-linux-thread-multi\
	     -I $RPM_BUILD_ROOT/opt/vulture/lib\
	     -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL\
	     LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../URI-1.35 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../Crypt-SSLeay-0.51 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib\
	     -I $RPM_BUILD_ROOT/opt/vulture/lib Makefile.PL /usr LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../libwww-perl-5.805 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib\
	     -I $RPM_BUILD_ROOT/opt/vulture/lib Makefile.PL LIB=/lib -n &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../Convert-ASN1-0.20 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL LIB=/lib -n &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../perl-ldap-0.33 &&\
	perl -I $RPM_BUILD_ROOT/opt/vulture/lib -I ../ExtUtils-MakeMaker-6.42/lib \
		Makefile.PL LIB=/lib < /dev/null &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../DBI-1.607 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../DBD-Sybase-1.09 &&\
	echo Y | SYBASE=$RPM_BUILD_ROOT/opt/vulture/freetds perl \
	     -I $RPM_BUILD_ROOT/opt/vulture/lib/x86_64-linux-thread-multi\
	     -I $RPM_BUILD_ROOT/opt/vulture/lib/i386-linux-thread-multi\
	     -I $RPM_BUILD_ROOT/opt/vulture/lib\
	     -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL\
	     LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../DBD-SQLite2-0.33 &&\
	perl -I $RPM_BUILD_ROOT/opt/vulture/lib/x86_64-linux-thread-multi\
	     -I $RPM_BUILD_ROOT/opt/vulture/lib/i386-linux-thread-multi\
	     -I $RPM_BUILD_ROOT/opt/vulture/lib\
	     -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL\
	     LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../DBD-SQLite-1.13 &&\
	perl -I $RPM_BUILD_ROOT/opt/vulture/lib/x86_64-linux-thread-multi\
	     -I $RPM_BUILD_ROOT/opt/vulture/lib/i386-linux-thread-multi\
	     -I $RPM_BUILD_ROOT/opt/vulture/lib\
	     -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL\
	     LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../DBD-Pg-1.49 &&\
	perl -I $RPM_BUILD_ROOT/opt/vulture/lib/x86_64-linux-thread-multi\
	     -I $RPM_BUILD_ROOT/opt/vulture/lib/i386-linux-thread-multi\
	     -I $RPM_BUILD_ROOT/opt/vulture/lib\
	     -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL\
	     LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../DBD-mysql-4.001 &&\
	perl -I $RPM_BUILD_ROOT/opt/vulture/lib/x86_64-linux-thread-multi\
	     -I $RPM_BUILD_ROOT/opt/vulture/lib/i386-linux-thread-multi\
	     -I $RPM_BUILD_ROOT/opt/vulture/lib\
	     -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL\
	     LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../CGI.pm-3.20 &&\
	perl -I $RPM_BUILD_ROOT/opt/vulture/lib -I ../ExtUtils-MakeMaker-6.42/lib \
		Makefile.PL LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../Apache-Session-1.81 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../libevent-1.3e &&\
	./configure --prefix=$RPM_BUILD_ROOT/opt/vulture &&\
	make &&\
	make install &&\
	cd ../memcached-1.4.5 &&\
	./configure LDFLAGS=-L$RPM_BUILD_ROOT/opt/vulture/lib --prefix=$RPM_BUILD_ROOT/opt/vulture &&\
	make &&\
	make install &&\
	cd ../Cache-Memcached-1.24 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib -I $RPM_BUILD_ROOT/opt/vulture/lib Makefile.PL INSTALLDIRS=site \
		INSTALLSITELIB=$RPM_BUILD_ROOT/opt/vulture/lib INSTALLSITEARCH=$RPM_BUILD_ROOT/opt/vulture/lib \
		PREFIX=$RPM_BUILD_ROOT/opt/vulture LIB=$RPM_BUILD_ROOT/opt/vulture/lib &&\
	make &&\
	make install &&\
	cd ../String-CRC32-1.4 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib -I $RPM_BUILD_ROOT/opt/vulture/lib Makefile.PL INSTALLDIRS=site \
		INSTALLSITELIB=$RPM_BUILD_ROOT/opt/vulture/lib INSTALLSITEARCH=$RPM_BUILD_ROOT/opt/vulture/lib \
		PREFIX=$RPM_BUILD_ROOT/opt/vulture LIB=$RPM_BUILD_ROOT/opt/vulture/lib &&\
	make &&\
	make install &&\
	cd ../Apache-Session-Memcached-0.03 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib -I $RPM_BUILD_ROOT/opt/vulture/lib Makefile.PL INSTALLDIRS=site \
		INSTALLSITELIB=$RPM_BUILD_ROOT/opt/vulture/lib INSTALLSITEARCH=$RPM_BUILD_ROOT/opt/vulture/lib \
		PREFIX=$RPM_BUILD_ROOT/opt/vulture LIB=$RPM_BUILD_ROOT/opt/vulture/lib &&\
	make &&\
	make install &&\
	cd ../Apache-SSLLookup-2.00_04 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib \
	     -I $RPM_BUILD_ROOT/opt/vulture/lib/x86_64-linux-thread-multi \
	     -I $RPM_BUILD_ROOT/opt/vulture/lib/i586-linux-thread-multi \
	     -I $RPM_BUILD_ROOT/opt/vulture/lib/i386-linux-thread-multi \
	     Makefile.PL LIB=/lib &&\
	make CCFLAGS="-I$RPM_BUILD_ROOT/opt/vulture/httpd/include" &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	cd ../Crypt-DES-2.05 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	cd ../Crypt-CBC-2.18 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	cd ../Crypt-Blowfish-2.10 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	cd ../Digest-SHA1-2.11 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../Data-HexDump-0.02 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../Authen-Radius-0.12 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib -I $RPM_BUILD_ROOT/opt/vulture/lib \
		Makefile.PL LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	cd ../Net_SSLeay.pm-1.30 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib -I $RPM_BUILD_ROOT/opt/vulture/lib \
		Makefile.PL /usr LIB=/lib &&\
	make CCFLAGS="-I$RPM_BUILD_ROOT/opt/vulture/openssl/include" &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	cd ../IPC-Run-0.80 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib Makefile.PL LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean &&\
	cd ../IO-Socket-SSL-0.98 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib -I $RPM_BUILD_ROOT/opt/vulture/lib \
		Makefile.PL LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean  &&\
	cd ../Module-Load-0.20 &&\
	perl -I ../ExtUtils-MakeMaker-6.42/lib -I $RPM_BUILD_ROOT/opt/vulture/lib \
		Makefile.PL LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	make clean  &&\
	cd ../Apache-Reload-0.10 &&\
        perl -I ../ExtUtils-MakeMaker-6.42/lib\
             -I $RPM_BUILD_ROOT/opt/vulture/lib/x86_64-linux-thread-multi\
             -I $RPM_BUILD_ROOT/opt/vulture/lib/i386-linux-thread-multi\
             -I $RPM_BUILD_ROOT/opt/vulture/lib Makefile.PL LIB=/lib &&\
	make &&\
	make DESTDIR=$RPM_BUILD_ROOT/opt/vulture SITEPREFIX= PERLPREFIX= install &&\
	echo "SAFE SKIP make clean for Apache-Reload" || exit -1

%post
	useradd -M apache 2> /dev/null || :
	echo "/opt/vulture/lib" > /etc/ld.so.conf.d/vulture.conf
	echo "/opt/vulture/httpd/lib" >> /etc/ld.so.conf.d/vulture.conf
	echo "/opt/vulture/openssl/lib" >> /etc/ld.so.conf.d/vulture.conf
	echo "/opt/vulture/freetds/lib" >> /etc/ld.so.conf.d/vulture.conf
	ldconfig

%files
%defattr(-,root, root)
/opt/vulture

%changelog
* Sun Aug 28 2011 Arnaud Desmons <arnaud.desmons@advens.fr> - 2.3-1
- mod_qos
- Module::Load
- Authen::Simple::Kerberos
- Authen::Smb

* Sun Jul 24 2011 Arnaud Desmons <arnaud.desmons@advens.fr> - 2.2-1
- httpd 2.2.19
- for CentOS 5.6 : --with-mysql-dir=/usr --with-zlib-dir=/usr

* Sat Mar 26 2011 Arnaud Desmons <arnaud.desmons@advens.fr> - 2.1-1
- Added Conflicts
- Modified paths
- modsecurity 2.5.13

* Mon Feb 14 2011 Arnaud Desmons <arnaud.desmons@advens.fr> - 2.0
- initial release 2
- mod_expires
