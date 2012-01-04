NAME		= vulture
VERSION		= 2.0.1
PREFIX		= /var/www
PREFIXLIB	= /opt
UID		= -o www-data
GID		= -g www-data
DIRS		= admin conf bin static
DIRSLIB		= ACL Auth Core Plugin SSO
INSTALL		= /usr/bin/install -c -D -m0644
TAR    		= $(NAME)-$(VERSION).tar
GZ     		= $(TAR).gz
BZ2    		= $(TAR).bz2

all:
	if [ -e /etc/debian_version ]; then \
		if [ ! -f lib/SSLLookup/Makefile ]; then \
			cd lib/SSLLookup && perl -I $(PREFIXLIB)/$(NAME)/lib \
				Makefile.PL INSTALLDIRS=site INSTALLSITELIB=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
				INSTALLSITEARCH=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi PREFIX=$(PREFIXLIB)/$(NAME) \
				LIB=$(PREFIXLIB)/$(NAME)/lib CCFLAGS="-I/usr/include/apr-1.0" && cd ../../; \
		fi; \
		make -C lib/SSLLookup/; \
		#if [ ! -f lib/Apache2/Makefile ]; then \
		#	cd lib/Apache2 && perl -I $(PREFIXLIB)/$(NAME)/lib \
		#		-I $(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi Makefile.PL LIB=$(PREFIXLIB)/$(NAME)/lib \
		#		INSTALLSITELIB=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
		#		INSTALLSITEARCH=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
		#		PREFIX=$(PREFIXLIB)/$(NAME) SITEPREFIX=$(PREFIXLIB)/$(NAME) && cd ../../; \
		#fi; \
		#make -C lib/Apache2/; \
		if [ ! -f lib/Apache2-ModProxyPerlHtml-3.0/Makefile ]; then \
			cd lib/Apache2-ModProxyPerlHtml-3.0 && perl -I $(PREFIXLIB)/$(NAME)/lib \
				-I $(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi Makefile.PL LIB=$(PREFIXLIB)/$(NAME)/lib \
				INSTALLSITELIB=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
				INSTALLSITEARCH=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
				PREFIX=$(PREFIXLIB)/$(NAME) SITEPREFIX=$(PREFIXLIB)/$(NAME) && cd ../../; \
		fi; \
		make -C lib/Apache2-ModProxyPerlHtml-3.0/; \
		if [ ! -f lib/Vulture/Makefile ]; then \
			cd lib/Vulture && perl -I $(PREFIXLIB)/$(NAME)/lib Makefile.PL INSTALLDIRS=site \
				INSTALLSITELIB=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
				INSTALLSITEARCH=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi PREFIX=$(PREFIXLIB)/$(NAME) \
				LIB=$(PREFIXLIB)/$(NAME)/lib && cd ../../;\
		fi; \
		make -C lib/Vulture/; \
		if [ ! -f lib/Crypt-CBC-2.30/Makefile ]; then \
			cd lib/Crypt-CBC-2.30 && perl -I ../lib/mod_perl/lib -I $(PREFIXLIB)/$(NAME)/lib Makefile.PL INSTALLDIRS=site \
				INSTALLSITELIB=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
				INSTALLSITEARCH=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi PREFIX=$(PREFIXLIB)/$(NAME) \
				LIB=$(PREFIXLIB)/$(NAME)/lib && cd ../../;\
		fi; \
		make -C lib/Crypt-CBC-2.30/; \
		if [ ! -f lib/Crypt-OpenSSL-AES-0.01/Makefile ]; then \
			cd lib/Crypt-OpenSSL-AES-0.01 && perl -I ../lib/mod_perl/lib -I $(PREFIXLIB)/$(NAME)/lib Makefile.PL INSTALLDIRS=site \
				INSTALLSITELIB=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
				INSTALLSITEARCH=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi PREFIX=$(PREFIXLIB)/$(NAME) \
				LIB=$(PREFIXLIB)/$(NAME)/lib && cd ../../;\
		fi; \
		make -C lib/Crypt-OpenSSL-AES-0.01/; \
		if [ ! -f lib/Apache-Session-Memcached-0.03/Makefile ]; then \
                        cd lib/Apache-Session-Memcached-0.03 && perl -I $(PREFIXLIB)/$(NAME)/lib Makefile.PL INSTALLDIRS=site \
                                INSTALLSITELIB=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
                                INSTALLSITEARCH=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi PREFIX=$(PREFIXLIB)/$(NAME) \
                                LIB=$(PREFIXLIB)/$(NAME)/lib && cd ../../;\
                fi; \
		make -C lib/Apache-Session-Memcached-0.03/; \
		if [ ! -f lib/NTLM-1.05/Makefile ]; then \
                        cd lib/NTLM-1.05 && perl -I $(PREFIXLIB)/$(NAME)/lib Makefile.PL INSTALLDIRS=site \
                                INSTALLSITELIB=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
                                INSTALLSITEARCH=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi PREFIX=$(PREFIXLIB)/$(NAME) \
                                LIB=$(PREFIXLIB)/$(NAME)/lib && cd ../../;\
                fi; \
		make -C lib/NTLM-1.05/; \
        if [ ! -f lib/Net-IP-Match-Regexp-1.01/Makefile ]; then \
                        cd lib/Net-IP-Match-Regexp-1.01 && perl -I $(PREFIXLIB)/$(NAME)/lib Makefile.PL INSTALLDIRS=site \
                                INSTALLSITELIB=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
                                INSTALLSITEARCH=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi PREFIX=$(PREFIXLIB)/$(NAME) \
                                LIB=$(PREFIXLIB)/$(NAME)/lib && cd ../../;\
                fi; \
		make -C lib/Net-IP-Match-Regexp-1.01/; \
	else \
		cd lib/Vulture && perl Makefile.PL $(OPT) && make; \
	fi

dist: clean $(GZ)

$(TAR):
	for j in `find . ! -type l ! -name '*~'  ! -name '#*' ! -name 'db' ! -path 'ebuild/Manifest' ! -path 'ebuild/files' ! -path '*/.svn/*'`; do \
		if [ -f $$j ]; then \
			$(INSTALL) $$j $(NAME)-$(VERSION)/$$j; \
		fi; \
	done
	tar cf $(TAR) $(NAME)-$(VERSION)
	rm -rf $(NAME)-$(VERSION)

$(GZ): $(TAR)
	gzip -f $(TAR)

bz2:	clean $(BZ2)

$(BZ2): $(TAR)
	bzip2 $(TAR)

clean:
	rm -rf $(GZ) $(TAR) $(BZ2) $(NAME)-$(VERSION)
	#for d in Apache2-ModProxyPerlHtml-3.0 Authen-Radius-0.12 Crypt-CBC-2.30 Crypt-OpenSSL-AES-0.01 Data-HexDump-0.02 SSLLookup Apache-Session-Memcached-0.03 Vulture NTLM-1.05; do \
	for d in Apache2-ModProxyPerlHtml-3.0 Authen-Radius-0.12 Crypt-CBC-2.30 Crypt-OpenSSL-AES-0.01 Data-HexDump-0.02 SSLLookup Apache-Session-Memcached-0.03 Vulture NTLM-1.05 Net-IP-Match-Regexp-1.01; do \
		if  [ -f lib/$$d/Makefile ]; then \
			make -C lib/$$d clean; \
		fi; \
	done    

install:
	for i in '$(DIRS)'; do \
		for j in `find $$i`; do \
		if [ -f $$j ]; then \
			if [ -e /etc/debian_version ]; then \
				$(INSTALL) $(UID) $(GID) $$j $(DESTDIR)$(PREFIX)/$(NAME)/$$j; \
			else \
				$(INSTALL) $$j $(DESTDIR)$(PREFIX)/$(NAME)/$$j; \
			fi; \
		fi; \
		done; \
	done
	if [ -e /etc/debian_version ]; then \
		/usr/bin/install -d -m0755 $(UID) $(GID) $(DESTDIR)$(PREFIX)/$(NAME)/sql; \
	else \
		/usr/bin/install -d -m0755 $(DESTDIR)$(PREFIX)/$(NAME)/sql; \
	fi
	for i in '$(DIRSLIB)'; do \
		cd lib/Vulture; \
		for j in `find $$i`; do \
		if [ -f $$j ]; then \
			if [ -e /etc/debian_version ]; then \
				$(INSTALL) $(UID) $(GID) $$j $(DESTDIR)$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi/Vulture/$$j; \
			else \
				$(INSTALL) $$j $(DESTDIR)$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi/Vulture/$$j; \
			fi; \
		fi; \
		done; \
		cd ../..; \
	done
	if [ -e /etc/debian_version ]; then \
		make -C lib/SSLLookup  install && \
		#make -C lib/Apache2 install && \
		make -C lib/Apache2-ModProxyPerlHtml-3.0 install && \
		make -C lib/Crypt-CBC-2.30 install && \
		make -C lib/Crypt-OpenSSL-AES-0.01 install && \
		make -C lib/Apache-Session-Memcached-0.03 install && \
		make -C lib/NTLM-1.05 install && \
        make -C lib/Net-IP-Match-Regexp-1.01 install && \
		cd lib/modsecurity-apache_2.6.1 && ./configure --prefix=$(PREFIXLIB)/$(NAME)/ --exec-prefix=$(PREFIXLIB)/$(NAME)/ && \
		cd apache2 && make clean && make install && \
		cd ../../../ &&  \
		install -m0600 debian/httpd.conf $(DESTDIR)$(PREFIX)/$(NAME)/conf/httpd.conf && \
		install -m0600 debian/aes-encrypt-key.key $(DESTDIR)$(PREFIX)/$(NAME)/conf/aes-encrypt-key.key && \
		install -m0600 debian/settings.py $(DESTDIR)$(PREFIX)/$(NAME)/admin/settings.py && \
        install -m0600 debian/vulture.wsgi $(DESTDIR)$(PREFIX)/$(NAME)/conf/vulture.wsgi && \
		chmod 744 $(DESTDIR)$(PREFIX)/$(NAME)/admin/manage.py; \
	fi; \

rpm:	clean $(TAR)
	make $(BZ2)
	rpmbuild -ta --target noarch $(BZ2)
	make clean


