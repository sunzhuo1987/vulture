NAME		= vulture
VERSION		= 2.0
PREFIX		= /var/www/
PREFIXLIB	= /opt/
UID		= -o www-data
GID		= -g www-data
DIRS		= sql www conf bin
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
		if [ ! -f lib/Apache2/Makefile ]; then \
			cd lib/Apache2 && perl -I $(PREFIXLIB)/$(NAME)/lib \
				-I $(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi Makefile.PL LIB=$(PREFIXLIB)/$(NAME)/lib \
				INSTALLSITELIB=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
				INSTALLSITEARCH=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
				PREFIX=$(PREFIXLIB)/$(NAME) SITEPREFIX=$(PREFIXLIB)/$(NAME) && cd ../../; \
		fi; \
		make -C lib/Apache2/; \
		if [ ! -f lib/Vulture/Makefile ]; then \
			cd lib/Vulture && perl -I $(PREFIXLIB)/$(NAME)/lib Makefile.PL INSTALLDIRS=site \
				INSTALLSITELIB=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
				INSTALLSITEARCH=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi PREFIX=$(PREFIXLIB)/$(NAME) \
				LIB=$(PREFIXLIB)/$(NAME)/lib && cd ../../;\
		fi; \
		make -C lib/Vulture/; \
		if [ ! -f lib/Crypt-CBC-2.19/Makefile ]; then \
			cd lib/Crypt-CBC-2.19 && perl -I ../lib/mod_perl/lib -I $(PREFIXLIB)/$(NAME)/lib Makefile.PL INSTALLDIRS=site \
				INSTALLSITELIB=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi \
				INSTALLSITEARCH=$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi PREFIX=$(PREFIXLIB)/$(NAME) \
				LIB=$(PREFIXLIB)/$(NAME)/lib && cd ../../;\
		fi; \
		make -C lib/Crypt-CBC-2.19/; \
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
	else \
		cd lib/Vulture && perl Makefile.PL $(OPT) && make; \
	fi

dist: clean $(GZ)

$(TAR):
	for j in `find . ! -type l ! -path './.bzr/*' ! -name '*~'  ! -name '#*' ! -name 'db' ! -path 'ebuild/Manifest' ! -path 'ebuild/files' ! -path './.svn/*'`; do \
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
	rm -rf $(GZ) $(TAR) $(BZ2) $(EBUILD) $(NAME)-$(VERSION)
	for d in Apache2 Authen-Radius-0.12 Crypt-CBC-2.19 Data-HexDump-0.02 SSLLookup Apache-Session-Memcached-0.03 Vulture NTLM-1.05; do \
		if  [ -f lib/$$d/Makefile ]; then \
			make -C lib/$$d clean; \
		fi; \
	done    

install:
	for i in '$(DIRS)'; do \
		for j in `find $$i`; do \
		if [ -f $$j ]; then \
			$(INSTALL) $(UID) $(GID) $$j $(DESTDIR)$(PREFIX)/$(NAME)/$$j; \
		fi; \
		done; \
	done
	
	for i in '$(DIRSLIB)'; do \
		cd lib/Vulture; \
		for j in `find $$i`; do \
		if [ -f $$j ]; then \
			$(INSTALL) $(UID) $(GID) $$j $(DESTDIR)$(PREFIXLIB)/$(NAME)/lib/i386-linux-thread-multi/Vulture/$$j; \
		fi; \
		done; \
		cd ../..; \
	done
	
	if [ -e /etc/debian_version ]; then \
		make -C lib/SSLLookup  install && \
		make -C lib/Apache2 install && \
		make -C lib/Crypt-CBC-2.19 install && \
		make -C lib/Apache-Session-Memcached-0.03 install && \
		make -C lib/NTLM-1.05 install && \
		cd lib/modsecurity-apache_2.6.1 && ./configure --prefix=$(PREFIXLIB)/$(NAME)/ --exec-prefix=$(PREFIXLIB)/$(NAME)/ && \
		cd apache2 && make clean && make install && \
		cd ../../../ &&  \
		rm -f $(DESTDIR)$(PREFIX)/$(NAME)/www/db && \
		install -m0600 debian/httpd.conf $(DESTDIR)$(PREFIX)/$(NAME)/conf/httpd.conf && \
		install -m0600 debian/settings.py $(DESTDIR)$(PREFIX)/$(NAME)/www/settings.py && \
		chmod 744 $(DESTDIR)$(PREFIX)/$(NAME)/www/manage.py; \
	fi; \
    for i in `find $(DESTDIR) -name "*.svn*"` ; do rm -rf $i ; done && \
    for i in `find $(DESTDIR) -name "*.*~"` ; do rm -rf $i ; done;


rpm:	clean $(TAR)
	make $(BZ2)
	rpmbuild -ta --target noarch $(BZ2)
	make clean


