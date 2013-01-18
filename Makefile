NAME		= vulture
VERSION		= 2.0.5
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
	cd lib/Vulture && perl Makefile.PL $(OPT) && make; \

dist: clean $(GZ)

$(TAR):
	for j in `find . ! -type l ! -name '*~'  ! -name '#*' ! -name 'db' ! -path 'ebuild/Manifest' ! -path 'ebuild/files' ! -path '*/.svn/*' !  -path '*/.svn'`; do \
		if [ -f $$j ]; then \
			$(INSTALL) $$j $(NAME)-$(VERSION)/$$j; \
		fi; \
	done
	tar cf $(TAR) $(NAME)-$(VERSION)
	rm -rf $(NAME)-$(VERSION)

$(GZ): $(TAR)
	gzip -f $(TAR)

bz2: clean $(BZ2)

$(BZ2): $(TAR)
	bzip2 $(TAR)

clean:
	rm -rf $(GZ) $(TAR) $(BZ2) $(NAME)-$(VERSION)

install:
	for i in '$(DIRS)'; do \
		for j in `find $$i ! -path '*/.svn/*' !  -path '*/.svn'`; do \
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
		for j in `find $$i ! -path '*/.svn/*' !  -path '*/.svn'`; do \
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
		install -m0600 debian/httpd.conf $(DESTDIR)$(PREFIX)/$(NAME)/conf/httpd.conf && \
		install -m0600 debian/settings.py $(DESTDIR)$(PREFIX)/$(NAME)/admin/settings.py && \
        	install -m0600 debian/vulture.wsgi $(DESTDIR)$(PREFIX)/$(NAME)/conf/vulture.wsgi && \
		chmod 744 $(DESTDIR)$(PREFIX)/$(NAME)/admin/manage.py; \
	fi; \

rpm: clean $(TAR)
	make $(BZ2)
	rpmbuild -ta --target noarch $(BZ2)
	make clean
