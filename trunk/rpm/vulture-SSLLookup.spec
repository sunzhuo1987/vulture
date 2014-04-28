Requires: sudo

Summary: Hooks for various mod_ssl functions
Name: vulture-SSLLookup
Version: 2.00.04
Release: 0
License: GPL
Group: System/Servers
Buildarch: noarch
Source0: Apache-SSLLookup-2.00_04.tar.gz

BuildRequires: make 
%define _binaries_in_noarch_packages_terminate_build 0
%description
Hooks for various mod_ssl functions

%prep
%setup -c -a 0
cd Apache-SSLLookup-2.00_04
perl Makefile.PL CCFLAGS='-I/usr/include/apr-1' PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make -I/usr/include/apr-1 PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib

%install
cd Apache-SSLLookup-2.00_04
%make_install

%clean

%pre
if [ `getent passwd vulture-admin >/dev/null 2>/dev/null` ]; then
	adduser vulture-admin
fi

%post

%preun

%files
%defattr(-,vulture-admin,root,-)
/opt/vulture/lib
