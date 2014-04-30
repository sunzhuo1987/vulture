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
%define _unpackaged_files_terminate_build 0
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

%post

%preun

%define _rpmfilename %%{ARCH}/%%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm

%files
%defattr(-,root,root,-)
/opt/vulture/lib/share
/opt/vulture/lib/x86_64-linux-thread-multi/Apache
/opt/vulture/lib/x86_64-linux-thread-multi/auto

