Requires: sudo perl-Capture-Tiny perl-Devel-GlobalDestruction perl-Email-Address perl-MRO-Compat perl-Module-Find perl-Module-Runtime perl-Class-C3

Summary: Vulture LIBS
Name: vulture-LIBS
Version: 0.1
Release: 0
License: GPL
Group: System/Servers
Buildarch: noarch
AutoReqProv: no
Source0: Apache2-AuthenNTLM-0.02.tar.gz
Source1: Apache-Session-Memcached-0.03.tar.gz
Source2: Authen-Krb5-Simple-0.43.tar.gz
Source3: Authen-Radius-0.24.tar.gz
Source4: Authen-Simple-Kerberos-0.1.tar.gz
Source5: Crypt-Random-Source-0.07.tar.gz
Source6: Data-HexDump-0.02.tar.gz
Source7: MooX-Types-MooseLike-0.25.tar.gz
Source8: Email-Abstract-3.007.tar.gz
Source9: Email-Sender-1.300011.tar.gz
Source10: Math-Random-ISAAC-1.004.tar.gz
Source11: Math-Random-Secure-0.06.tar.gz
Source12: Moo-1.004002.tar.gz
Source13: Apache-Reload-0.10.tar.gz
Source14: strictures-1.005004.tar.gz
Source15: Role-Tiny-1.003003.tar.gz
Source16: Import-Into-1.002001.tar.gz

BuildRequires: make 
%define _binaries_in_noarch_packages_terminate_build 0
%define _unpackaged_files_terminate_build 0
%description
Vulture Libs

%prep
%setup -c -a 0
%setup -D -a 1
%setup -D -a 2
%setup -D -a 3
%setup -D -a 4
%setup -D -a 5
%setup -D -a 6
%setup -D -a 7
%setup -D -a 8
%setup -D -a 9
%setup -D -a 10
%setup -D -a 11
%setup -D -a 12
%setup -D -a 13
%setup -D -a 14
%setup -D -a 15
%setup -D -a 16

cd Apache2-AuthenNTLM-0.02
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd Apache-Reload-0.10
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd Apache-Session-Memcached-0.03
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd Authen-Krb5-Simple-0.43
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd Authen-Radius-0.24
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd Authen-Simple-Kerberos-0.1
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd Crypt-Random-Source-0.07
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd Data-HexDump-0.02
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd Email-Abstract-3.007
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd Email-Sender-1.300011
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd Math-Random-ISAAC-1.004
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd Math-Random-Secure-0.06
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd strictures-1.005004
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd Role-Tiny-1.003003
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd Import-Into-1.002001
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd .. 
cd Moo-1.004002
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..
cd MooX-Types-MooseLike-0.25
perl Makefile.PL PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
make PREFIX=/opt/vulture/lib LIB=/opt/vulture/lib
cd ..

%install
cd Apache2-AuthenNTLM-0.02
%make_install
cd ..
cd Apache-Session-Memcached-0.03
%make_install
cd ..
cd Authen-Krb5-Simple-0.43
%make_install
cd ..
cd Authen-Radius-0.24
%make_install
cd ..
cd Authen-Simple-Kerberos-0.1
%make_install
cd ..
cd Crypt-Random-Source-0.07
%make_install
cd ..
cd Data-HexDump-0.02
%make_install
cd ..
cd Email-Abstract-3.007
%make_install
cd ..
cd Email-Sender-1.300011
%make_install
cd ..
cd Math-Random-ISAAC-1.004
%make_install
cd ..
cd Math-Random-Secure-0.06
%make_install
cd ..
cd strictures-1.005004
%make_install
cd ..
cd Role-Tiny-1.003003
%make_install
cd ..
cd Import-Into-1.002001
%make_install
cd ..
cd Moo-1.004002
%make_install
cd ..
cd MooX-Types-MooseLike-0.25
%make_install
cd ..
cd Apache-Reload-0.10
%make_install
cd ..

%clean

%pre

%post

%preun

%define _rpmfilename %%{ARCH}/%%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm

%files
%defattr(-,root,root,-)
/opt/vulture/lib/Apache/
/opt/vulture/lib/Apache2/
/opt/vulture/lib/Authen
/opt/vulture/lib/Crypt
/opt/vulture/lib/Data
/opt/vulture/lib/Email
/opt/vulture/lib/Import
/opt/vulture/lib/Math
/opt/vulture/lib/Method
/opt/vulture/lib/*.pm
/opt/vulture/lib/Moo/
/opt/vulture/lib/MooX
/opt/vulture/lib/Role
/opt/vulture/lib/Sub
/opt/vulture/lib/bin
/opt/vulture/lib/share
/opt/vulture/lib/x86_64-linux-thread-multi/Apache2
/opt/vulture/lib/x86_64-linux-thread-multi/Authen
/opt/vulture/lib/x86_64-linux-thread-multi/auto

